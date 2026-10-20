"""Bounded Rust source snapshots and formatter results. No candidate execution."""
import base64
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile

SNAPSHOT_LIMIT = 4 * 1024**2
FILE_LIMIT = 512 * 1024
FILE_COUNT = 512
CHANGE_LIMIT = 1024**2
CHANGE_COUNT = 128
RESULT_LIMIT = 1536 * 1024
WORKSPACE = 'rust/actors'
RUST_INPUT_SHA256 = '2a0b4a32ad74b3bb49195d43f76ece75166b500004f5b32f868cb20a292bc52f'
HEX = re.compile('[a-f0-9]{64}')
CONFIG_NAMES = ('rustfmt.toml', '.rustfmt.toml')
EXCLUDED = {'target', 'vendor', 'generated', '.git', 'submodules'}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def selected(name):
    """Cargo workspace source plus the configuration its formatter can inherit."""
    if not isinstance(name, str) or len(name) > 240:
        return False
    path = PurePosixPath(name)
    if (path.is_absolute() or str(path) != name or any(p in EXCLUDED or p in ('.', '..') for p in path.parts)
            or any(ord(c) < 32 for c in name)):
        return False
    if name in [prefix + leaf for prefix in ('', 'rust/', WORKSPACE + '/')
                for leaf in (*CONFIG_NAMES, '.cargo/config', '.cargo/config.toml')]:
        return True
    return name.startswith(WORKSPACE + '/') and (
        path.suffix == '.rs' or path.name in ('Cargo.toml', 'Cargo.lock', *CONFIG_NAMES))


def read_file(root, name):
    """Traverse with directory descriptors so links cannot escape the checkout."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = PurePosixPath(name).parts
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
        with os.fdopen(file_fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > FILE_LIMIT:
                raise ValueError('Snapshot file type/size refused: ' + name)
            data = stream.read(FILE_LIMIT + 1)
            if len(data) != info.st_size or len(data) > FILE_LIMIT:
                raise ValueError('Snapshot file changed during read: ' + name)
        return data, '100755' if info.st_mode & 0o111 else '100644'
    finally:
        os.close(fd)


def capture(repo, base, recipe):
    """Use an isolated Git index/config; never run hooks, filters or fsmonitor."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from inputs import GitTree, regular
    if not isinstance(base, str) or not re.fullmatch('[a-f0-9]{40}', base):
        raise ValueError('Snapshot base must be a full commit SHA')
    if not isinstance(recipe, str) or not HEX.fullmatch(recipe):
        raise ValueError('Invalid formatter recipe identity')
    root = Path(repo).absolute()
    # Reject symlinked checkout roots and ancestors before descriptor traversal.
    if root.resolve() != root:
        raise ValueError('Snapshot checkout path traverses a symlink')
    with tempfile.TemporaryDirectory(prefix='eqemu-format-index-') as tmp:
        view = GitTree(root, Path(tmp))
        tree = view.git('rev-parse', base + '^{tree}').decode().strip()
        baseline, _ = view.inventory(base, tree)
        index = Path(view.location('--git-path', 'index'))
        with regular(index, 16 * 1024**2) as (stream, _):
            data = stream.read(16 * 1024**2 + 1)
        if len(data) > 16 * 1024**2:
            raise ValueError('Index exceeds snapshot budget')
        copied = Path(tmp) / 'index'; copied.write_bytes(data)
        view.env['GIT_INDEX_FILE'] = str(copied)
        listing = view.git('--work-tree=' + str(root), 'ls-files', '-z', '--cached', '--others', '--exclude-standard')
        names = sorted({name.decode() for name in listing.split(b'\0') if name and selected(name.decode())})
        # Include ancestor config even when ignored. It affects the formatter.
        for prefix in ('', 'rust/', WORKSPACE + '/'):
            for leaf in (*CONFIG_NAMES, '.cargo/config', '.cargo/config.toml'):
                name = prefix + leaf
                if os.path.lexists(root / name) and name not in names:
                    names.append(name)
        files = []
        total = 0
        for name in sorted(names):
            try:
                data, mode = read_file(root, name)
            except FileNotFoundError:
                continue  # A tracked deletion is represented by the missing inventory entry.
            total += len(data)
            if total > SNAPSHOT_LIMIT or len(files) >= FILE_COUNT:
                raise ValueError('Snapshot budget exceeded')
            files.append(dict(path=name, mode=mode, bytes=len(data), sha256=sha(data),
                              content_base64=base64.b64encode(data).decode()))
        present = {entry['path'] for entry in files}
        if WORKSPACE + '/Cargo.toml' not in present:
            raise ValueError('Rust actor workspace manifest missing')
        snapshot = dict(version=1, scope='working-snapshot-input', base=base,
                        head=view.location('HEAD'), recipe_sha256=recipe, files=files,
                        deleted=sorted(e['path'] for e in baseline if selected(e['path']) and e['path'] not in present))
        validate_snapshot(snapshot)
        return snapshot


def validate_snapshot(snapshot):
    if (not isinstance(snapshot, dict) or set(snapshot) != {'version', 'scope', 'base', 'head', 'recipe_sha256', 'files', 'deleted'}
            or type(snapshot['version']) is not int or snapshot['version'] != 1
            or snapshot['scope'] != 'working-snapshot-input'
            or any(not isinstance(snapshot[k], str) or not re.fullmatch('[a-f0-9]{40}', snapshot[k]) for k in ('base', 'head'))
            or not isinstance(snapshot['recipe_sha256'], str) or not HEX.fullmatch(snapshot['recipe_sha256'])
            or not isinstance(snapshot['files'], list) or not 0 < len(snapshot['files']) <= FILE_COUNT
            or not isinstance(snapshot['deleted'], list) or len(snapshot['deleted']) > FILE_COUNT):
        raise ValueError('Malformed source snapshot')
    total = 0; names = set()
    for entry in snapshot['files']:
        if (not isinstance(entry, dict) or set(entry) != {'path', 'mode', 'bytes', 'sha256', 'content_base64'}
                or not selected(entry['path']) or entry['path'] in names
                or entry['mode'] not in ('100644', '100755') or type(entry['bytes']) is not int
                or not 0 <= entry['bytes'] <= FILE_LIMIT or not isinstance(entry['content_base64'], str)):
            raise ValueError('Malformed snapshot file')
        data = base64.b64decode(entry['content_base64'], validate=True)
        if len(data) != entry['bytes'] or sha(data) != entry['sha256']:
            raise ValueError('Snapshot file hash/size mismatch')
        total += len(data); names.add(entry['path'])
    if (total > SNAPSHOT_LIMIT or WORKSPACE + '/Cargo.toml' not in names
            or not all(selected(name) and name not in names for name in snapshot['deleted'])
            or snapshot['deleted'] != sorted(set(snapshot['deleted']))):
        raise ValueError('Snapshot inventory exceeds bounds or contradicts deletions')
    return snapshot


def snapshot_identity(snapshot):
    return dict(version=1, scope='working-snapshot-input', base=snapshot['base'], head=snapshot['head'],
                input_snapshot_sha256=sha(canonical(snapshot)), recipe_sha256=snapshot['recipe_sha256'],
                files=[{k: v for k, v in entry.items() if k != 'content_base64'} for entry in snapshot['files']],
                deleted=snapshot['deleted'])


def indexed_paths(repo):
    """Read the actual index with the same config isolation as snapshot capture."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from inputs import GitTree, regular
    with tempfile.TemporaryDirectory(prefix='eqemu-format-index-query-') as tmp:
        view = GitTree(repo, Path(tmp))
        with regular(Path(view.location('--git-path', 'index')), 16 * 1024**2) as (stream, _):
            data = stream.read(16 * 1024**2 + 1)
        if len(data) > 16 * 1024**2:
            raise ValueError('Index exceeds snapshot budget')
        copied = Path(tmp) / 'index'; copied.write_bytes(data)
        view.env['GIT_INDEX_FILE'] = str(copied)
        result = sorted({name.decode() for name in view.git('ls-files', '-z', '--cached').split(b'\0')
                         if name and selected(name.decode())})
        if len(result) > FILE_COUNT:
            raise ValueError('Selected index exceeds snapshot budget')
        return result


def validate_result(result, snapshot, operation, implementation):
    """A caller validates everything before applying any result bytes."""
    validate_snapshot(snapshot)
    if len(canonical(result)) > RESULT_LIMIT:
        raise ValueError('Formatter result exceeds budget')
    if (not isinstance(result, dict) or type(result.get('version')) is not int or result['version'] != 1
            or result.get('scope') != 'working-snapshot-format' or result.get('operation') != operation
            or result.get('base') != snapshot['base'] or result.get('head') != snapshot['head']
            or result.get('input_snapshot_sha256') != sha(canonical(snapshot))
            or result.get('recipe_sha256') != snapshot['recipe_sha256']
            or result.get('implementation_sha256') != implementation
            or result.get('rust_input_sha256') != RUST_INPUT_SHA256
            or type(result.get('exit_code')) is not int or result['exit_code'] not in (0, 1, 2)
            or result.get('cleanup_complete') is not True or result.get('vm_started') is not True
            or not isinstance(result.get('changed_files'), list) or len(result['changed_files']) > CHANGE_COUNT):
        raise ValueError('Incomplete or mismatched formatter result')
    timing = result.get('timings')
    if (not isinstance(timing, dict) or not all(name in timing for name in ('boot_seconds', 'preparation_seconds', 'format_seconds', 'total_seconds'))
            or any(type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1800 for value in timing.values())):
        raise ValueError('Incomplete formatter timing evidence')
    files = {e['path']: dict(e) for e in snapshot['files']}
    seen = set(); total = 0
    for change in result['changed_files']:
        if (not isinstance(change, dict) or set(change) != {'path', 'before_sha256', 'after_sha256', 'content_base64'}
                or not isinstance(change['path'], str) or change['path'] not in files
                or not change['path'].endswith('.rs') or change['path'] in seen
                or change['before_sha256'] != files[change['path']]['sha256']
                or not isinstance(change['content_base64'], str)):
            raise ValueError('Forbidden formatter change')
        data = base64.b64decode(change['content_base64'], validate=True)
        total += len(data)
        if (len(data) > FILE_LIMIT or total > CHANGE_LIMIT or sha(data) != change['after_sha256']
                or change['after_sha256'] == change['before_sha256']):
            raise ValueError('Formatter change hash/size mismatch')
        files[change['path']].update(sha256=sha(data), bytes=len(data), content_base64=change['content_base64'])
        seen.add(change['path'])
    output = dict(snapshot, files=[files[e['path']] for e in snapshot['files']])
    if (result.get('output_snapshot_sha256') != sha(canonical(output))
            or ((operation == 'check' or result['exit_code'] != 0) and result['changed_files'])):
        raise ValueError('Formatter output binding or operation mismatch')
    return result
