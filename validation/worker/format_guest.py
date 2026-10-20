#!/usr/bin/python3
"""Pinned formatter only. The trusted launcher copies this into a disposable VM."""
import base64
import json
import os
from pathlib import Path
import sys
import time

import build_guest as build
import snapshot as policy

RUST_SHA = '2a0b4a32ad74b3bb49195d43f76ece75166b500004f5b32f868cb20a292bc52f'


def inventory(root):
    found = {}
    for parent, directories, names in os.walk(root, followlinks=False):
        for name in directories:
            if (Path(parent) / name).is_symlink():
                raise ValueError('Formatter introduced a directory symlink')
        for name in names:
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            if not policy.selected(relative):
                raise ValueError('Formatter introduced a forbidden file')
            found[relative] = policy.read_file(root, relative)
            if len(found) > policy.FILE_COUNT or sum(len(data) for data, _ in found.values()) > policy.SNAPSHOT_LIMIT:
                raise ValueError('Formatter output inventory exceeds budget')
    return found


def format_source(snapshot, source, operation, command):
    """Only existing .rs bytes may change; all config, modes and deletions survive."""
    original = inventory(source)
    expected = {e['path']: (base64.b64decode(e['content_base64'], validate=True), e['mode']) for e in snapshot['files']}
    if original != expected:
        raise ValueError('Extracted snapshot differs')
    command('rust-format', ['/opt/eqemu-format/toolchain/bin/cargo', 'fmt', '--all',
                           *(['--check'] if operation == 'check' else [])],
            cwd=source / policy.WORKSPACE, candidate=True, seconds=120)
    current = inventory(source)
    if set(current) != set(original):
        raise ValueError('Formatter added or removed files')
    changes = []
    total = 0
    for name, (data, mode) in current.items():
        before, before_mode = original[name]
        if mode != before_mode or (data != before and (not name.endswith('.rs') or operation != 'format')):
            raise ValueError('Formatter modified protected inventory')
        if data != before:
            total += len(data)
            if total > policy.CHANGE_LIMIT or len(changes) >= policy.CHANGE_COUNT:
                raise ValueError('Formatter change budget exceeded')
            changes.append(dict(path=name, before_sha256=policy.sha(before), after_sha256=policy.sha(data),
                                content_base64=base64.b64encode(data).decode()))
    return sorted(changes, key=lambda change: change['path'])


def main():
    started = time.monotonic()
    nonce_path = Path('/opt/eqemu-worker-nonce')
    if os.geteuid() != 0 or not Path('/opt/eqemu-worker-format-guest').is_file():
        raise RuntimeError('Disposable format guest only')
    nonce = nonce_path.read_text().strip()
    request = json.loads(Path('/opt/eqemu-format-request.json').read_text())
    result = dict(version=1, nonce=nonce, scope='working-snapshot-format', exit_code=2,
                  changed_files=[], output_snapshot_sha256=request['input_snapshot_sha256'])
    build.DEADLINE = started + 840
    try:
        root = Path('/opt/eqemu-format'); root.mkdir()
        media = Path('/media/eqemu-input'); media.mkdir(parents=True)
        build.command('mount-job', ['mount', '-o', 'ro,nosuid,nodev', '/dev/sr1', str(media)])
        identity = json.loads((media / 'identity.json').read_text())
        if identity != {k: request[k] for k in ('base', 'head', 'input_snapshot_sha256', 'recipe_sha256', 'files')}:
            raise ValueError('Format input identity mismatch')
        for name, expected in identity['files'].items():
            path = media / name
            if path.stat().st_size != expected['bytes'] or build.sha(path) != expected['sha256']:
                raise ValueError('Changed formatter input: ' + name)
        if identity['files']['rust-inputs.tar']['sha256'] != RUST_SHA:
            raise ValueError('Unapproved formatter tool bundle')
        encoded = (media / 'snapshot.json').read_bytes()
        if len(encoded) > policy.SNAPSHOT_LIMIT * 2:
            raise ValueError('Oversized snapshot')
        snapshot = policy.validate_snapshot(json.loads(encoded))
        if (policy.sha(policy.canonical(snapshot)) != request['input_snapshot_sha256']
                or snapshot['base'] != request['base'] or snapshot['head'] != request['head']
                or snapshot['recipe_sha256'] != request['recipe_sha256']):
            raise ValueError('Snapshot binding mismatch')
        source = root / 'source'; source.mkdir()
        for entry in snapshot['files']:
            path = source / entry['path']; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(base64.b64decode(entry['content_base64'], validate=True))
            path.chmod(0o755 if entry['mode'] == '100755' else 0o644)
        build.extract(media / 'rust-inputs.tar', root / 'inputs')
        for component in ('rustc', 'cargo', 'rust-std', 'rustfmt-preview'):
            unpacked = root / component
            build.extract(root / 'inputs' / (component + '.tar.xz'), unpacked)
            installers = list(unpacked.glob('*/install.sh'))
            if len(installers) != 1:
                raise ValueError('Missing pinned formatter installer')
            build.command('install-' + component, ['/bin/sh', str(installers[0]),
                          '--prefix=' + str(root / 'toolchain'), '--disable-ldconfig'], seconds=120)
        home = root / 'home'; home.mkdir()
        build.ENV.update(PATH=str(root / 'toolchain/bin') + ':/usr/bin:/bin', HOME=str(home),
                         CARGO_HOME=str(home), CARGO_NET_OFFLINE='true', RUSTUP_AUTO_INSTALL='0',
                         RUSTFMT=str(root / 'toolchain/bin/rustfmt'), RUSTC=str(root / 'toolchain/bin/rustc'),
                         RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='')
        result['preparation_seconds'] = round(time.monotonic() - started, 3)
        formatting = time.monotonic()
        try:
            result['changed_files'] = format_source(snapshot, source, request['operation'], build.command)
        finally:
            result['format_seconds'] = round(time.monotonic() - formatting, 3)
        output = {e['path']: dict(e) for e in snapshot['files']}
        for change in result['changed_files']:
            output[change['path']].update(sha256=change['after_sha256'], content_base64=change['content_base64'],
                                        bytes=len(base64.b64decode(change['content_base64'])))
        result.update(exit_code=0, output_snapshot_sha256=policy.sha(policy.canonical(
            dict(snapshot, files=[output[e['path']] for e in snapshot['files']]))))
    except Exception as error:
        result.update(exit_code=1 if isinstance(error, build.CandidateFailure) else 2,
                      error=str(error)[-2000:], changed_files=[],
                      output_snapshot_sha256=request['input_snapshot_sha256'])
    result['guest_seconds'] = round(time.monotonic() - started, 3)
    encoded = policy.canonical(result)
    if len(encoded) > policy.RESULT_LIMIT - 16384:
        result.update(exit_code=2, error='Formatter result budget exceeded', changed_files=[],
                      output_snapshot_sha256=request['input_snapshot_sha256'])
        encoded = policy.canonical(result)
    # Base64 protects the framed line from embedded newlines/control characters.
    print('\nEQEMU_FORMAT_RESULT ' + base64.b64encode(encoded).decode(), flush=True)


if __name__ == '__main__':
    main()
