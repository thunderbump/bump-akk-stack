"""Package a dirty Rust snapshot and the existing pinned tool bundle as data."""
import json
from pathlib import Path
import subprocess
import tempfile

from prepare import record, RUST_SHA
from snapshot import canonical, sha, capture, snapshot_identity, WORKSPACE, SNAPSHOT_LIMIT, FILE_LIMIT, FILE_COUNT, CHANGE_LIMIT, CHANGE_COUNT, RESULT_LIMIT


def implementation(root):
    from runtime import IMPLEMENTATION_FILES
    return sha(canonical({name: record(root / name)['sha256'] for name in IMPLEMENTATION_FILES}))


def tool_identity(root):
    names = ('validation/worker/snapshot.py', 'validation/worker/format_prepare.py',
             'validation/worker/format_guest.py', 'validation/worker/snapshot_apply.py', 'validation/worker/build_guest.py',
             'validation/rust-toolchain.json', 'scripts/format-worker-snapshot')
    recipe = sha(canonical(dict(version=1, workspace=WORKSPACE, rust_input_sha256=RUST_SHA,
        files={name: record(root / name)['sha256'] for name in names})))
    configs = [prefix + leaf for prefix in ('', 'rust/', WORKSPACE + '/')
               for leaf in ('rustfmt.toml', '.rustfmt.toml', '.cargo/config', '.cargo/config.toml')]
    return dict(version=1, scope='working-snapshot-tool', recipe_sha256=recipe,
                implementation_sha256=implementation(root), rust_input_sha256=RUST_SHA, workspace=WORKSPACE,
                snapshot_roots=[WORKSPACE], repository_config=configs,
                limits=dict(snapshot_bytes=SNAPSHOT_LIMIT, file_bytes=FILE_LIMIT, snapshot_files=FILE_COUNT,
                            change_bytes=CHANGE_LIMIT, change_files=CHANGE_COUNT, result_bytes=RESULT_LIMIT))


def prepare(snapshot, operation, rust_input, output):
    if operation not in ('format', 'check'):
        raise ValueError('Unknown snapshot operation')
    if record(rust_input)['sha256'] != RUST_SHA:
        raise ValueError('Missing or changed pinned Rust formatter input')
    with tempfile.TemporaryDirectory(prefix='eqemu-format-payload-') as tmp:
        root = Path(tmp)
        source = root / 'snapshot.json'; source.write_bytes(canonical(snapshot))
        files = {'snapshot.json': source, 'rust-inputs.tar': Path(rust_input)}
        identity = {k: snapshot_identity(snapshot)[k] for k in ('base', 'head', 'input_snapshot_sha256', 'recipe_sha256')}
        identity['files'] = {name: record(path) for name, path in files.items()}
        metadata = root / 'identity.json'; metadata.write_bytes(canonical(identity))
        if output.exists() or output.is_symlink():
            raise ValueError('Format payload output already exists')
        try:
            subprocess.run(['/usr/bin/genisoimage', '-quiet', '-output', str(output), '-volid', 'EQEMU_INPUT',
                            '-joliet', '-rock', '-graft-points', 'identity.json=' + str(metadata),
                            *[name + '=' + str(path) for name, path in files.items()]],
                           check=True, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if any(record(path) != identity['files'][name] for name, path in files.items()):
                raise ValueError('Formatter inputs changed during preparation')
            return dict(version=1, operation=operation, **identity, **record(output))
        except BaseException:
            output.unlink(missing_ok=True)
            raise
