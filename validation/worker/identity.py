"""AFK reuse identity for the trusted frontend, worker, policy and offline inputs."""
import hashlib
import json
from pathlib import Path

from prepare import record


def identity(root, config_path, native, rust):
    # Read bytes rather than paths/mtimes: reuse must notice an in-place replacement.
    config = json.loads(config_path.read_text())
    frontend = ('scripts/validate-worker-candidate', 'validation/worker/identity.py',
                'validation/worker/prepare.py', 'validation/worker/client.py',
                'validation/inputs.py', 'validation/profile.json')
    worker = ('validation/worker/runtime.py', 'validation/worker/guest.py',
              'validation/worker/build_guest.py', 'validation/worker/client.py',
              'scripts/check-validation-worker')
    files = [*(root / name for name in frontend),
             *(Path(config['code_dir']) / name for name in worker), config_path,
             Path('/etc/systemd/system/eqemu-validator@.service'),
             Path('/etc/systemd/system/eqemu-validator.socket'),
             Path('/etc/apparmor.d/eqemu-validator'),
             Path(config['base_image']), native, rust]
    records = {str(path.resolve()): record(path) for path in files}
    digest = hashlib.sha256(json.dumps(records, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'schema_version': 1, 'identity': 'eqemu-worker-v1:' + digest}
