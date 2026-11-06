"""Finite initial ordinary-state transition. Not a protocol action."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat

PARENT = Path('/var/lib/eqemu-validator')
STATE = PARENT/'ordinary'
OLD_WORKSPACE = PARENT/'last-integration'
BACKUP = Path('/srv/eqemu-resilient-adoption')
CONFIG = Path('/etc/eqemu-validator/config.json')
UNIT = Path('/etc/systemd/system/eqemu-validator@.service')
PROFILE = Path('/etc/apparmor.d/eqemu-validator')
PUBLISHER_UNITS = tuple(Path('/etc/systemd/system')/n for n in
                        ('eqemu-validator-maintenance.socket','eqemu-validator-maintenance@.service'))
TRUSTED_UID = 0
WORKER_UID, WORKER_GID = 995, 980


def release_bytes(here, packet):
    from package import read_regular
    artifact = json.loads(read_regular(here/'worker-release.json'))
    expected = {e['path']: e for e in packet['current_code']['fresh_files']}
    if set(artifact) != set(expected):
        raise ValueError('release must have exact baseline closure')
    result = {name: base64.b64decode(raw, validate=True) for name, raw in artifact.items()}
    original = read_regular(here/'ordinary-runtime-baseline.py')
    patched = read_regular(here/'ordinary-runtime.py')
    for name, raw in result.items():
        check = (original if name == 'validation/worker/runtime.py' else
                 read_regular(here/'integration-release-baseline.json') if name == 'integration-release.json' else raw)
        if len(check) != expected[name]['bytes'] or hashlib.sha256(check).hexdigest() != expected[name]['sha256']:
            raise ValueError('release differs from admitted baseline')
    if result['validation/worker/runtime.py'] != patched:
        raise ValueError('patched worker differs from sealed artifact')
    return result


def manifest_data(path, expected_hash):
    from package import read_regular, decode
    raw = read_regular(path, 65536)
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError('reviewed current-state manifest hash required')
    value = decode(raw)
    if (set(value) != {'version','entries','records'} or value['version'] != 1
            or not isinstance(value['entries'], list) or len(value['entries']) > 16
            or len(set(value['entries'])) != len(value['entries'])
            or not isinstance(value['records'], dict)
            or not set(value['records']) <= {'last-result.json','last-serial.log'}):
        raise ValueError('invalid finite state selection')
    return value


def prepare_state(manager, target, here, packet, legacy_bytes, manifest):
    """Fence first; preserve only manifest-selected records; never move unknown data."""
    from engine import protected, sync_dir, atomic
    from package import read_regular, atomic as atomic_bytes
    if not manager._fenced:
        raise ValueError('owned writers must be fenced before custody transition')
    info = PARENT.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != WORKER_UID
            or info.st_gid != WORKER_GID or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('current ordinary parent differs from reviewed transition')
    protected(PARENT.parent, TRUSTED_UID)
    allowed = {'worker.lock','last-integration','asan-v1','asan-v2','asan-v3',
               'last-result.json','last-serial.log'}
    actual = set(os.listdir(PARENT))
    if (actual != set(manifest['entries']) or not actual <= allowed
            or 'worker.lock' not in actual or 'last-integration' not in actual
            or set(manifest['records']) != actual & {'last-result.json','last-serial.log'}):
        raise ValueError('unreviewed state entries or active work; bounded inventory required')
    for name in actual & {'asan-v1','asan-v2','asan-v3'}:
        info = (PARENT/name).lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != WORKER_UID or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('unknown diagnostic state ownership')
    selected = {}
    for name, entry in manifest['records'].items():
        if set(entry) != {'bytes','sha256'} or type(entry['bytes']) is not int or not 0 <= entry['bytes'] <= 1024*1024:
            raise ValueError('invalid selected managed record')
        path = PARENT/name
        info = path.lstat()
        if info.st_uid != WORKER_UID or info.st_gid != WORKER_GID or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('unreviewed managed record metadata')
        raw = read_regular(path, entry['bytes'])
        if len(raw) != entry['bytes'] or hashlib.sha256(raw).hexdigest() != entry['sha256']:
            raise ValueError('managed record changed')
        selected[name] = raw
    profile = read_regular(PROFILE)
    if hashlib.sha256(profile).hexdigest() != '1943a9df8b90539703f9fc9a1ed703be91caf0437192a560f79a46d7a32ed6d4':
        raise ValueError('ordinary confinement baseline changed')
    # This leaf must remain the common nonroot-owned mode0600 lock.
    fd = os.open(PARENT/'worker.lock', os.O_RDWR|os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != WORKER_UID
                or info.st_gid != WORKER_GID or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError('shared lock differs from reviewed custody')
        fcntl.flock(fd, fcntl.LOCK_EX|fcntl.LOCK_NB)
        BACKUP.mkdir(mode=0o700, exist_ok=True)
        protected(BACKUP, TRUSTED_UID)
        custody = BACKUP/'custody'
        custody.mkdir(mode=0o700)  # Existing partial transition refuses.
        atomic(custody/'state-selection.json', manifest)
        for name, raw in selected.items():
            atomic_bytes(custody/name, raw)
        # Archive exact old authority assets before replacing any of them.
        for path in (CONFIG, UNIT, PROFILE, *PUBLISHER_UNITS):
            atomic_bytes(custody/path.name, read_regular(path))
        STATE.mkdir(mode=0o700)
        os.chown(STATE, WORKER_UID, WORKER_GID)
        workspace = STATE/'last-integration'
        workspace.mkdir(mode=0o700)
        os.chown(workspace, WORKER_UID, WORKER_GID)
        for directory, records in ((STATE, selected), (workspace, legacy_bytes)):
            for name, raw in records.items():
                atomic_bytes(directory/name, raw)
                os.chown(directory/name, WORKER_UID, WORKER_GID)
            sync_dir(directory)
        # No blanket move/chown/delete. Old records and ASan children stay put.
        os.chown(PARENT, TRUSTED_UID, 0)
        os.chmod(PARENT, 0o711)
        sync_dir(PARENT)
        atomic(custody/'custody-observed.json', {'state':'seeded','original_outcome':packet['migration']['original_outcome']})
    finally:
        os.close(fd)
    # Prevent every subsequent invocation of the competing publisher, including
    # direct activation of its template, before admitting a managed code binding.
    for path in PUBLISHER_UNITS:
        temporary = path.parent/('.retire-'+path.name)
        if temporary.exists() or temporary.is_symlink():
            raise ValueError('interrupted publisher retirement requires reconciliation')
        temporary.symlink_to('/dev/null')
        os.replace(temporary, path)
        sync_dir(path.parent)
    manager._run(['daemon-reload'], target['timeout'])
    # Keep old unit/config pins as pre-adoption expectations; install these exact
    # successors only after their originals have been validated and retained.
    for path, asset in ((CONFIG,'ordinary-config.json'),(UNIT,'ordinary-unit'),(PROFILE,'ordinary-apparmor')):
        atomic_bytes(path, read_regular(here/asset), 0o644)
    manager._run(['daemon-reload'], target['timeout'])
    # No AppArmor loader, activation or workload here. External root admission
    # must load/verify this exact profile separately before starting any worker.
