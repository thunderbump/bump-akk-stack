"""One-time reviewed root installation. No worker or candidate execution."""
import sys
sys.dont_write_bytecode = True
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

ROOT = Path('/usr/local/lib/eqemu-validator-maintenance-v1')
STATE = Path('/srv/eqemu-validator-code/.maintenance-v1')
UNITS = Path('/etc/systemd/system')
NAMES = {'maintenance.py', 'service.py', 'install.py', 'baseline.json',
         'eqemu-validator-maintenance.socket', 'eqemu-validator-maintenance@.service'}


def read(path, limit=131072):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOATIME | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        assert stat.S_ISREG(info.st_mode) and info.st_size <= limit
        raw = os.pread(fd, limit + 1, 0)
        assert len(raw) == info.st_size and info == os.fstat(fd) and info == path.lstat()
        return raw
    finally:
        os.close(fd)


def protected(path):
    for parent in [*reversed(path.parents), path]:
        info = parent.lstat()
        assert stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o022


def create(path, raw, mode):
    protected(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
        with os.fdopen(os.dup(fd), 'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
    finally:
        os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:os.fsync(parent)
    finally:os.close(parent)


def systemctl(*args):
    subprocess.run(['/usr/bin/systemctl', *args], check=True, timeout=20)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('operation', choices=['install', 'resume-install', 'uninstall'])
    args = parser.parse_args()
    try:
        assert os.geteuid() == os.getegid() == 0
        with open('/proc/self/status') as stream:
            status = dict(line.split(':', 1) for line in stream.read(16385).splitlines() if ':' in line)
        assert status['NoNewPrivs'].strip() == '0'
        manifest_raw = read(args.package / 'manifest.json')
        assert hashlib.sha256(manifest_raw).hexdigest() == args.sha256
        manifest = json.loads(manifest_raw)
        assert set(manifest) == NAMES
        assets = {name: read(args.package / name) for name in NAMES}
        for name, raw in assets.items():
            assert manifest[name] == dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        assert {p.name for p in args.package.iterdir()} == NAMES | {'manifest.json'}
        config = json.loads(assets['baseline.json'])
        # Capture source bytes before installing/importing any package code.
        import types
        core = types.ModuleType('verified_install_core')
        exec(compile(assets['maintenance.py'], '<verified-maintenance>', 'exec'), core.__dict__)
        host = core.Host()
        with host.guard():
            if args.operation in ('install', 'resume-install'):
                fresh = args.operation == 'install'
                expected_root = {name:assets[name] for name in ('maintenance.py','service.py','install.py','baseline.json')}
                expected_root['package-manifest.json'] = manifest_raw
                protected(ROOT.parent);protected(STATE.parent);protected(UNITS)
                if fresh:
                    assert not ROOT.exists() and not ROOT.is_symlink() and not STATE.exists() and not STATE.is_symlink()
                elif ROOT.exists():
                    protected(ROOT)
                    assert {path.name for path in ROOT.iterdir()} <= set(expected_root)
                # Validate EVERY existing artifact before any creation or service change.
                for name,raw in expected_root.items():
                    path=ROOT/name
                    if path.exists() or path.is_symlink():
                        assert not fresh and read(path)==raw
                        info=path.lstat()
                        assert (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(0,0,0o600 if name=='package-manifest.json' else 0o644)
                for name in NAMES:
                    if name.endswith(('.socket','.service')):
                        path=UNITS/name
                        if path.exists() or path.is_symlink():
                            assert not fresh and read(path)==assets[name]
                            info=path.lstat();assert (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(0,0,0o644)
                if STATE.exists():
                    protected(STATE);assert stat.S_IMODE(STATE.lstat().st_mode)==0o700
                elif STATE.is_symlink():raise ValueError('state')
                if fresh:
                    store=core.Store(config);store.snapshot(config['records']);store.binding(config['records'])
                if not ROOT.exists():ROOT.mkdir(mode=0o755)
                if not STATE.exists():STATE.mkdir(mode=0o700)
                core.same_mount(core.CODE, STATE)
                for name,raw in expected_root.items():
                    if not (ROOT/name).exists():create(ROOT/name,raw,0o600 if name=='package-manifest.json' else 0o644)
                for name in NAMES:
                    if name.endswith(('.socket','.service')) and not (UNITS/name).exists():create(UNITS/name,assets[name],0o644)
                systemctl('daemon-reload')
                systemctl('enable', '--now', 'eqemu-validator-maintenance.socket')
                print('{"state":"installed","worker_started":false}')
            else:
                protected(ROOT);protected(STATE)
                assert not (STATE / 'pending.json').exists()
                store = core.Store(config)
                assert store.head()['transaction'] is None, 'Rollback published bindings before uninstall'
                store.snapshot(config['records'])
                for name in ('maintenance.py', 'service.py', 'install.py', 'baseline.json'):
                    assert read(ROOT / name) == assets[name]
                for name in NAMES:
                    if name.endswith(('.socket', '.service')):assert read(UNITS / name) == assets[name]
                systemctl('disable', '--now', 'eqemu-validator-maintenance.socket')
                # Active request services must be absent; never kill them for uninstall.
                active = subprocess.run(['/usr/bin/systemctl','list-units','--type=service','--state=activating,active,deactivating','--no-legend','--no-pager','eqemu-validator-maintenance@*.service'],stdout=subprocess.PIPE,check=True,timeout=10)
                assert not active.stdout.strip()
                for name in NAMES:
                    if name.endswith(('.socket', '.service')):(UNITS / name).unlink()
                systemctl('daemon-reload')
                print('{"state":"disabled-and-unregistered","protected_code_and_audit_retained":true,"worker_started":false}')
        return 0
    except Exception:
        print('{"state":"installation-refused-or-partial","retry":false,"preserve_created_files":true}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
