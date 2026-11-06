"""Prepare a fixed core/baseline existing-broker update as data. Never execute it."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path('/usr/local/lib/eqemu-validator-maintenance-v1')
UNIT = Path('/etc/systemd/system/eqemu-validator-maintenance@.service')
STAGE = Path('/root/eqemu-maintenance-mvp-atime-update-v4')
BACKUP = Path('/root/eqemu-maintenance-mvp-atime-backup-v4')
EXPECTED_BEFORE = {
    'maintenance.py': 'be08bef85b2681b52ecf9b21885b0de526bd0bf7eab174ccbea5d84cfb1a2b40',
    'baseline.json': '100edaa4484356be96eb5571f88930451a30dd62aedce8aa5e31c739c93474fa'}
EXPECTED_UNIT = 'e209cf3efae5e763385ae888b15b9abb887c95d80e8ba2cc9b5e2cc11669ddb5'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def prepare(output):
    repo = Path(__file__).resolve().parents[2]
    assert not subprocess.check_output(['/usr/bin/git', '-C', str(repo), 'status', '--porcelain=v1'])
    commit = subprocess.check_output(['/usr/bin/git', '-C', str(repo), 'rev-parse', 'HEAD']).decode().strip()
    source = repo / 'validation/maintenance'
    paths = {'maintenance.py': ROOT/'maintenance.py', 'baseline.json': ROOT/'baseline.json'}
    before = {name: path.read_bytes() for name, path in paths.items()}
    assert all(digest(raw) == EXPECTED_BEFORE[name] for name, raw in before.items()), 'installed-before-drift'
    assert digest(UNIT.read_bytes()) == EXPECTED_UNIT, 'retained-unit-drift'
    baseline = json.loads(before['baseline.json'])
    after = dict(before)
    after['maintenance.py'] = (source/'maintenance.py').read_bytes()
    baseline['code_sha256']['maintenance.py'] = digest(after['maintenance.py'])
    after['baseline.json'] = (json.dumps(baseline, sort_keys=True, separators=(',', ':'))+'\n').encode()
    output.mkdir(mode=0o700)
    for name, raw in after.items():
        (output/name).write_bytes(raw)
    # Client is distributed separately; it is never imported by the root service.
    (output/'client.py').write_bytes((source/'client.py').read_bytes())
    manifest = dict(source_commit=commit, files={name:dict(destination=str(paths[name]),
                    before_sha256=digest(before[name]), after_sha256=digest(after[name])) for name in paths},
                    client_sha256=digest((source/'client.py').read_bytes()),
                    retained_unit=dict(destination=str(UNIT), sha256=EXPECTED_UNIT))
    q = shlex.quote
    unit_guard = [f'test -f {UNIT} && test ! -L {UNIT}',
                  f"printf '%s  %s\\n' {EXPECTED_UNIT} {UNIT} | sha256sum -c -"]
    lines = ['# REVIEW ONLY. Run manually in a normal root terminal outside NoNewPrivs.',
             '# No script from this package is executed as root. Stop on every error.',
             'set -eu', 'test "$(id -u)" = 0',
             "grep -q '^NoNewPrivs:[[:space:]]*0$' /proc/self/status",
             *unit_guard, f'mkdir -m 700 {STAGE}', f'mkdir -m 700 {BACKUP}']
    for name, path in paths.items():
        lines += [f'test -f {path} && test ! -L {path}',
                  f"printf '%s  %s\\n' {digest(before[name])} {path} | sha256sum -c -",
                  f'install -o root -g root -m 600 {q(str(output/name))} {STAGE/name}',
                  f"printf '%s  %s\\n' {digest(after[name])} {STAGE/name} | sha256sum -c -"]
    active_guard = [
        'maintenance_active=$(/usr/bin/systemctl list-units --type=service --state=activating,active,deactivating --no-legend --no-pager \'eqemu-validator-maintenance@*.service\')',
        'test -z "$maintenance_active"']
    lines += ['/usr/bin/systemctl stop eqemu-validator-maintenance.socket', *active_guard]
    for name, path in paths.items():
        lines += [f'cp -p --no-dereference {path} {BACKUP/name}',
                  f"printf '%s  %s\\n' {digest(before[name])} {BACKUP/name} | sha256sum -c -"]
    for name, path in paths.items():
        lines += [f'install -o root -g root -m 644 {STAGE/name} {path}',
                  f"printf '%s  %s\\n' {digest(after[name])} {path} | sha256sum -c -"]
    lines += ['/usr/bin/systemctl daemon-reload', '/usr/bin/systemctl start eqemu-validator-maintenance.socket']
    (output/'UPDATE-REVIEW-ONLY.sh').write_text('\n'.join(lines)+'\n')
    restore = ['# Explicit restore after reviewing any partial update. No automatic rollback.', 'set -eu', *unit_guard,
               '/usr/bin/systemctl stop eqemu-validator-maintenance.socket',
               *active_guard]
    for name, path in paths.items():
        restore += [f"printf '%s  %s\\n' {digest(before[name])} {BACKUP/name} | sha256sum -c -",
                    f'install -o root -g root -m 644 {BACKUP/name} {path}']
    restore += ['/usr/bin/systemctl daemon-reload', '/usr/bin/systemctl start eqemu-validator-maintenance.socket']
    (output/'RESTORE-REVIEW-ONLY.sh').write_text('\n'.join(restore)+'\n')
    manifest['scripts_sha256'] = {name: digest((output/name).read_bytes()) for name in
                                  ('UPDATE-REVIEW-ONLY.sh', 'RESTORE-REVIEW-ONLY.sh')}
    (output/'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    prepare(parser.parse_args().output.absolute())
