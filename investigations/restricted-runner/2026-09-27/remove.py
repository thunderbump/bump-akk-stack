#!/usr/bin/python3 -I
"""Disable admission; optionally stop exact-owned runs. Retain evidence and installed code."""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

VERSION = Path(__file__).resolve().parent
BASE = Path('/var/lib/eqemu-test')
POLICY = Path('/etc/sudoers.d/eqemu-test')
RULE = b'%eqemu-test ALL=(root) NOPASSWD: NOSETENV: /usr/local/sbin/eqemu-test-request ""\n'


def main():
    if os.geteuid() != 0 or sys.argv[1:] not in ([], ['--cancel-owned']):
        raise ValueError('Use sudo remove.py [--cancel-owned]')
    spec = importlib.util.spec_from_file_location('control', VERSION / 'control.py')
    control = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(control)
    control.verify_installation()
    # No pending request may re-enable a run after revocation begins.
    lock_path = BASE / 'request.lock'
    if not lock_path.exists():
        with lock_path.open('x'):
            pass
        lock_path.chmod(0o600)
    control.safe_path(lock_path)
    with lock_path.open('r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        record = control.read_json(BASE / 'installation.json')
        record['enabled'] = False
        control.write_json(BASE / 'installation.json', record)
        if POLICY.exists() or POLICY.is_symlink():
            control.safe_path(POLICY)
            if POLICY.read_bytes() != RULE:
                raise ValueError('Policy changed; refuse removal')
            POLICY.unlink()
            control.command(['/usr/sbin/visudo', '-c'])
        for root in ((BASE / 'runs').iterdir() if (BASE / 'runs').exists() else []):
            control.run_root(root.name)
            suite = control.load_suite(root)
            if not suite.quiescent(suite.properties(suite.UNIT)):
                if '--cancel-owned' not in sys.argv:
                    raise ValueError('Admission disabled; run active. Retry with --cancel-owned or let it finish.')
                suite.run(['/usr/bin/systemctl', 'stop', suite.UNIT], timeout=330)
            result = control.publish(root.name)
            if not result['cleanup_complete']:
                raise ValueError('Admission disabled; incomplete cleanup requires exact recovery: ' + root.name)
        record = control.read_json(BASE / 'installation.json')
        record['enabled'] = False
        control.write_json(BASE / 'installation.json', record)
        # Remove only exact installed entry points; never delete retained run evidence or shared packages.
        manifest = control.read_json(VERSION / 'manifest.json')
        expected = {
            Path('/usr/local/bin/eqemu-test'): manifest['files']['client.py'],
            Path('/usr/local/sbin/eqemu-test-request'): hashlib.sha256(
                ('#!/bin/sh\n[ "$#" -eq 0 ] || exit 2\nexec /usr/bin/python3 -I ' + str(VERSION / 'control.py') + '\n').encode()).hexdigest(),
        }
        for path, digest in expected.items():
            if path.exists() or path.is_symlink():
                control.safe_path(path)
                if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    raise ValueError('Entry point changed; retain: ' + str(path))
                path.unlink()
        if record.get('bump_added'):
            control.command(['/usr/bin/gpasswd', '-d', 'bump', 'eqemu-test'])
            record['bump_added'] = False
            control.write_json(BASE / 'installation.json', record)
        # Retaining a locked proof identity and report group preserves attribution/readability.
        # Neither has a sudo grant after this rollback. Their deletion is a later exact audit.
        print(json.dumps({'disabled': True, 'entry_points_removed': True,
                          'evidence_retained': str(BASE), 'code_retained': str(VERSION),
                          'note': 'No privilege grant remains. Locked proof account and report group retained for evidence ownership.'}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
