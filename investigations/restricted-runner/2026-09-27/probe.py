#!/usr/bin/python3 -I
"""Post-install authorization checks using the locked submit-only identity; starts no VM."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys

USER = 'eqemu-test-proof'
HELPER = '/usr/local/sbin/eqemu-test-request'
VERSION = Path(__file__).resolve().parent


def invoke(args, data='', timeout=10):
    return subprocess.run(['/usr/sbin/runuser', '-u', USER, '--', *args], input=data,
                          text=True, capture_output=True, timeout=timeout,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}, cwd='/')


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Use sudo for the submit-only identity proof')
    account = pwd.getpwnam(USER)
    groups = invoke(['/usr/bin/id', '-nG']).stdout.split()
    if account.pw_uid == 0 or groups != ['eqemu-test'] or account.pw_shell != '/usr/sbin/nologin':
        raise RuntimeError('Proof account has unexpected privileges')
    checks = {}
    cases = {
        'malformed': '{',
        'duplicate': '{"version":1,"version":1,"op":"run","profile":"startup-diagnostic"}',
        'oversized': 'x' * 4097,
        'host_path': json.dumps({'version': 1, 'op': 'run', 'profile': 'startup-diagnostic', 'path': '/etc/shadow'}),
        'host_command': json.dumps({'version': 1, 'op': 'run', 'profile': 'startup-diagnostic', 'command': ['/bin/sh']}),
        'bad_id': json.dumps({'version': 1, 'op': 'cancel', 'run_id': '../../other'}),
        'unknown_profile': json.dumps({'version': 1, 'op': 'run', 'profile': 'arbitrary-python'}),
    }
    # Require a helper-generated error. A broken sudo rule must not masquerade as rejection coverage.
    for name, data in cases.items():
        result = invoke(['/usr/bin/sudo', '-n', HELPER], data)
        try:
            error = json.loads(result.stderr)['error']
        except Exception as exc:
            raise RuntimeError('Helper was not reached for ' + name) from exc
        checks[name] = result.returncode != 0 and bool(error)
    for name, args in {
        'extra_arguments': [HELPER, 'publish', '0000000001'],
        'root_shell': ['/bin/sh', '-c', 'true'],
        'direct_python': ['/usr/bin/python3', '-I', str(VERSION / 'control.py')],
    }.items():
        checks[name] = invoke(['/usr/bin/sudo', '-n', *args]).returncode != 0
    for path in (VERSION / 'control.py', Path(HELPER), VERSION / 'worker.py.in'):
        checks['not_writable_' + path.name] = invoke(['/usr/bin/test', '-w', str(path)]).returncode != 0
    checks['reports_traversable'] = invoke(['/usr/bin/test', '-x', '/var/lib/eqemu-test/reports']).returncode == 0
    if not all(checks.values()):
        raise RuntimeError(json.dumps(checks))
    result = {'checks': checks, 'vm_started': False, 'authorization_checks_passed': True}
    target = Path('/var/lib/eqemu-test/authorization-checks.json')
    target.write_text(json.dumps(result, indent=2) + '\n')
    target.chmod(0o644)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
