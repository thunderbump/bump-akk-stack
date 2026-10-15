"""Tiny cloud-init workload for worker qualification, not EQEmu acceptance."""
import json

BUILD_CHECKS = (
    'rust-format', 'rust-dependencies', 'rust-clippy', 'rust-tests', 'rust-doctests',
    'native-configure', 'native-build', 'zone-rust-symbol', 'native-utilities',
)


def user_data(nonce, control):
    result = json.dumps({'version': 1, 'nonce': nonce, 'scope': 'worker-smoke',
                         'exit_code': 1 if control == 'assertion' else 0}, separators=(',', ':'))
    script = '#!/bin/sh\nset -eu\n'
    if control in ('deadline', 'controller-death'):
        script += 'sleep 600\n'
    elif control != 'missing-result':
        script += "printf '%s\\n' 'EQEMU_WORKER_RESULT " + result + "' >/dev/ttyS0\n"
    script += '/usr/sbin/poweroff\n'
    return '#cloud-config\n' + json.dumps({
        'hostname': 'eqemu-worker-smoke',
        'ssh_pwauth': False,
        'disable_root': True,
        'write_files': [{'path': '/opt/eqemu-worker-smoke', 'permissions': '0700', 'content': script}],
        'runcmd': [['/opt/eqemu-worker-smoke']],
    }) + '\n'


def build_user_data(nonce):
    """The reviewed guest command travels in seed data, never executes on the host."""
    from pathlib import Path
    return '#cloud-config\n' + json.dumps({
        'hostname': 'eqemu-worker-build', 'ssh_pwauth': False, 'disable_root': True,
        'write_files': [
            {'path': '/opt/eqemu-worker-build-guest', 'permissions': '0600',
             'content': Path(__file__).with_name('build_guest.py').read_text()},
            {'path': '/opt/eqemu-worker-nonce', 'permissions': '0600', 'content': nonce},
            {'path': '/opt/eqemu-worker-checks.json', 'permissions': '0600', 'content': json.dumps(BUILD_CHECKS)},
        ],
        'runcmd': [['/bin/sh', '-c',
                    'exec /usr/bin/python3 -u /opt/eqemu-worker-build-guest >/dev/ttyS0 2>&1']],
    }) + '\n'
