"""Tiny cloud-init workload for worker qualification, not EQEmu acceptance."""
import json


def user_data(nonce, control):
    result = json.dumps({'version': 1, 'nonce': nonce, 'scope': 'worker-smoke',
                         'exit_code': 1 if control == 'assertion' else 0}, separators=(',', ':'))
    script = '#!/bin/sh\nset -eu\n'
    if control == 'deadline':
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
