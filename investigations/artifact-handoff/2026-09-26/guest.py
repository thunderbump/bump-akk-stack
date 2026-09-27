#!/usr/bin/python3
"""Fixed synthetic guest workload. Never run on the host."""
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import sys
import time
import tty
sys.path.insert(0, str(Path(__file__).parent))
from artifact import consume_files, validate_inventory
from diagnostics import DiagnosticTail

ROLE = '@ROLE@'
IDENTITY = 'synthetic-artifact-v1'
SIZE = 4 * 1024**3
PAYLOAD = b'eqemu-artifact-handoff\n' * 2048
MOUNT = Path('/opt/handoff-mount')
DEVICE = '/dev/vdb'
FD = None
NONCE = None
DEADLINE = 0


def command(args):
    timeout = min(120, max(1, DEADLINE - time.monotonic()))
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise RuntimeError(str(args[:2]) + ': ' + result.stdout[-2000:].decode(errors='replace'))
    return result


def emit(value):
    data = ('\nEQEMU_BUILD ' + json.dumps(dict(value, nonce=NONCE), separators=(',', ':')) + '\n').encode()
    if len(data) > 16384:
        raise ValueError('Evidence frame budget')
    end = min(DEADLINE, time.monotonic() + 15)
    while data:
        if time.monotonic() >= end:
            raise TimeoutError('Evidence writer deadline')
        if select.select([], [FD], [], .2)[1]:
            try:
                data = data[os.write(FD, data):]
            except BlockingIOError:
                pass


def controls(inventory):
    for change in ['wrong-identity', 'traversal', 'symlink', 'duplicate', 'oversize']:
        value = json.loads(json.dumps(inventory))
        if change == 'wrong-identity': value['identity'] = 'wrong'
        if change == 'traversal': value['files'][0]['path'] = '../escape'
        if change == 'symlink': value['files'][0]['type'] = 'symlink'
        if change == 'duplicate': value['files'] *= 2
        if change == 'oversize': value['files'][0]['bytes'] = 4 * 1024**3
        try:
            validate_inventory(value, IDENTITY)
        except ValueError:
            continue
        raise RuntimeError('Accepted negative control ' + change)
    tail = DiagnosticTail(['synthetic-credential'])
    child = subprocess.Popen([sys.executable, '-c',
        'import sys; print("[Warning] Aborted connection synthetic-credential", flush=True); sys.exit(3)'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        output, _ = child.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        raise
    for start in range(0, len(output), 7):
        tail.feed(output[start:start+7])
    code = child.returncode
    evidence = tail.export()
    if code != 3 or 'synthetic-credential' in evidence['text'] or 'Aborted connection' not in evidence['text']:
        raise RuntimeError('Diagnostic control failed')
    return {'inventory_negatives': 5, 'observed_child_exit': code, 'diagnostic': evidence}


def workload():
    if not stat.S_ISBLK(os.stat(DEVICE).st_mode) or int(Path('/sys/class/block/vdb/size').read_text()) * 512 != SIZE:
        raise RuntimeError('Unexpected artifact device')
    MOUNT.mkdir()
    mounted = False
    try:
        if ROLE == 'producer':
            command(['mkfs.ext4', '-F', '-m', '0', '-E', 'nodiscard,lazy_itable_init=0,lazy_journal_init=0', DEVICE])
            command(['mount', '-o', 'nosuid,nodev,noexec', DEVICE, str(MOUNT)])
            mounted = True
            (MOUNT / 'payload.bin').write_bytes(PAYLOAD)
            inventory = {'version': 1, 'identity': IDENTITY, 'files': [
                {'path': 'payload.bin', 'type': 'file', 'bytes': len(PAYLOAD), 'sha256': hashlib.sha256(PAYLOAD).hexdigest()}]}
            (MOUNT / 'manifest.json').write_text(json.dumps(inventory, sort_keys=True))
        else:
            command(['mount', '-o', 'ro,noload,nosuid,nodev,noexec', DEVICE, str(MOUNT)])
            mounted = True
            with (MOUNT / 'manifest.json').open('rb') as source:
                data = source.read(262145)
            if len(data) > 262144:
                raise RuntimeError('Manifest budget')
            inventory = json.loads(data)
            destination = Path('/opt/handoff-consumed')
            destination.mkdir()
            consume_files(MOUNT, destination, inventory, IDENTITY, time.monotonic() + 30)
            if (destination / 'payload.bin').read_bytes() != PAYLOAD:
                raise RuntimeError('Payload differs')
            # This writes only to the disposable consumer copy if read-only attachment is broken.
            try:
                fd = os.open(DEVICE, os.O_WRONLY)
                try:
                    os.pwrite(fd, b'X', SIZE - 1)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            except OSError as error:
                if error.errno not in [errno.EROFS, errno.EPERM, errno.EACCES, errno.EIO]:
                    raise
            else:
                raise RuntimeError('Read-only device accepted a write')
        facts = controls(inventory)
        manifest_sha = hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()
        command(['umount', str(MOUNT)])
        mounted = False
        return {'manifest_sha256': manifest_sha, 'payload_sha256': hashlib.sha256(PAYLOAD).hexdigest(),
                'payload_bytes': len(PAYLOAD), 'controls': facts, 'unmounted': True}
    finally:
        if mounted:
            command(['umount', str(MOUNT)])


def main():
    global FD, NONCE, DEADLINE
    if os.geteuid() != 0 or not Path('/opt/handoff/GUEST_ONLY').is_file():
        raise RuntimeError('Guest-only workload')
    if sorted(p.name for p in Path('/sys/class/net').iterdir()) != ['lo']:
        raise RuntimeError('Unexpected network')
    if any(x in Path('/proc/mounts').read_text() for x in [' virtiofs ', ' 9p ', ' nfs ', ' nfs4 ']):
        raise RuntimeError('Unexpected shared mount')
    subprocess.run(['systemctl', 'stop', 'serial-getty@ttyS0.service'], check=True, timeout=30)
    FD = os.open('/dev/ttyS0', os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(FD)
    DEADLINE = time.monotonic() + 300
    try:
        emit({'kind': 'ready', 'role': ROLE})
        pending = b''
        while b'\n' not in pending:
            if time.monotonic() >= DEADLINE or len(pending) > 2048:
                raise RuntimeError('Command timeout or size')
            if select.select([FD], [], [], .2)[0]: pending += os.read(FD, 1024)
        request = json.loads(pending)
        import re
        if set(request) != {'op', 'nonce'} or request['op'] != 'handoff' or not re.fullmatch('[a-f0-9]{32}', request['nonce']):
            raise RuntimeError('Invalid command')
        NONCE = request['nonce']
        emit(dict(workload(), kind='result', ok=True, role=ROLE))
    except Exception as error:
        emit({'kind': 'result', 'ok': False, 'role': ROLE, 'error': str(error)[-2000:]})
    finally:
        subprocess.run(['systemctl', 'poweroff'], timeout=15, check=False)


if __name__ == '__main__':
    main()
