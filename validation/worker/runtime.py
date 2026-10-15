#!/usr/bin/python3 -I
"""One offline smoke VM under a dedicated worker. No candidate commands run here."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from guest import user_data

CONFIG = Path('/etc/eqemu-validator/config.json')
QEMU = '/usr/bin/qemu-system-x86_64'
QEMU_IMG = '/usr/bin/qemu-img'
CLOUD_LOCALDS = '/usr/bin/cloud-localds'
SECONDS = 300
LOG_LIMIT = 1024**2
BASE_LIMIT = 2 * 1024**3
CONTROLS = ('pass', 'assertion', 'missing-result', 'deadline')


class CleanupError(RuntimeError):
    pass
SCRATCH = ('disk.qcow2', 'seed.iso', 'user-data', 'meta-data')


def read_json(path, limit=16384):
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('JSON size limit: ' + str(path))
    return json.loads(data)


def root_file(path):
    """Configuration and the public base are selected outside worker control."""
    path = Path(path)
    if not path.is_absolute() or any(ch in str(path) for ch in ',\n\r'):
        raise ValueError('Unsupported absolute path')
    for parent in (*reversed(path.parents), path):
        info = parent.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError('Expected root-owned nonwritable input: ' + str(parent))
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('Expected regular input: ' + str(path))
    return path


def config(path=CONFIG):
    value = read_json(root_file(path))
    required = {'version', 'user', 'worker_uid', 'worker_gid', 'state_dir', 'code_dir', 'submitter', 'socket', 'base_image'}
    if set(value) != required or type(value['version']) is not int or value['version'] != 1:
        raise ValueError('Unsupported worker configuration')
    for key in ('state_dir', 'code_dir', 'socket', 'base_image'):
        if not isinstance(value[key], str) or not Path(value[key]).is_absolute() or any(ch in value[key] for ch in ',\n\r'):
            raise ValueError('Unsupported configured path: ' + key)
    account = pwd.getpwnam(value['user'])
    if (account.pw_uid == 0 or account.pw_uid != value['worker_uid'] or account.pw_gid != value['worker_gid']
            or os.geteuid() != account.pw_uid or os.getegid() != account.pw_gid):
        raise ValueError('Runtime must run as the configured nonroot worker')
    state = Path(value['state_dir'])
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != account.pw_uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Worker state must be a private owned directory')
    if state.resolve() != state or Path(value['code_dir']).resolve() != Path(value['code_dir']):
        raise ValueError('Worker paths must not traverse symlinks')
    return value


def resource_state():
    """Observe the actual service cgroup, including children, rather than unit text."""
    location = Path('/proc/self/cgroup').read_text().strip().splitlines()
    row = next(line for line in location if line.startswith('0::'))
    relative = row[3:].lstrip('/')
    if '..' in Path(relative).parts:
        raise ValueError('Unexpected cgroup path')
    root = Path('/sys/fs/cgroup') / relative
    values = {name: (root / name).read_text().strip() for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max')}
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    values.update(no_new_privileges=status['NoNewPrivs'].strip(), effective_capabilities=status['CapEff'].strip())
    return values


def ready(value):
    observed = {'uid': os.geteuid(), 'gid': os.getegid(), 'user': pwd.getpwuid(os.geteuid()).pw_name}
    checks = {}
    try:
        observed['invocation_id'] = invocation(); checks['systemd_invocation'] = True
    except ValueError:
        checks['systemd_invocation'] = False
    for name, tool in (('qemu', QEMU), ('qemu_img', QEMU_IMG), ('cloud_localds', CLOUD_LOCALDS)):
        checks[name] = os.path.isfile(tool) and os.access(tool, os.X_OK)
    try:
        fd = os.open('/dev/kvm', os.O_RDWR | os.O_CLOEXEC)
        os.close(fd)
        checks['kvm'] = True
    except OSError:
        checks['kvm'] = False
    try:
        observed['apparmor'] = Path('/proc/self/attr/current').read_text().strip()
        checks['apparmor'] = observed['apparmor'] == 'eqemu-validator (enforce)'
    except OSError:
        checks['apparmor'] = False
    try:
        limits = resource_state(); observed['resources'] = limits
        quota, period = limits['cpu.max'].split()
        checks['resources'] = (0 < int(limits['memory.max']) <= 2 * 1024**3 and limits['memory.swap.max'] == '0'
                               and 0 < int(limits['pids.max']) <= 128 and 0 < int(quota) <= 2 * int(period)
                               and limits['no_new_privileges'] == '1' and int(limits['effective_capabilities'], 16) == 0)
    except (OSError, ValueError, KeyError, StopIteration):
        checks['resources'] = False
    try:
        base = root_file(value['base_image'])
        checks['public_base'] = 0 < base.stat().st_size <= BASE_LIMIT and os.access(base, os.R_OK)
    except (OSError, ValueError):
        checks['public_base'] = False
    home = pwd.getpwnam(value['submitter']).pw_dir
    checks['submitter_home_hidden'] = not os.access(home, os.R_OK | os.X_OK)
    return {'version': 1, 'operation': 'check', 'scope': 'worker-readiness', 'exit_code': 0 if all(checks.values()) else 2,
            'checks': checks, 'observed': observed, 'vm_started': False, 'execution_qualified': False}


def atomic_json(path, value):
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise ValueError('Unexpected worker temporary record')
        json.dump(value, stream, sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.replace(temporary, path)


def acquire(value):
    fd = os.open(Path(value['state_dir']) / 'worker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise RuntimeError('Another worker operation is active')
    return fd


def scratch_cleanup(job):
    scratch = job / 'scratch'
    if scratch.exists():
        if scratch.is_symlink() or scratch.stat().st_uid != os.geteuid():
            raise RuntimeError('Unexpected smoke scratch ownership')
        if not {item.name for item in scratch.iterdir()} <= set(SCRATCH):
            raise RuntimeError('Unexpected smoke scratch contents')
        for item in scratch.iterdir():
            if item.is_symlink() or not item.is_file():
                raise RuntimeError('Unexpected smoke scratch file')
            item.unlink()
        scratch.rmdir()


def invocation():
    identity = os.environ.get('INVOCATION_ID', '')
    if not re.fullmatch('[a-f0-9]{32}', identity):
        raise ValueError('Worker requires its systemd invocation identity')
    return identity


def cleanup(value):
    """ExecStopPost recovers this invocation only; checks never mutate older jobs."""
    active = Path(value['state_dir']) / 'active.json'
    if not active.exists():
        return 0
    if read_json(active).get('invocation_id') != invocation():
        return 0
    try:
        lock = acquire(value)
    except RuntimeError:
        return 0  # Another accepted connection owns the active run.
    try:
        active = Path(value['state_dir']) / 'active.json'
        if active.exists():
            record = read_json(active)
            if (set(record) != {'run_id', 'invocation_id'} or record['invocation_id'] != invocation()
                    or not re.fullmatch('[a-f0-9]{32}', record['run_id'])):
                raise ValueError('Unexpected active job record')
            job = Path(value['state_dir']) / record['run_id']
            if job.exists():
                if job.is_symlink() or not job.is_dir() or job.stat().st_uid != os.geteuid():
                    raise ValueError('Unexpected active job directory')
                scratch_cleanup(job)
            atomic_json(Path(value['state_dir']) / 'last-result.json', {'version': 1, 'scope': 'worker-smoke', 'run_id': record['run_id'],
                        'exit_code': 2, 'error': 'Controller stopped before final completion',
                        'cleanup_complete': False, 'scratch_removed': True})
            if (job / 'serial.log').exists():
                os.replace(job / 'serial.log', Path(value['state_dir']) / 'last-serial.log')
            if job.exists():
                job.rmdir()
            active.unlink()
        return 0
    finally:
        os.close(lock)


def tool(args, deadline):
    remaining = min(30, deadline - time.monotonic())
    if remaining <= 0:
        raise RuntimeError('Smoke deadline exceeded')
    # Tools share the same owned-session cleanup as QEMU; descendants cannot outlive a timeout.
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               start_new_session=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, close_fds=True)
    try:
        code = process.wait(timeout=remaining)
        if code:
            raise RuntimeError(Path(args[0]).name + ': exit ' + str(code))
    finally:
        stop_process(process)


def disconnected(connection):
    try:
        value = connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
        if value:
            raise RuntimeError('Unexpected extra client data')
        return True
    except BlockingIOError:
        return False


def stop_process(process):
    """Always reap QEMU and its owned session, including exceptional exits."""
    try:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        raise CleanupError('Owned process group remains')
    except CleanupError:
        raise
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CleanupError('Owned process cleanup could not be confirmed') from error


def supervise(args, scratch, log, connection, deadline, nonce):
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               cwd=scratch, start_new_session=True, close_fds=True,
                               env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(scratch)})
    output = bytearray()
    try:
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector, log.open('xb') as stream:
            selector.register(process.stdout, selectors.EVENT_READ)
            eof = False
            while not eof or process.poll() is None:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Smoke deadline exceeded')
                if disconnected(connection):
                    raise RuntimeError('Client disconnected; smoke cancelled')
                for key, _ in selector.select(.1):
                    block = os.read(key.fd, 65536)
                    if not block:
                        eof = True; selector.unregister(key.fileobj)
                        continue
                    if len(output) + len(block) > LOG_LIMIT:
                        raise RuntimeError('Smoke serial output limit exceeded')
                    output.extend(block); stream.write(block); stream.flush()
            if process.wait(timeout=5) != 0:
                raise RuntimeError('QEMU failed')
    finally:
        stop_process(process)
        process.stdout.close()
    results = []
    for line in output.decode(errors='replace').splitlines():
        if line.startswith('EQEMU_WORKER_RESULT '):
            results.append(json.loads(line.removeprefix('EQEMU_WORKER_RESULT ')))
    if len(results) != 1:
        raise RuntimeError('Missing or duplicate guest completion')
    result = results[0]
    if (not isinstance(result, dict) or set(result) != {'version', 'nonce', 'scope', 'exit_code'}
            or type(result['version']) is not int or result['version'] != 1 or result['nonce'] != nonce or result['scope'] != 'worker-smoke'
            or type(result['exit_code']) is not int or result['exit_code'] not in (0, 1)):
        raise RuntimeError('Malformed guest completion')
    return result['exit_code']


def smoke(value, connection, control='pass'):
    lock = acquire(value)
    state = Path(value['state_dir']); active = state / 'active.json'
    run_id = uuid.uuid4().hex; job = state / run_id
    report = {'version': 1, 'operation': 'smoke', 'scope': 'worker-smoke', 'run_id': run_id,
              'control': control, 'exit_code': 2, 'cleanup_complete': False, 'vm_started': False,
              'worker_uid': os.geteuid(), 'coverage': ['tiny-cloud-init'], 'candidate': None}
    try:
        if active.exists():
            raise RuntimeError('Previous smoke requires service cleanup')
        probe = ready(value); report['readiness'] = probe
        if probe['exit_code'] != 0:
            raise RuntimeError('Worker readiness failed')
        if shutil.disk_usage(state).free < 10 * 1024**3:
            raise RuntimeError('Smoke needs 10 GiB free space')
        atomic_json(active, {'run_id': run_id, 'invocation_id': invocation()})
        job.mkdir(mode=0o700); scratch = job / 'scratch'; scratch.mkdir(mode=0o700)
        deadline = time.monotonic() + SECONDS
        base = root_file(value['base_image'])
        with base.open('rb') as stream:
            report['base_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
        (scratch / 'user-data').write_text(user_data(run_id, control))
        (scratch / 'meta-data').write_text('instance-id: eqemu-smoke-' + run_id + '\n')
        tool([QEMU_IMG, 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(scratch / 'disk.qcow2'), '8G'], deadline)
        tool([CLOUD_LOCALDS, str(scratch / 'seed.iso'), str(scratch / 'user-data'), str(scratch / 'meta-data')], deadline)
        args = [QEMU, '-no-user-config', '-nodefaults', '-machine', 'q35,accel=kvm', '-cpu', 'host', '-smp', '2', '-m', '1024',
                '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot',
                '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
                '-drive', 'file=' + str(scratch / 'disk.qcow2') + ',if=virtio,format=qcow2,cache=none',
                '-drive', 'file=' + str(scratch / 'seed.iso') + ',media=cdrom,readonly=on,format=raw']
        report['vm_started'] = True
        report['exit_code'] = supervise(args, scratch, job / 'serial.log', connection, deadline, run_id)
    except Exception as error:
        report['error'] = str(error)[:1000]
        report['exit_code'] = 2
        if isinstance(error, CleanupError):
            report['cleanup_error'] = str(error)[:1000]
    finally:
        try:
            if 'cleanup_error' not in report:
                if job.exists():
                    scratch_cleanup(job)
                report['cleanup_complete'] = True
        except Exception as error:
            report['cleanup_error'] = str(error)[:1000]; report['exit_code'] = 2
        if job.exists():
            atomic_json(state / 'last-result.json', report)
            if (job / 'serial.log').exists():
                os.replace(job / 'serial.log', state / 'last-serial.log')
            if report['cleanup_complete']:
                job.rmdir()
        if active.exists() and read_json(active).get('run_id') == run_id and report['cleanup_complete']:
            active.unlink()
        os.close(lock)
    return report


def request(connection, value):
    """One bounded request on systemd's accepted fd0 socket; no listener or host RPC."""
    peer_uid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
    if peer_uid != pwd.getpwnam(value['submitter']).pw_uid:
        raise ValueError('Socket peer is not the configured submitter')
    connection.settimeout(5)
    raw = bytearray()
    while b'\n' not in raw:
        block = connection.recv(4097 - len(raw))
        if not block:
            raise ValueError('Missing worker request')
        raw.extend(block)
        if len(raw) > 4096:
            raise ValueError('Worker request limit exceeded')
    if not raw.endswith(b'\n') or raw.count(b'\n') != 1:
        raise ValueError('One worker request required')
    data = json.loads(raw)
    if not isinstance(data, dict) or type(data.get('version')) is not int or data['version'] != 1:
        raise ValueError('Unsupported worker request')
    if data == {'version': 1, 'operation': 'check'}:
        return ready(value)
    if set(data) != {'version', 'operation', 'control'} or data['operation'] != 'smoke' or data['control'] not in CONTROLS:
        raise ValueError('Unsupported worker operation')
    connection.settimeout(None)  # MSG_DONTWAIT EOF probes must not inherit the request-read timeout.
    return smoke(value, connection, data['control'])


def interrupted(signum, _):
    raise RuntimeError('Worker interrupted by signal ' + str(signum))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('serve', 'cleanup'))
    parser.add_argument('--config', type=Path, default=CONFIG)
    args = parser.parse_args(argv)
    connection = None
    try:
        value = config(args.config)
        if args.operation == 'cleanup':
            return cleanup(value)
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, interrupted)
        connection = socket.socket(fileno=os.dup(0))
        try:
            result = request(connection, value)
        except Exception as error:
            result = {'version': 1, 'exit_code': 2, 'error': str(error)[:1000], 'scope': 'worker-smoke'}
        try:
            connection.settimeout(5)
            connection.sendall((json.dumps(result, separators=(',', ':')) + '\n').encode())
        except OSError:
            pass  # A disconnected client cannot prevent owned cleanup/result persistence.
        return result['exit_code']
    except Exception as error:
        print('worker: ' + str(error)[:1000], file=sys.stderr)
        return 2
    finally:
        if connection is not None:
            connection.close()


if __name__ == '__main__':
    raise SystemExit(main())
