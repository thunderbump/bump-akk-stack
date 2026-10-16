"""Fixed disposable normal-world fixture. Never execute candidate code on the host.

Root prepares public data; the observer and all three native executables run as
nobody in the offline guest. The observer uses kernel-owned socket identities and
an echoed EQ stream session challenge, not startup log strings.
"""
import json
import os
from pathlib import Path
import pwd
import math
import resource
import signal
import socket
import struct
import subprocess
import sys
import time

SECONDS = 1800
OBSERVE_SECONDS = 120
BASELINE_SECONDS = 5


def cpu_ticks(pid):
    fields = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
    return int(fields[11]) + int(fields[12])


def socket_inodes(pid):
    result = set()
    for fd in Path('/proc', str(pid), 'fd').iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue
        if target.startswith('socket:['):
            result.add(target[8:-1])
    return result


def world_connected(world, zone):
    """Require both ends of an established loopback connection owned by our PIDs."""
    world_inodes, zone_inodes = socket_inodes(world), socket_inodes(zone)
    rows = [line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:]]
    for row in rows:
        if (row[3] == '01' and row[9] in zone_inodes
                and row[2] == '0100007F:2328' and row[1].startswith('0100007F:')):
            if any(peer[3] == '01' and peer[9] in world_inodes
                   and peer[1] == row[2] and peer[2] == row[1] for peer in rows):
                return True
    return False


def probe(port=7000):
    """A fresh random session must be echoed by the live zone's EQ stream handler."""
    challenge = os.urandom(4)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
        stream.connect(('127.0.0.1', port))
        stream.settimeout(.25)
        stream.send(b'\x00\x01' + struct.pack('!I', 2) + challenge + struct.pack('!I', 512))
        try:
            response = stream.recv(512)
        except (TimeoutError, ConnectionRefusedError):
            return False
        return len(response) >= 6 and response[:2] == b'\x00\x02' and response[2:6] == challenge


def owned_members():
    """Observer and native children share the session owned by the root adapter."""
    group = os.getpgrp()
    result = []
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            fields = path.read_text().rsplit(')', 1)[1].split()
            pid = int(path.parent.name)
            if pid != os.getpid() and fields[0] != 'Z' and int(fields[2]) == group:
                result.append(pid)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return result


def stop(processes):
    """Clean the exact owned session even when a native leader exited first."""
    def send(sig):
        for pid in owned_members():
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                pass
    send(signal.SIGTERM)
    end = time.monotonic() + 10
    while owned_members() and time.monotonic() < end:
        time.sleep(.05)
    clean = not owned_members()
    if not clean:
        send(signal.SIGKILL)
    for process in processes:
        process.wait(timeout=5)
    end = time.monotonic() + 2
    while owned_members() and time.monotonic() < end:
        time.sleep(.05)
    return clean and not owned_members()


def validate(value):
    """Host-safe success gate; CPU scheduler ticks are not gameplay tick counts."""
    required = {'exit_code', 'cleanup_complete', 'control', 'ready_seconds', 'baseline_seconds',
                'responsive_samples', 'cpu_ticks', 'clock_ticks_per_second',
                'fixture_manifest_sha256', 'binaries', 'database_cleanup'}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError('Missing normal-world baseline')
    if (type(value['exit_code']) is not int or value['exit_code'] != 0 or value['control'] is not None
            or value['cleanup_complete'] is not True or value['database_cleanup'] is not True):
        raise ValueError('Normal-world completion/cleanup')
    for name, low, high in [('ready_seconds', 0, OBSERVE_SECONDS), ('baseline_seconds', BASELINE_SECONDS, OBSERVE_SECONDS)]:
        number = value[name]
        if type(number) not in (int, float) or not math.isfinite(number) or not low <= number <= high:
            raise ValueError('Invalid normal-world timing')
    if (type(value['responsive_samples']) is not int or not 2 <= value['responsive_samples'] <= 1200
            or type(value['clock_ticks_per_second']) is not int or not 1 <= value['clock_ticks_per_second'] <= 10000
            or not isinstance(value['cpu_ticks'], list) or len(value['cpu_ticks']) != 2
            or any(type(t) is not int or not 0 <= t <= 10000000 for t in value['cpu_ticks'])
            or value['cpu_ticks'][1] <= 0):
        raise ValueError('Invalid normal-world activity')
    import re
    if (not isinstance(value['fixture_manifest_sha256'], str)
            or not re.fullmatch('[a-f0-9]{64}', value['fixture_manifest_sha256'])
            or not isinstance(value['binaries'], dict) or set(value['binaries']) != {'world', 'zone', 'shared_memory'}
            or any(not isinstance(d, str) or not re.fullmatch('[a-f0-9]{64}', d) for d in value['binaries'].values())):
        raise ValueError('Normal-world input/output identity')
    return value


def observe(binary_dir, server, control):
    """Unprivileged source-owned assertion with bounded diagnostics on every path."""
    if os.geteuid() == 0 or not Path('/opt/eqemu-worker-build-guest').is_file():
        raise RuntimeError('Unprivileged disposable guest only')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**2, 1024**2))
    processes = []
    logs = []
    cancelled = False
    def cancel(*_):
        nonlocal cancelled
        cancelled = True
    prior = {sig: signal.signal(sig, cancel) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    result = dict(exit_code=2, cleanup_complete=False, control=control)
    start = time.monotonic()
    try:
        def guard():
            if cancelled or time.monotonic() - start >= OBSERVE_SECONDS:
                raise RuntimeError('Normal-world cancellation or readiness deadline')
            if any(p.poll() is not None for p in processes):
                raise RuntimeError('Normal server exited before assertion completed')
            if any(path.stat().st_size > 1024**2 for path in logs):
                raise RuntimeError('Normal server console budget')
        for name, args in (('world', []), ('zone', ['poknowledge', '7000'])):
            path = server / (name + '-console.log'); logs.append(path)
            with path.open('xb') as log:
                # The startup control uses a deliberately absent config in an owned empty directory.
                cwd = server
                if control == 'startup' and name == 'world':
                    cwd = server / 'missing-config'; cwd.mkdir()
                processes.append(subprocess.Popen([str(binary_dir / name), *args], cwd=cwd,
                    stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT))
        while True:
            guard()
            if world_connected(processes[0].pid, processes[1].pid) and probe():
                break
            time.sleep(.1)
        result['ready_seconds'] = round(time.monotonic() - start, 3)
        print('NORMAL_WORLD_READY', flush=True)
        before = [cpu_ticks(p.pid) for p in processes]
        baseline = time.monotonic(); samples = 0
        while time.monotonic() - baseline < BASELINE_SECONDS or control == 'cancel':
            guard()
            if not world_connected(processes[0].pid, processes[1].pid) or not probe():
                raise RuntimeError('Normal zone lost world connection or application responsiveness')
            samples += 1
            time.sleep(.1)
        delta = [cpu_ticks(p.pid) - tick for p, tick in zip(processes, before)]
        result.update(baseline_seconds=round(time.monotonic() - baseline, 3),
                      responsive_samples=samples, cpu_ticks=delta, clock_ticks_per_second=os.sysconf('SC_CLK_TCK'))
        # No native lifecycle test CLI or candidate-authored completion marker is used.
        if samples < 2 or delta[1] <= 0 or control == 'assertion':
            result.update(exit_code=1, error='Normal-world readiness/activity assertion failed')
        elif control is not None:
            raise RuntimeError('Qualification control unexpectedly completed')
        else:
            result['exit_code'] = 0
    except Exception as error:
        result.update(exit_code=2, error=str(error)[-500:])
    finally:
        try:
            result['cleanup_complete'] = stop(processes)
        finally:
            for sig, handler in prior.items():
                signal.signal(sig, handler)
            for path in logs:
                # The root adapter scrubs credentials before persisting or exporting these tails.
                with path.open('rb') as log:
                    log.seek(max(0, path.stat().st_size - 1200))
                    print(path.name + ': ' + log.read(1200).decode(errors='replace'), flush=True)
        if not result['cleanup_complete']:
            result['exit_code'] = 2
    print('NORMAL_WORLD_RESULT ' + json.dumps(result, separators=(',', ':')), flush=True)


def run(build, identity):
    """Reuse the identified public fixture; preparation is never a host recipe."""
    from actor_runtime import Runtime, ROOT, MEDIA
    if os.geteuid() != 0 or not Path('/opt/eqemu-worker-build-guest').is_file():
        raise RuntimeError('Disposable build guest only')
    if build.DEADLINE - time.monotonic() < SECONDS:
        raise RuntimeError('Insufficient remaining normal-world runtime budget')
    fixture = json.loads(Path('/opt/runtime-fixture.json').read_text())
    control = identity.get('world_control')
    if control not in (None, 'startup', 'assertion', 'cancel'):
        raise RuntimeError('Unknown normal-world control')
    # Existing helper has its own explicit guest budget, allocation guards and redaction.
    ROOT.mkdir(mode=0o755)
    runtime = Runtime(build, None, fixture)
    prior = {sig: signal.signal(sig, lambda *_: setattr(runtime, 'cancelled', True))
             for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    clean = False
    result = None
    error = None
    binaries = {name: build.sha(build.WORK / 'build/bin' / name) for name in ('world', 'zone', 'shared_memory')}
    try:
        MEDIA.mkdir()
        runtime.command('normal-mount-runtime', ['mount', '-o', 'loop,ro,nosuid,nodev,noexec',
                        '/media/eqemu-input/runtime.iso', str(MEDIA)])
        runtime.verify_inputs()
        runtime.install_packages()
        runtime.initialize_database(); runtime.import_database()
        # Native Zone construction reads the selected zone row, not a rule_values
        # entry. Disable idle processing before boot; seconds_before_idle is then
        # irrelevant. Match the exact default PoK row verified by import_database.
        runtime.query('normal-activity', "UPDATE zone SET idle_when_empty=0 WHERE zoneidnumber=202 AND version=0 AND short_name='poknowledge';")
        if runtime.query('normal-activity-check', "SELECT zoneidnumber,version,short_name,idle_when_empty FROM zone WHERE zoneidnumber=202 AND version=0 AND short_name='poknowledge';").strip() != '202\t0\tpoknowledge\t0':
            raise RuntimeError('Empty-zone activity configuration missing')
        server = runtime.configure()
        config_path = server / 'eqemu_config.json'
        config = json.loads(config_path.read_text())
        config['server']['world']['loginserver'] = {'host': '127.0.0.1', 'port': '5998', 'account': '', 'password': ''}
        config_path.write_text(json.dumps(config))
        account = pwd.getpwnam('nobody')
        # Only the disposable runtime belongs to the native user, not tools or source.
        for path in [server, *server.rglob('*')]:
            if not path.is_symlink():
                os.chown(path, account.pw_uid, account.pw_gid)
        prefix = ['/usr/bin/setpriv', '--reuid=' + str(account.pw_uid), '--regid=' + str(account.pw_gid),
                  '--clear-groups', '--no-new-privs']
        runtime.command('normal-shared-memory', [*prefix, str(build.WORK / 'build/bin/shared_memory')], cwd=server, timeout=180)
        for name in ('items', 'spells'):
            path = server / 'shared' / name
            if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= 768*1024**2:
                raise RuntimeError('Missing generated shared data: ' + name)
        ready = False
        def phase(line):
            nonlocal ready
            if line == b'NORMAL_WORLD_READY':
                if ready:
                    raise RuntimeError('Duplicate normal-world readiness phase')
                ready = True
                build.emit({'kind': 'stage', 'name': 'normal-world-ready', 'state': 'started'})
        output = runtime.command('normal-world', [*prefix, '/usr/bin/python3', '/opt/normal_world.py',
                                  str(build.WORK / 'build/bin'), str(server), control or 'positive'],
                                 timeout=OBSERVE_SECONDS+30, on_line=phase)
        frames = [json.loads(line.removeprefix('NORMAL_WORLD_RESULT ')) for line in output.splitlines()
                  if line.startswith('NORMAL_WORLD_RESULT ')]
        if len(frames) != 1:
            raise RuntimeError('Missing/duplicate normal-world assertion completion')
        result = frames[0]
        if result.get('exit_code') not in (0, 1, 2) or result.get('cleanup_complete') is not True:
            raise RuntimeError('Incomplete normal-world cleanup/result')
        if control is not None and result['exit_code'] == 0:
            raise RuntimeError('Qualification control cannot pass')
        runtime.verify_inputs()
        for name, digest in binaries.items():
            if build.sha(build.WORK / 'build/bin' / name) != digest:
                raise RuntimeError('Candidate executable changed: ' + name)
    except Exception as exc:
        error = runtime.scrub(str(exc))[-3000:]
    finally:
        try:
            clean = runtime.cleanup()
        finally:
            for sig, handler in prior.items():
                signal.signal(sig, handler)
    if error or not clean or result is None:
        raise RuntimeError('Normal-world fixture: ' + (error or 'Database/native cleanup incomplete'))
    result.update(fixture_manifest_sha256=fixture['manifest_sha256'], binaries=binaries, database_cleanup=clean)
    if result['exit_code'] == 1:
        raise build.CandidateFailure('Normal-world assertion failed: ' + runtime.scrub(output)[-3000:])
    if result['exit_code'] != 0:
        raise RuntimeError('Normal-world non-pass: ' + runtime.scrub(output)[-3000:])
    return validate(result)


if __name__ == '__main__':
    observe(Path(sys.argv[1]), Path(sys.argv[2]), None if sys.argv[3] == 'positive' else sys.argv[3])
