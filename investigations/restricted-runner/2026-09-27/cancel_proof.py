#!/usr/bin/python3 -I
"""One unprivileged ready-then-cancel experiment through the installed interface."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

REPORTS = Path('/var/lib/eqemu-test/reports')
HELPER = '/usr/local/sbin/eqemu-test-request'
PROFILE = 'startup-diagnostic'


def request(op, **fields):
    value = dict(version=1, op=op, **fields)
    result = subprocess.run(['/usr/bin/sudo', '-n', HELPER], input=json.dumps(value),
                            text=True, capture_output=True, timeout=360)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'Installed request failed')
    return json.loads(result.stdout)


def read_report(root, name):
    """Read bounded root-owned published evidence; no caller-written receipts qualify."""
    for directory in (REPORTS, root):
        facts = directory.lstat()
        if not stat.S_ISDIR(facts.st_mode) or facts.st_uid != 0 or facts.st_mode & 0o022:
            raise RuntimeError('Unsafe report directory')
    fd = os.open(root / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        facts = os.fstat(stream.fileno())
        if not stat.S_ISREG(facts.st_mode) or facts.st_uid != 0 or facts.st_mode & 0o022 or facts.st_size > 1024**2:
            raise RuntimeError('Unsafe published report')
        data = stream.read(1024**2 + 1)
        if len(data) > 1024**2:
            raise RuntimeError('Published report grew')
    return json.loads(data), hashlib.sha256(data).hexdigest()


def ready_event(worker):
    for event in worker.get('scenario_events_untrusted', []):
        if event.get('name') == 'ready' and event.get('value', {}).get('zone_connection') is True:
            return event
    return None


def check_cancel(result, worker, suite, cleanup, worker_cleanup, run_id, uid):
    if (result.get('run_id') != run_id or result.get('owner_uid') != uid
            or result.get('terminal') is not True or result.get('cleanup_complete') is not True
            or result.get('accepted') is not False or result.get('diagnostic_only') is not True
            or result.get('diagnostic_complete') is not False):
        raise RuntimeError('Terminal cancellation identity/status mismatch')
    if (suite.get('suite_passed') is not False or suite.get('error') != 'Supervisor interrupted'
            or worker.get('ok') is not False or worker.get('workload_ok') is not False
            or worker.get('error') != 'Controller interrupted'
            or worker.get('diagnostic_complete') is True or worker.get('guest_report_untrusted')):
        raise RuntimeError('Expected interruption was not preserved')
    if (cleanup.get('complete') is not True or cleanup.get('rescued') != []
            or 'controller_budget_error' in cleanup
            or worker.get('uuid') is None or worker.get('uuid') != worker_cleanup.get('uuid')):
        raise RuntimeError('Incomplete suite cleanup or worker identity')
    for key in ('complete', 'domain_absent', 'profile_absent', 'slice_file_absent',
                'cgroup_absent', 'data_absent', 'readonly_inputs_unchanged', 'artifact_input_unchanged'):
        if worker_cleanup.get(key) is not True:
            raise RuntimeError('Incomplete worker cleanup: ' + key)
    events = cleanup.get('controller_budget', {}).get('memory.events', '')
    counters = dict(line.split() for line in events.splitlines())
    if not counters or any(int(counters.get(key, -1)) != 0 for key in ('oom', 'oom_kill')):
        raise RuntimeError('Missing or failed controller memory evidence')


def prove(uid, interrupted, emit):
    result = {'cancellation_checks_passed': False, 'accepted': False, 'started_at': time.time()}
    run_id = None
    cleanup_done = False
    try:
        start = request('run', profile=PROFILE)
        if start.get('started') is not True or not isinstance(start.get('run_id'), str) or not re.fullmatch('[a-f0-9]{10}', start['run_id']):
            raise RuntimeError('Missing admitted run identity')
        run_id = start['run_id']
        result['run_id'] = run_id
        emit(result)
        root = REPORTS / run_id
        deadline = time.monotonic() + 2700
        while True:
            if interrupted():
                raise RuntimeError('Proof interrupted before qualification')
            if time.monotonic() >= deadline:
                raise RuntimeError('Readiness deadline')
            current = request('status', run_id=run_id)
            if current.get('run_id') != run_id or current.get('owner_uid') != uid:
                raise RuntimeError('Status ownership mismatch')
            if current.get('terminal') is True:
                raise RuntimeError('Run ended before controlled cancellation')
            try:
                worker, _ = read_report(root, 'worker.json')
            except FileNotFoundError:
                time.sleep(2)
                continue
            ready = ready_event(worker)
            if ready:
                result['ready'] = ready
                result['worker_uuid'] = worker['uuid']
                result['cancel_requested_at'] = time.time()
                emit(result)
                break
            time.sleep(2)
        final = request('cancel', run_id=run_id)
        result['cancel_result'] = final
        cleanup_done = final.get('terminal') is True and final.get('cleanup_complete') is True
        evidence = {}
        result['receipt_sha256'] = {}
        for name in ('worker.json', 'suite.json', 'cleanup.json', 'worker-cleanup.json'):
            evidence[name], result['receipt_sha256'][name] = read_report(root, name)
        check_cancel(final, evidence['worker.json'], evidence['suite.json'], evidence['cleanup.json'],
                     evidence['worker-cleanup.json'], run_id, uid)
        if evidence['worker.json']['uuid'] != result['worker_uuid']:
            raise RuntimeError('Worker changed across cancellation')
        result['cancellation_checks_passed'] = True
    except Exception as error:
        result['error'] = str(error)[:2000]
    finally:
        if run_id is not None and not cleanup_done:
            try:
                result['failure_cleanup'] = request('cancel', run_id=run_id)
            except Exception as error:
                result['failure_cleanup_error'] = str(error)[:2000]
        result['finished_at'] = time.time()
        emit(result)
    return result


def main():
    uid = pwd.getpwnam('eqemu-test-proof').pw_uid
    if os.getuid() != uid or os.geteuid() != uid or uid == 0 or len(sys.argv) != 1:
        raise RuntimeError('Run without arguments as eqemu-test-proof, never root')
    os.umask(0o077)
    destination = Path(tempfile.mkdtemp(prefix='eqemu-cancel-proof-'))
    destination.chmod(0o755)
    stop = False
    def interrupted(*_):
        nonlocal stop
        stop = True
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    def emit(result):
        result['receipt_path'] = str(destination / 'result.json')
        temporary = destination / 'result.new'
        temporary.write_text(json.dumps(result, indent=2) + '\n')
        temporary.chmod(0o644)
        temporary.replace(destination / 'result.json')
        print(json.dumps(result), flush=True)
    result = prove(uid, lambda: stop, emit)
    return 0 if result['cancellation_checks_passed'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
