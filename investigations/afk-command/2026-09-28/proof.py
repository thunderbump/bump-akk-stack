#!/usr/bin/env python3
"""Bounded synthetic AFK integration experiment; never candidate acceptance.

The driver owns every process. The separate-session worker models only lifetime,
not VM confinement or privileged runner behavior. No installed code is changed.
"""
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import time

AFK_SHA = 'efd979cd482258d8dba8a044a85f88063d694bb7'
SCRIPT = Path(__file__).resolve()


def write(path, value):
    temp = path.with_suffix('.new')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.replace(path)


def read(path):
    return json.loads(path.read_text())


def wait_for(predicate, seconds=10):
    deadline = time.monotonic() + seconds
    while not predicate():
        if time.monotonic() >= deadline:
            raise TimeoutError('Synthetic experiment observation deadline')
        time.sleep(0.03)


def worker(root):
    """Independent eight-second lifetime, with deliberately slow owned cleanup."""
    signal.alarm(15)  # Backstop even if the driver disappears or this loop breaks.
    write(root / 'worker-start.json', {'pid': os.getpid(), 'pgid': os.getpgrp()})
    deadline = time.monotonic() + 8
    wait_for(lambda: (root / 'cancel').exists() or time.monotonic() >= deadline)
    reason = 'cancelled' if (root / 'cancel').exists() else 'independent_deadline'
    write(root / 'cleanup-start.json', {'reason': reason, 'time': time.monotonic()})
    time.sleep(3.5)
    report = read(root / 'report.json')
    report.update(terminal=True, cleanup_complete=True, error=reason)
    write(root / 'report.json', report)
    write(root / 'worker-finished.json', {'reason': reason, 'time': time.monotonic()})


def client(root, case):
    """Small command prototype: report through existing stdout, always non-pass."""
    signal.alarm(20)
    interrupted = False

    def stop(*_):
        nonlocal interrupted
        interrupted = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    write(root / 'client-start.json', {'pid': os.getpid(), 'pgid': os.getpgrp()})
    identity = read(root / 'identity.json')
    print(json.dumps({'synthetic': True, 'run_id': identity['run_id'],
                      'accepted': False, 'event': 'submitted'}), flush=True)
    try:
        if case == 'refusal':
            raise ValueError('Synthetic admission refused: insufficient disk')
        while True:
            if interrupted:
                (root / 'cancel').touch()
            report = read(root / 'report.json')
            if (report.get('run_id') != identity['run_id']
                    or report.get('accepted') is not False
                    or type(report.get('terminal')) is not bool
                    or type(report.get('cleanup_complete')) is not bool):
                raise ValueError('Invalid synthetic report identity or flags')
            if report['terminal']:
                print(json.dumps({'synthetic': True, 'event': 'final', **report}), flush=True)
                if interrupted:
                    return 130
                return 1 if case == 'candidate_failure' and report['cleanup_complete'] else 2
            time.sleep(0.03)
    except (OSError, ValueError) as error:
        print(json.dumps({'synthetic': True, 'event': 'final',
                          'run_id': identity['run_id'], 'accepted': False,
                          'cleanup_complete': None, 'error': str(error)}), flush=True)
        return 2


def git(workspace, *args):
    return subprocess.check_output(['git', '-C', str(workspace), *args], text=True).strip()


def run_case(root, workspace, afk, case, template):
    from afk_validate.evidence import validate_repairable_failure

    root.mkdir()
    live = case in {'timeout', 'interrupt', 'client_killed'}
    run_id = hashlib.sha256(case.encode()).hexdigest()[:10]
    write(root / 'identity.json', {'run_id': run_id})
    report = dict(template, run_id=run_id, report_directory=str(root),
                  terminal=not live, diagnostic_complete=not live,
                  cleanup_complete=not live, accepted=False)
    if case == 'candidate_failure':
        report.update(diagnostic_only=False, diagnostic_complete=False,
                      error='Synthetic candidate assertion: expected 2, observed 1')
    if case == 'cleanup_incomplete':
        report.update(cleanup_complete=False, error='Synthetic cleanup incomplete')
    if case != 'missing_report':
        write(root / 'report.json', report)
    if case == 'invalid_report':
        write(root / 'report.json', dict(report, run_id='wrong-run'))
    validation = {'schema_version': 1, 'workspace': str(workspace),
                  'command': [sys.executable, '-B', str(SCRIPT), 'client', str(root), case],
                  'timeout_seconds': 2 if case == 'timeout' else 20}
    write(root / 'input.json', validation)
    w = v = None
    client_fd = None
    started = time.monotonic()
    try:
        if live:
            w = subprocess.Popen([sys.executable, '-B', str(SCRIPT), 'worker', str(root)],
                                 start_new_session=True, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
            wait_for(lambda: (root / 'worker-start.json').exists())
        with (root / 'validator.stdout').open('w') as out, (root / 'validator.stderr').open('w') as err:
            v = subprocess.Popen([sys.executable, '-B', '-m', 'afk_validate',
                                  str(root / 'input.json'), str(root / 'afk')],
                                 cwd=afk, stdout=out, stderr=err, start_new_session=True)
            wait_for(lambda: (root / 'client-start.json').exists())
            if live:
                wait_for(lambda: (root / 'afk/stdout.log').exists()
                         and run_id in (root / 'afk/stdout.log').read_text())
                client_state = read(root / 'client-start.json')
                assert client_state['pgid'] != read(root / 'worker-start.json')['pgid']
                # A pidfd prevents cleanup from signalling a reused process ID.
                client_fd = os.pidfd_open(client_state['pid'])
                if case == 'interrupt':
                    v.send_signal(signal.SIGINT)
                if case == 'client_killed':
                    signal.pidfd_send_signal(client_fd, signal.SIGKILL)
            validator_exit = v.wait(timeout=25)
        output = read(root / 'afk/output.json')
        stdout = (root / 'afk/stdout.log').read_text()
        stderr = (root / 'afk/stderr.log').read_text()
        assert len((stdout + stderr).encode()) <= 128 * 1024
        assert validator_exit != 0 and output['outcome'] != 'passed'
        assert run_id in stdout
        try:
            validate_repairable_failure(root / 'afk', workspace)
            repairable = True
        except ValueError:
            repairable = False
        result = {'case': case, 'synthetic': True, 'accepted': False,
                  'validator_exit': validator_exit, 'outcome': output['outcome'],
                  'process': output['process'], 'repairable': repairable,
                  'final_summary_present': '"event": "final"' in stdout,
                  'worker_alive_at_validator_exit': w is not None and w.poll() is None}
        if live:
            assert result['worker_alive_at_validator_exit']
            assert not result['final_summary_present']
            assert output['process']['signal'] == 'SIGKILL'
            assert not repairable
            assert output['outcome'] == {'timeout': 'timed_out', 'interrupt': 'interrupted',
                                         'client_killed': 'failed'}[case]
            assert w.wait(timeout=15) == 0
            final = read(root / 'worker-finished.json')
            result['worker_final'] = final
            result['independent_cleanup_complete'] = read(root / 'report.json')['cleanup_complete']
            assert result['independent_cleanup_complete']
            assert final['reason'] == ('independent_deadline' if case == 'client_killed' else 'cancelled')
        else:
            assert result['final_summary_present'] and repairable
            assert output['process']['exit_code'] == (1 if case == 'candidate_failure' else 2)
        result['duration_seconds'] = round(time.monotonic() - started, 3)
        # Preserve complete compact logs/output, not merely the derived conclusions.
        result.update(afk_output=output, command_stdout=stdout, command_stderr=stderr)
        return result
    finally:
        if client_fd is not None:
            try:
                signal.pidfd_send_signal(client_fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.close(client_fd)
        for process in (v, w):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=3)


def main(afk, destination):
    if os.geteuid() == 0:
        raise RuntimeError('Run this experiment without root')
    afk = afk.resolve()
    assert git(afk, 'rev-parse', 'HEAD') == AFK_SHA
    assert not git(afk, 'diff', 'HEAD')
    sys.path.insert(0, str(afk))
    sys.dont_write_bytecode = True
    signal.alarm(280)
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    destination.mkdir()  # Never overwrite prior evidence.
    template_path = SCRIPT.parents[2] / 'restricted-runner/2026-09-27/receipts/normal-c4d96a00b4/result.json'
    template = read(template_path)
    results = {'synthetic': True, 'accepted': False, 'checks_passed': False,
               'afk_commit': AFK_SHA, 'script_sha256': hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),
               'template_sha256': hashlib.sha256(template_path.read_bytes()).hexdigest(), 'cases': []}
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='eqemu-afk-command-') as temp:
        root = Path(temp)
        workspace = root / 'workspace'
        workspace.mkdir()
        git(workspace, 'init', '-q')
        git(workspace, '-c', 'user.name=Proof', '-c', 'user.email=proof@example.invalid',
            '-c', 'commit.gpgsign=false', 'commit', '-q', '--allow-empty', '-m', 'Synthetic fixture')
        for case in ['diagnostic', 'candidate_failure', 'refusal', 'missing_report',
                     'invalid_report', 'cleanup_incomplete', 'timeout', 'interrupt', 'client_killed']:
            result = run_case(root / case, workspace, afk, case, template)
            results['cases'].append(result)
            write(destination / 'result.json', results)
            print(case, result['outcome'], result['process'], flush=True)
        results['temporary_bytes'] = sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
        assert results['temporary_bytes'] < 10 * 1024**2
    results.update(checks_passed=True, temporary_directory_removed=not root.exists(),
                   duration_seconds=round(time.monotonic() - started, 3))
    assert results['duration_seconds'] < 300
    write(destination / 'result.json', results)
    print(json.dumps({k: v for k, v in results.items() if k != 'cases'}), flush=True)


if __name__ == '__main__':
    if sys.argv[1] == 'client':
        sys.exit(client(Path(sys.argv[2]), sys.argv[3]))
    elif sys.argv[1] == 'worker':
        worker(Path(sys.argv[2]))
    else:
        main(Path(sys.argv[1]), Path(sys.argv[2]))
