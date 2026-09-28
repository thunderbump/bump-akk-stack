#!/usr/bin/python3 -I
"""Installed host interface. Only fixed profiles and owned run IDs cross this seam."""
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import stat
import subprocess
import sys
import time
import uuid

VERSION = Path(__file__).resolve().parent
BASE = Path('/var/lib/eqemu-test')
GROUP = 'eqemu-test'
PROFILE = 'startup-diagnostic'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
MAX_REQUEST = 4096
MAX_RUNS = 8
sys.dont_write_bytecode = True


def safe_path(path, directory=False):
    """Every ancestor is administrator-controlled; no symlink traversal."""
    path = Path(path)
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Unsafe ancestor: ' + str(parent))
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Unsafe installed path: ' + str(path))
    return info


def read_json(path):
    if safe_path(path).st_size > 1024 * 1024:
        raise ValueError('Oversized host record')
    return json.loads(Path(path).read_text())


def write_json(path, value, group=None):
    path = Path(path)
    safe_path(path.parent, directory=True)
    if path.exists() or path.is_symlink():
        safe_path(path)
    data = (json.dumps(value, indent=2) + '\n').encode()
    temporary = path.with_suffix('.new')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            if group is not None:
                os.fchown(stream.fileno(), 0, group)
                os.fchmod(stream.fileno(), 0o640)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def checked_id(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{10}', value):
        raise ValueError('Invalid run ID')
    return value


def parse_request(raw):
    if len(raw) > MAX_REQUEST:
        raise ValueError('Request too large')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Duplicate request key')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('Invalid request') from error
    if not isinstance(value, dict) or type(value.get('version')) is not int or value['version'] != 1:
        raise ValueError('Invalid request version')
    op = value.get('op')
    if op == 'run':
        if set(value) != {'version', 'op', 'profile'} or value['profile'] != PROFILE:
            raise ValueError('Unknown profile or fields')
    elif op in ('status', 'cancel'):
        if set(value) != {'version', 'op', 'run_id'}:
            raise ValueError('Unknown request fields')
        checked_id(value['run_id'])
    else:
        raise ValueError('Unknown operation')
    return value


def read_request(fd, seconds=2):
    end = time.monotonic() + seconds
    data = b''
    while True:
        remaining = end - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            raise ValueError('Request deadline')
        block = os.read(fd, MAX_REQUEST + 1 - len(data))
        if not block:
            return parse_request(data)
        data += block
        if len(data) > MAX_REQUEST:
            raise ValueError('Request too large')


def caller_uid():
    value = os.environ.get('SUDO_UID', '')
    if not re.fullmatch('[0-9]{1,10}', value) or int(value) == 0:
        raise ValueError('Use the installed helper through sudo as a submitter')
    import pwd
    account = pwd.getpwuid(int(value))
    group = grp.getgrnam(GROUP)
    if account.pw_gid != group.gr_gid and account.pw_name not in group.gr_mem:
        raise ValueError('Caller is not a submitter')
    return account.pw_uid


def command(args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, env=ENV, cwd='/', timeout=timeout)
    if result.returncode:
        raise RuntimeError('Host operation failed: ' + result.stderr[-2000:])
    return result


def verify_installation():
    manifest = read_json(VERSION / 'manifest.json')
    for name, expected in manifest['files'].items():
        if not re.fullmatch('[a-zA-Z0-9_.-]+', name):
            raise ValueError('Installed manifest path')
        path = VERSION / name
        if safe_path(path).st_size > 256 * 1024 or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Installed code changed: ' + name)
    safe_path(BASE, directory=True)
    return manifest


def run_root(run_id, uid=None):
    root = BASE / 'runs' / checked_id(run_id)
    safe_path(root, directory=True)
    owner = read_json(root / 'owner.json')
    if owner['run_id'] != run_id or owner['version'] != str(VERSION):
        raise ValueError('Run installation identity mismatch')
    if uid is not None and owner['uid'] != uid:
        raise ValueError('Run belongs to another submitter')
    return root


def load_suite(root):
    owner = read_json(root / 'owner.json')
    for name in ('suite.py', 'consumer-worker.py'):
        path = root / name
        if safe_path(path).st_size > 256 * 1024 or hashlib.sha256(path.read_bytes()).hexdigest() != owner['code'][name]:
            raise ValueError('Run controller changed')
    spec = importlib.util.spec_from_file_location('installed_suite', root / 'suite.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def render(run_id):
    checked_id(run_id)
    worker = (VERSION / 'worker.py.in').read_text().replace('@RUN@', run_id)
    suite = (VERSION / 'suite.py.in').read_text().replace('@RUN@', run_id)
    suite = suite.replace('@VERSION@', str(VERSION)).replace('@WORKER_SHA@', hashlib.sha256(worker.encode()).hexdigest())
    return {'consumer-worker.py': worker, 'suite.py': suite}


def publish_locked(run_id):
    """Export fixed bounded evidence names, never a guest-selected host path."""
    root = run_root(run_id)
    suite = load_suite(root)
    owner = read_json(root / 'owner.json')
    group = grp.getgrnam(GROUP).gr_gid
    output = BASE / 'reports' / run_id
    if not output.exists():
        output.mkdir(mode=0o750)
        output.chmod(0o750)
        os.chown(output, 0, group)
    safe_path(output, directory=True)
    summary = read_json(root / 'suite-result.json') if (root / 'suite-result.json').exists() else {}
    cleanup = summary.get('cleanup', {})
    stopped = suite.quiescent(suite.properties(suite.UNIT))
    absent = False
    if stopped and cleanup.get('complete') is True:
        worker = suite.module('consumer')
        absent = (suite.absent(worker, worker.state()) if worker.ROOT.exists()
                  else suite.unstarted_absent(worker) and not suite.read(root / 'leases.json')['active'])
    result = {'version': 1, 'run_id': run_id, 'owner_uid': owner['uid'],
              'terminal': stopped, 'accepted': False, 'diagnostic_only': True,
              'diagnostic_complete': summary.get('diagnostic_complete') is True,
              'cleanup_complete': cleanup.get('complete') is True and absent,
              'error': summary.get('error', owner.get('setup_error')),
              'report_directory': str(output)}
    for name, source in [('suite.json', root / 'suite-result.json'),
                         ('cleanup.json', root / 'suite-cleanup.json'),
                         ('worker.json', root / 'consumer/evidence/report.json'),
                         ('worker-cleanup.json', root / 'consumer/evidence/cleanup.json')]:
        if source.exists():
            write_json(output / name, read_json(source), group)
    # Already bounded by the worker; publish private diagnostic streams only to the report group.
    for name in ('serial.log', 'diagnostics.jsonl'):
        source = root / 'consumer/evidence' / name
        if source.exists():
            if safe_path(source).st_size > 1024 * 1024:
                raise ValueError('Diagnostic publication size')
            target = output / name
            if target.exists():
                safe_path(target)
            temporary = output / (name + '.new')
            with temporary.open('xb') as stream:
                stream.write(source.read_bytes())
                os.fchown(stream.fileno(), 0, group)
                os.fchmod(stream.fileno(), 0o640)
            temporary.replace(target)
    write_json(output / 'result.json', result, group)
    return result


def publish(run_id):
    root = run_root(run_id)
    lock_path = root / 'publication.lock'
    safe_path(lock_path)
    with lock_path.open('r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return publish_locked(run_id)


def admission_preflight():
    # Reject expired inputs or unavailable capacity before creating a reservation.
    import types
    modules = {}
    for name, text in render('0000000000').items():
        module = types.ModuleType(name)
        module.__file__ = str(VERSION / name)
        exec(compile(text, module.__file__, 'exec'), module.__dict__)
        modules[name] = module
    modules['suite.py'].prerequisites()
    modules['consumer-worker.py'].admission()


def start(uid):
    admission_preflight()
    # The request lock serializes requests; active.json reserves the worker across processes.
    active_path = BASE / 'active.json'
    if active_path.exists():
        previous = read_json(active_path)['run_id']
        prior = publish(previous)
        if not prior['terminal'] or not prior['cleanup_complete']:
            raise RuntimeError('Previous run active or cleanup incomplete: ' + previous)
        active_path.unlink()
    runs = BASE / 'runs'
    if len(list(runs.iterdir())) >= MAX_RUNS:
        raise RuntimeError('Eight-run evidence limit reached; administrator retention review required')
    run_id = uuid.uuid4().hex[:10]
    root = runs / run_id
    root.mkdir(mode=0o711)
    root.chmod(0o711)
    code = render(run_id)
    owner = {'run_id': run_id, 'uid': uid, 'version': str(VERSION), 'created_at': time.time(), 'code': {}}
    for name, value in code.items():
        path = root / name
        with path.open('x') as stream:
            stream.write(value)
        path.chmod(0o600)
        owner['code'][name] = hashlib.sha256(value.encode()).hexdigest()
    write_json(root / 'owner.json', owner)
    with (root / 'publication.lock').open('x'):
        pass
    write_json(active_path, {'run_id': run_id})
    try:
        suite = load_suite(root)
        # setup only validates and starts the bounded supervisor; expensive work stays in its cgroup.
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            suite.setup()
    except Exception as error:
        owner['setup_error'] = str(error)[:2000]
        write_json(root / 'owner.json', owner)
        try:
            worker = suite.module('consumer')
            if suite.quiescent(suite.properties(suite.UNIT)) and suite.unstarted_absent(worker):
                if suite.CTLFILE.exists():
                    safe_path(suite.CTLFILE)
                    if suite.CTLFILE.read_text() != suite.CTLTEXT:
                        raise ValueError('Controller slice changed')
                    suite.CTLFILE.unlink()
                    suite.run(['/usr/bin/systemctl', 'daemon-reload'])
                write_json(root / 'leases.json', {'active': {}, 'released': []})
                cleanup = {'complete': True, 'unstarted': True, 'rescued': []}
                write_json(root / 'suite-result.json', {'suite_passed': False, 'error': owner['setup_error'], 'cleanup': cleanup})
                write_json(root / 'suite-cleanup.json', cleanup)
                active_path.unlink()
        except Exception:
            pass  # Unknown ownership stays reserved for administrator inspection.
        raise RuntimeError('Setup failed; retained for exact recovery: ' + run_id) from error
    return {'started': True, 'run_id': run_id, 'accepted': False}


def dispatch(request, uid):
    safe_path(BASE / 'request.lock')
    with (BASE / 'request.lock').open('r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if request['op'] == 'run':
            installation = read_json(BASE / 'installation.json')
            if installation.get('enabled') is not True or installation.get('version') != str(VERSION):
                raise RuntimeError('Admission disabled')
            return start(uid)
        root = run_root(request['run_id'], uid)
        if request['op'] == 'cancel':
            suite = load_suite(root)
            if not suite.quiescent(suite.properties(suite.UNIT)):
                suite.run(['/usr/bin/systemctl', 'stop', suite.UNIT], timeout=330)
        return publish(request['run_id'])


def main():
    if os.geteuid() != 0:
        raise ValueError('Privileged helper requires sudo')
    os.umask(0o077)
    # Complete the bounded request handoff even if its client loses the terminal.
    # Explicit cancel and the worker deadline own cancellation after admission.
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    verify_installation()
    if len(sys.argv) == 3 and sys.argv[1] == 'publish':
        # Only the installed controller invokes this directly, never sudoers callers.
        result = publish(checked_id(sys.argv[2]))
    elif len(sys.argv) == 1:
        uid = caller_uid()
        request = read_request(0)
        os.environ.clear()
        os.environ.update(ENV)
        result = dispatch(request, uid)
    else:
        raise ValueError('No command arguments permitted')
    print(json.dumps(result), flush=True)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({'error': str(error)[:2000]}), file=sys.stderr)
        sys.exit(1)
