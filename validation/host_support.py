"""Fixed build-package host helpers; no standalone diagnostic entry point."""
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
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
MAX_REQUEST = 4096
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


def command(args, timeout=30):
    result = subprocess.run(args, capture_output=True, text=True, env=ENV, cwd='/', timeout=timeout)
    if result.returncode:
        raise RuntimeError('Host operation failed: ' + result.stderr[-2000:])
    return result
