"""Fixed build-package host helpers; no standalone diagnostic entry point."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import time
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, env=ENV, cwd='/', timeout=30)
def parent_safe(path):
    for parent in reversed(Path(path).parents):
        s = parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise RuntimeError('Unsafe parent: ' + str(parent))
def write(path, data, mode):
    with Path(path).open('xb') as stream:
        stream.write(data)
        os.fchmod(stream.fileno(), mode)
def make_dir(path, mode, group=0):
    Path(path).mkdir(mode=mode)
    os.chmod(path, mode)
    os.chown(path, 0, group)
def copy_input(source, target, identity):
    fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    deadline = time.monotonic() + 600
    with os.fdopen(fd, 'rb') as src:
        facts = os.fstat(src.fileno())
        if not stat.S_ISREG(facts.st_mode) or facts.st_size != identity['bytes']:
            raise RuntimeError('Input type/length changed')
        digest = hashlib.sha256()
        with target.open('xb') as dst:
            remaining = identity['bytes']
            while remaining:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Input copy deadline')
                block = src.read(min(1024 * 1024, remaining))
                if not block:
                    raise RuntimeError('Input truncated')
                dst.write(block)
                digest.update(block)
                remaining -= len(block)
            if src.read(1) or digest.hexdigest() != identity['sha256']:
                raise RuntimeError('Input bytes changed')
            dst.flush()
            os.fsync(dst.fileno())
            os.fchmod(dst.fileno(), 0o400)
