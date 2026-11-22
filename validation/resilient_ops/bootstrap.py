"""Finite standalone operator staging. Run only after external root custody/hash review."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

ROOT = Path('/usr/local/libexec')
TRUSTED_UID = 0


def protected(path):
    for entry in (path, *path.parents):
        info = entry.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise ValueError('protected operator ancestors required')


def regular(path, limit):
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o7022:
            raise ValueError('bounded unlinked regular input required')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            raw = source.read(limit+1)
        if len(raw) > limit:
            raise ValueError('input bound exceeded')
        return raw
    finally:
        os.close(fd)


def stage(package, expected_manifest):
    """Only the manifest-pinned package.py can become a fixed hash-named operator."""
    if not re.fullmatch('[a-f0-9]{64}', expected_manifest):
        raise ValueError('exact selected manifest required')
    package = Path(package)
    # The input directory may be caller-owned but cannot traverse links.
    for path in (package, *package.parents):
        if path.is_symlink() or not path.is_dir():
            raise ValueError('package ancestry cannot traverse links')
    raw = regular(package/'manifest.json', 65536)
    if hashlib.sha256(raw).hexdigest() != expected_manifest:
        raise ValueError('manifest changed')
    manifest = json.loads(raw)
    if set(manifest) != {'version','assets'} or manifest['version'] != 1:
        raise ValueError('invalid manifest')
    expected = manifest['assets']['package.py']
    if not isinstance(expected, str) or not re.fullmatch('[a-f0-9]{64}', expected):
        raise ValueError('invalid operator hash')
    payload = regular(package/'package.py', 1024*1024)
    if hashlib.sha256(payload).hexdigest() != expected:
        raise ValueError('operator changed')
    protected(ROOT)
    destination = ROOT/('eqemu-resilient-ops-operator-'+expected+'.py')
    if destination.exists() or destination.is_symlink():
        info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != TRUSTED_UID
                or stat.S_IMODE(info.st_mode) != 0o600 or regular(destination,1024*1024) != payload):
            raise ValueError('unknown existing operator')
        # A retry must re-establish durable custody, including after a prior
        # file/link effect followed by a failed directory synchronization.
        fd = os.open(destination, os.O_RDONLY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
        fd = os.open(ROOT, os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
        return destination
    fd, name = tempfile.mkstemp(prefix='.rootops-operator-', dir=ROOT)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(payload); out.flush(); os.fsync(out.fileno())
        # No overwrite of an independently installed/changed operator.
        os.link(name, destination)
        fd = os.open(ROOT, os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        os.unlink(name)
    fd = os.open(ROOT, os.O_RDONLY|os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-bootstrap',required=True)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--expected-manifest',required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('external authorized root terminal required')
    here = Path(__file__).absolute()
    protected(here.parent)
    info = here.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600
            or hashlib.sha256(regular(here,1024*1024)).hexdigest() != args.expected_bootstrap):
        raise ValueError('externally verified bootstrap custody required')
    print(json.dumps({'staged_operator':str(stage(args.package,args.expected_manifest))}))


if __name__ == '__main__':
    main()
