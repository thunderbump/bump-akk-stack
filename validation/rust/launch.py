"""Bounded root-side launch bootstrap, embedded into the reviewed operator command."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

LIMIT = 256 * 1024


def checked_bytes(source, expected):
    """Hash the same bounded NOFOLLOW bytes that will execute, never reread the source."""
    if not isinstance(expected,str) or not re.fullmatch('[a-f0-9]{64}',expected):
        raise ValueError('Invalid reviewed controller digest')
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=LIMIT:
            raise ValueError('Controller is not a bounded regular file')
    except BaseException:
        os.close(fd)
        raise
    with os.fdopen(fd,'rb') as stream:
        data=stream.read(LIMIT+1)
        if len(data)!=info.st_size or len(data)>LIMIT or hashlib.sha256(data).hexdigest()!=expected:
            raise ValueError('Reviewed controller bytes changed')
    return data


@contextmanager
def staged_script(data,parent):
    """Keep a private executable-source copy alive for the controller's self-copy."""
    with tempfile.TemporaryDirectory(prefix='eqemu-rust-launch-',dir=parent) as temporary:
        root=Path(temporary);root.chmod(0o700)
        file=root/'controller.py'
        fd=os.open(file,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),0o600)
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        yield file


def execute(data,file):
    previous=sys.argv
    sys.argv=[str(file)]
    try:
        exec(compile(data,str(file),'exec'),{'__name__':'__main__','__file__':str(file)})
    finally:
        sys.argv=previous


def main():
    if os.geteuid()!=0 or len(sys.argv)!=3:
        raise ValueError('Reviewed controller launch requires root and fixed arguments')
    parent=Path('/run');info=parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
        raise ValueError('Unsafe root-side launch directory')
    source=Path(sys.argv[1])
    if not source.is_absolute():raise ValueError('Controller path must be absolute')
    data=checked_bytes(source,sys.argv[2])
    with staged_script(data,parent) as file:
        if file.stat().st_uid!=0 or file.parent.stat().st_uid!=0:
            raise ValueError('Launch staging is not root-owned')
        execute(data,file)


if __name__=='__main__':
    main()
