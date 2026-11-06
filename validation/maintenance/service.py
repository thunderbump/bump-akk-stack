"""Systemd Accept=yes service. All executable imports live in protected root code."""
import sys
sys.dont_write_bytecode = True
import os
from pathlib import Path
import signal
import socket
import stat

ROOT = Path('/usr/local/lib/eqemu-validator-maintenance-v1')
for path in [*reversed(ROOT.parents), ROOT]:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
        raise SystemExit('maintenance-code-parent-refused')
for name in ('service.py', 'maintenance.py', 'baseline.json'):
    info = (ROOT / name).lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o644:
        raise SystemExit('maintenance-code-refused')
sys.path.insert(0, str(ROOT))
from maintenance import decode, read, sha, serve, Store, STATE

signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError()))
signal.alarm(75)
config = decode(read(ROOT / 'baseline.json')[0])
for name, digest in config['code_sha256'].items():
    if sha(read(ROOT / name)[0]) != digest:
        raise SystemExit('maintenance-code-hash-refused')
with socket.socket(fileno=os.dup(0)) as connection:
    result = serve(connection, config, Store(config))
    print('maintenance-request id=%s ok=%s reason=%s' %
          (result.get('id'), result['ok'], result.get('reason', 'none')), file=sys.stderr, flush=True)
