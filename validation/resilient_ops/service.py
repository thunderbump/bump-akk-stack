"""One connected socket, one bounded request. No caller-selected configuration."""
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import time

MAX_REQUEST = 8 * 1024 * 1024
MAX_RESPONSE = 64 * 1024
REQUEST_TIMEOUT = 30
POLICY = Path('/etc/eqemu-resilient-ops/policy.json')
STORE = Path('/var/lib/eqemu-resilient-ops')


def protected(path, directory=False, trusted_uid=0):
    """Reject symlinks and writable/unowned ancestors, including the leaf."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('absolute protected path required')
    for entry in reversed((path, *path.parents)):
        st = entry.lstat()
        if st.st_uid != trusted_uid or st.st_mode & 0o022 or stat.S_ISLNK(st.st_mode):
            raise ValueError('unprotected path')
        if entry != path or directory:
            if not stat.S_ISDIR(st.st_mode):
                raise ValueError('directory required')
        elif not stat.S_ISREG(st.st_mode):
            raise ValueError('regular file required')


def decode(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def serve(connection, engine, rejected_type=()):
    deadline = time.monotonic() + REQUEST_TIMEOUT
    connection.settimeout(REQUEST_TIMEOUT)
    try:
        uid, gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1:]
        if not any((peer['uid'], peer['gid']) == (uid, gid) for peer in engine.policy['peers']):
            raise ValueError('peer is not enrolled')
        data = bytearray()
        while b'\n' not in data:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('request deadline expired')
            connection.settimeout(remaining)
            part = connection.recv(min(65536, MAX_REQUEST + 1 - len(data)))
            if time.monotonic() >= deadline:
                raise TimeoutError('request deadline expired')
            if not part:
                raise ValueError('incomplete request')
            data.extend(part)
            if len(data) > MAX_REQUEST:
                raise ValueError('request too large')
        line, trailing = bytes(data).split(b'\n', 1)
        if trailing:
            raise ValueError('one request per connection')
        request = decode(line)
        if not isinstance(request, dict):
            raise ValueError('request object required')
        if request.get('method') in ('health', 'diagnose'):
            request['method'] = 'status'
        result = engine.handle(request, (uid, gid))
        response = json.dumps(result, separators=(',', ':'), allow_nan=False).encode() + b'\n'
        if len(response) > MAX_RESPONSE:
            raise ValueError('response too large; query operation status')
    except Exception as exc:
        if isinstance(exc, rejected_type):
            response = json.dumps({'ok': False, 'error': str(exc)}, separators=(',', ':')).encode() + b'\n'
            if len(response) > MAX_RESPONSE:
                response = b'{"ok":false,"error":"administrative requirement: bounded rejection required"}\n'
        else:
            # Never reflect policy paths, payloads, or exception details to the peer.
            response = b'{"ok":false,"error":"request_failed"}\n'
    connection.settimeout(REQUEST_TIMEOUT)
    connection.sendall(response)


def main():
    protected(Path(__file__).resolve().parent, directory=True)
    # -I omits the script directory. Only the protected installed release is imported.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    for name in ('engine.py', 'package.py', 'service.py'):
        protected(Path(__file__).resolve().parent / name)
    from package import validate_policy
    from engine import Engine, Rejected
    protected(POLICY)
    protected(STORE, directory=True)
    raw = POLICY.read_bytes()
    if len(raw) > 65536:
        raise ValueError('policy too large')
    policy = decode(raw)
    validate_policy(policy)
    with socket.socket(fileno=os.dup(0)) as connection:
        if connection.family != socket.AF_UNIX or connection.type != socket.SOCK_STREAM:
            raise ValueError('connected AF_UNIX stream required')
        connection.getpeername()
        serve(connection, Engine(policy, STORE), Rejected)


if __name__ == '__main__':
    main()
