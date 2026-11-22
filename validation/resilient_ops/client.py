"""Unprivileged client for the additive resilient operations socket."""
import argparse
import base64
import json
import os
from pathlib import Path
import socket
import stat

SOCKET = '/run/eqemu-resilient-ops.sock'
MAX_REQUEST = 8 * 1024 * 1024
MAX_RESPONSE = 64 * 1024


def artifact(directory):
    """Read regular files without following symlinks, with bounded total input."""
    result = {}
    total = 0
    entries = 0
    def visit(fd, prefix=''):
        nonlocal total, entries
        if prefix.count('/') > 32:
            raise ValueError('artifact directory nesting too deep')
        for name in sorted(os.listdir(fd)):
            entries += 1
            if entries > 4096:
                raise ValueError('too many artifact entries')
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if st.st_mode & 0o7000:
                raise ValueError('artifact privilege bits are not supported')
            relative = prefix + name
            if stat.S_ISDIR(st.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    visit(child, relative + '/')
                finally:
                    os.close(child)
            elif stat.S_ISREG(st.st_mode):
                leaf = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    if not stat.S_ISREG(os.fstat(leaf).st_mode) or os.fstat(leaf).st_mode & 0o7000:
                        raise ValueError('regular file required')
                    with os.fdopen(leaf, 'rb', closefd=False) as stream:
                        data = stream.read(MAX_REQUEST + 1 - total)
                finally:
                    os.close(leaf)
                total += len(data)
                if total > MAX_REQUEST or len(result) >= 4096:
                    raise ValueError('artifact too large')
                result[relative] = base64.b64encode(data).decode('ascii')
            else:
                raise ValueError('artifact contains nonregular entry')
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.fstat(fd).st_mode & 0o7000:
            raise ValueError('artifact privilege bits are not supported')
        visit(fd)
    finally:
        os.close(fd)
    return result


def call(request, socket_path=SOCKET):
    wire = json.dumps(request, separators=(',', ':'), allow_nan=False).encode() + b'\n'
    if len(wire) > MAX_REQUEST:
        raise ValueError('request too large')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3600)
        connection.connect(socket_path)
        connection.sendall(wire)
        connection.shutdown(socket.SHUT_WR)
        data = bytearray()
        while b'\n' not in data:
            chunk = connection.recv(min(65536, MAX_RESPONSE + 1 - len(data)))
            if not chunk:
                raise ValueError('incomplete response')
            data.extend(chunk)
            if len(data) > MAX_RESPONSE:
                raise ValueError('response too large')
        line, extra = bytes(data).split(b'\n', 1)
        if extra:
            raise ValueError('unexpected response data')
        return json.loads(line)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='method', required=True)
    prepare = commands.add_parser('prepare')
    prepare.add_argument('--request-id', required=True)
    prepare.add_argument('--target', required=True)
    prepare.add_argument('--action', choices=('publish', 'revert', 'recover'), required=True)
    prepare.add_argument('--generation', type=int, required=True)
    prepare.add_argument('--artifact', type=Path)
    prepare.add_argument('--release')
    prepare.add_argument('--recovery-of')
    execute = commands.add_parser('execute')
    execute.add_argument('--operation-id', required=True)
    execute.add_argument('--plan-id', required=True)
    for name in ('status', 'health', 'diagnose'):
        status = commands.add_parser(name)
        status.add_argument('--operation-id')
        status.add_argument('--target')
    args = vars(parser.parse_args(argv))
    if args.get('artifact') is not None:
        args['artifact'] = artifact(args['artifact'])
    request = {key: value for key, value in args.items() if value is not None}
    result = call(request)
    print(json.dumps(result, sort_keys=True))
    return 1 if result.get('ok') is False else 0


if __name__ == '__main__':
    raise SystemExit(main())
