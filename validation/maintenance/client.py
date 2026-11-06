"""Unprivileged maintenance client and matched fixed frontend preparation."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import uuid

from maintenance import (SOCKET, REQUEST_LIMIT, RESPONSE_LIMIT, canonical, decode,
                         require, hex_value, sha, FIXTURE, LOCK_PATH, PROTOCOL_PATH)


def exchange(request, endpoint=SOCKET, server_uid=0):
    raw = canonical(request)
    require(len(raw) <= REQUEST_LIMIT, 'request-bound')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(90)
        connection.connect(endpoint)
        peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(peer[1] == server_uid, 'server-peer-denied')
        connection.sendall(raw)
        connection.shutdown(socket.SHUT_WR)
        result = bytearray()
        while b'\n' not in result:
            block = connection.recv(4096)
            require(block, 'response-incomplete')
            result.extend(block)
            require(len(result) <= RESPONSE_LIMIT, 'response-bound')
    value = decode(result)
    require(value.get('schema') == 1 and value.get('id') == request['id']
            and type(value.get('ok')) is bool, 'response-binding')
    require(set(value) == {'schema','id','ok', 'result' if value['ok'] else 'reason'}, 'response-schema')
    return value


def git(repo, *args, limit=65536):
    env = dict(PATH='/usr/bin:/bin', LANG='C.UTF-8', GIT_CONFIG_NOSYSTEM='1',
               GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null',
               GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0')
    value = subprocess.run(['/usr/bin/git', '-C', str(repo), *args], env=env,
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20).stdout
    require(len(value) <= limit, 'git-object-bound')
    return value


def source_request(repo, commit):
    hex_value(commit, 40)
    require(not git(repo, 'status', '--porcelain=v1'), 'source-dirty')
    require(git(repo, 'rev-parse', 'HEAD').decode().strip() == commit, 'source-head')
    tree = git(repo, 'rev-parse', commit + '^{tree}').decode().strip()
    rust = git(repo, 'rev-parse', commit + ':rust').decode().strip()
    proof = {'commit': base64.b64encode(git(repo, 'cat-file', 'commit', commit)).decode()}
    for name in ('', 'rust', 'rust/actors', 'rust/actors/bridge', 'rust/actors/bridge/protocol'):
        obj = tree if not name else git(repo, 'rev-parse', commit + ':' + name).decode().strip()
        proof[name] = base64.b64encode(git(repo, 'cat-file', 'tree', obj)).decode()
    for name in (LOCK_PATH, PROTOCOL_PATH):
        proof[name] = base64.b64encode(git(repo, 'show', commit + ':' + name)).decode()
    return dict(commit=commit, tree=tree, rust_tree=rust), proof


def frontend(repo, output, binding):
    """Code comes from clean Stack Git; only the public fixture is a data overlay."""
    require(not git(repo, 'status', '--porcelain=v1'), 'frontend-dirty')
    commit = git(repo, 'rev-parse', 'HEAD').decode().strip()
    names = git(repo, 'ls-tree', '-r', '--name-only', commit).decode().splitlines()
    selected = [name for name in names if name.startswith('validation/') or name in
                ('scripts/validate-worker-candidate', 'scripts/validation-job', 'scripts/t3-validation-notify')]
    require(len(selected) <= 256, 'frontend-bound')
    raw = base64.b64decode(binding['fixture'], validate=True)
    require(sha(raw) == binding['sha256'], 'fixture-binding')
    output.mkdir(mode=0o700)
    records = {}
    for name in selected:
        # Git trees, not owner-worktree reads, supply every trusted source byte.
        data = raw if name == FIXTURE else git(repo, 'show', commit + ':' + name, limit=1048576)
        path = output / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(data)
        path.chmod(0o500 if name.startswith('scripts/') else 0o400)
        records[name] = sha(data)
    (output / 'stack-source.json').write_bytes(canonical({'source_commit': commit}))
    (output / 'stack-source.json').chmod(0o400)
    (output / 'maintenance-binding.json').write_bytes(canonical(dict(schema=1, source_commit=commit,
        fixture_sha256=sha(raw), source=decode(raw)['server_source'], files=records,
        meaning='trusted Git code with public service fixture data overlay, not a Git checkout')))
    (output / 'maintenance-binding.json').chmod(0o400)
    require(not git(repo, 'status', '--porcelain=v1') and git(repo, 'rev-parse', 'HEAD').decode().strip() == commit, 'frontend-changed')
    return dict(frontend=str(output), source_commit=commit, fixture_sha256=sha(raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='op', required=True)
    for name in ('health', 'status', 'diagnose', 'socket-start', 'socket-stop'):
        sub.add_parser(name)
    retire = sub.add_parser('retire-failed-integration')
    retire.add_argument('--expected-run', required=True)
    publish = sub.add_parser('publish')
    publish.add_argument('--repo', type=Path, required=True)
    publish.add_argument('--commit', required=True)
    publish.add_argument('--expected', required=True)
    publish.add_argument('--request-id', required=True)
    rollback = sub.add_parser('rollback')
    rollback.add_argument('--transaction', required=True)
    prepare = sub.add_parser('frontend')
    prepare.add_argument('--repo', type=Path, required=True)
    prepare.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        request = dict(schema=1, id=uuid.uuid4().hex, op=args.op)
        if args.op == 'publish':
            request['id'] = hex_value(args.request_id, 32)
            request['expected'] = hex_value(args.expected, 64)
            request['source'], request['proof'] = source_request(args.repo, args.commit)
        elif args.op == 'retire-failed-integration':
            request['expected_run'] = hex_value(args.expected_run, 32)
        elif args.op == 'rollback':
            request['transaction'] = hex_value(args.transaction, 32)
        elif args.op == 'frontend':
            request['op'] = 'fixture'
        value = exchange(request)
        if value['ok'] and args.op == 'frontend':
            value['result'] = frontend(args.repo, args.output.absolute(), value['result'])
        print(json.dumps(value, separators=(',', ':')))
        return 0 if value['ok'] else 2
    except Exception:
        print('{"ok":false,"reason":"client-refused-or-submission-uncertain","retry":false}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
