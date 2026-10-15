"""Ordinary-user client for the fixed worker socket. Never invokes sudo."""
import argparse
import json
from pathlib import Path
import socket
import sys
import time

CONFIG = Path('/etc/eqemu-validator/config.json')
REPORT_LIMIT = 16384


def exchange(path, request, payload=None):
    """Read-only probes may briefly race systemd's previous connection teardown."""
    deadline = time.monotonic() + 2
    while True:
        try:
            return exchange_once(path, request, payload)
        except (ConnectionResetError, BrokenPipeError):
            # Never retry a build/smoke request: it may already have started a VM.
            if request['operation'] not in ('check', 'last-result') or time.monotonic() >= deadline:
                raise
            time.sleep(.1)


def exchange_once(path, request, payload=None):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(18330 if request['operation'] == 'build' else 330 if request['operation'] == 'smoke' else 15)
        connection.connect(str(path))
        connection.sendall((json.dumps(request, separators=(',', ':')) + '\n').encode())
        if payload is not None:
            with Path(payload).open('rb') as stream:
                while block := stream.read(1024**2):
                    connection.sendall(block)
        data = bytearray()
        while b'\n' not in data:
            block = connection.recv(min(4096, REPORT_LIMIT + 1 - len(data)))
            if not block:
                raise RuntimeError('Worker closed without a final report')
            data.extend(block)
            if len(data) > REPORT_LIMIT:
                raise RuntimeError('Worker report size limit exceeded')
        if not data.endswith(b'\n') or data.count(b'\n') != 1:
            raise RuntimeError('Expected one final worker report')
        result = json.loads(data)
        if (not isinstance(result, dict) or type(result.get('version')) is not int or result['version'] != 1
                or type(result.get('exit_code')) is not int or result['exit_code'] not in (0, 1, 2)):
            raise RuntimeError('Malformed worker report')
        if result['exit_code'] in (0, 1):
            if request['operation'] == 'build' and (result.get('scope') != 'worker-build'
                    or result.get('operation') != 'build' or result.get('cleanup_complete') is not True
                    or result.get('vm_started') is not True or result.get('candidate') != request['candidate']
                    or result.get('tree') != request['tree'] or result.get('payload_sha256') != request['sha256']):
                raise RuntimeError('Incomplete or mismatched build result')
            if request['operation'] == 'smoke' and (result.get('scope') != 'worker-smoke'
                    or result.get('operation') != 'smoke' or result.get('cleanup_complete') is not True
                    or result.get('vm_started') is not True or result.get('control') != request['control']):
                raise RuntimeError('Incomplete smoke result')
            if request['operation'] == 'last-result' and (result.get('operation') != 'last-result'
                    or result.get('scope') != 'worker-observation' or not isinstance(result.get('result'), dict)):
                raise RuntimeError('Incomplete last-result observation')
            if request['operation'] == 'check' and (result.get('scope') != 'worker-readiness'
                    or result.get('operation') != 'check' or result.get('vm_started') is not False
                    or not isinstance(result.get('checks'), dict) or not result['checks']
                    or any(value is not True for value in result['checks'].values())):
                raise RuntimeError('Incomplete readiness result')
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument('--smoke', action='store_true', help='Explicitly run the tiny disposable VM')
    operation.add_argument('--last-result', action='store_true', help='Read the most recent persisted smoke report')
    parser.add_argument('--control', choices=('pass', 'assertion', 'missing-result', 'deadline', 'controller-death'), default='pass')
    parser.add_argument('--config', type=Path, default=CONFIG)
    args = parser.parse_args(argv)
    if not args.smoke and args.control != 'pass':
        parser.error('--control requires --smoke')
    request = {'version': 1, 'operation': 'smoke' if args.smoke else 'last-result' if args.last_result else 'check'}
    if args.smoke:
        request['control'] = args.control
    try:
        with args.config.open('rb') as stream:
            raw = stream.read(16385)
        if len(raw) > 16384:
            raise RuntimeError('Worker configuration size limit exceeded')
        path = json.loads(raw)['socket']
        if not isinstance(path, str) or not Path(path).is_absolute():
            raise RuntimeError('Worker socket must be an absolute path')
        result = exchange(path, request)
    except KeyboardInterrupt:
        result = {'version': 1, 'scope': 'worker-smoke', 'exit_code': 2,
                  'error': 'Client interrupted; connection closed for owned worker cancellation'}
    except Exception as error:
        result = {'version': 1, 'exit_code': 2, 'error': str(error)[:1000]}
    print(json.dumps(result, separators=(',', ':')))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
