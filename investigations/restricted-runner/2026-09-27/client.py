#!/usr/bin/python3 -I
"""Normal-user interface. Diagnostic completion deliberately remains nonzero."""
import argparse
import json
import signal
import subprocess
import sys
import time

HELPER = '/usr/local/sbin/eqemu-test-request'


def request(value, timeout=360):
    result = subprocess.run(['/usr/bin/sudo', '-n', HELPER], input=json.dumps(value),
                            text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or 'Request failed')
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='op', required=True)
    run = commands.add_parser('run')
    run.add_argument('profile', choices=['startup-diagnostic'])
    run.add_argument('--detach', action='store_true')
    for op in ('status', 'cancel'):
        commands.add_parser(op).add_argument('run_id')
    args = parser.parse_args()
    interrupted = False
    def stop(*_):
        nonlocal interrupted
        interrupted = True
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, stop)
    value = {'version': 1, 'op': args.op}
    value.update({'profile': args.profile} if args.op == 'run' else {'run_id': args.run_id})
    result = request(value)
    print(json.dumps(result), flush=True)
    if args.op != 'run':
        return 0
    run_id = result['run_id']
    if args.detach and not interrupted:
        return 0  # Submission only; never validation success.
    deadline = time.monotonic() + 3300
    while True:
        if interrupted or time.monotonic() > deadline:
            result = request({'version': 1, 'op': 'cancel', 'run_id': run_id})
            print(json.dumps(result), flush=True)
            return 130
        result = request({'version': 1, 'op': 'status', 'run_id': run_id})
        if result['terminal']:
            print(json.dumps(result), flush=True)
            return 0 if result['accepted'] and result['cleanup_complete'] else 1
        time.sleep(3)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
