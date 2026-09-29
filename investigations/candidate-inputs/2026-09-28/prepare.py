#!/usr/bin/python3 -I
"""Fixed offline candidate-input proof. No VM or compiler is started."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('candidate_inputs', HERE / 'inputs.py')
inputs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inputs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    prepare = commands.add_parser('prepare')
    prepare.add_argument('--source', type=Path, required=True)
    prepare.add_argument('--websocketpp', type=Path, required=True)
    prepare.add_argument('--input-store', type=Path, required=True)
    prepare.add_argument('--output', type=Path, required=True)
    verify = commands.add_parser('verify')
    verify.add_argument('--directory', type=Path, required=True)
    verify.add_argument('--manifest-sha256', required=True)
    verify.add_argument('--input-id', required=True)
    verify.add_argument('--input-store', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise ValueError('Run source preparation without root')
    # The fixed inputs fit below these process/file limits. No unbounded child wait.
    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024**2, 512 * 1024**2))
    def stop(signum, frame):
        raise TimeoutError('Preparation deadline or interruption')
    for sig in (signal.SIGALRM, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, stop)
    signal.alarm(600)
    started = time.monotonic()
    with inputs.regular(HERE / 'profile.json', inputs.MANIFEST_LIMIT) as (stream, _):
        profile = json.load(stream)
    if args.operation == 'prepare':
        result = inputs.prepare(profile, {'eqemu': args.source, 'websocketpp': args.websocketpp},
                                args.input_store, args.output)
    else:
        inputs.check_dependencies(profile, args.input_store)
        manifest = inputs.verify(args.directory, args.manifest_sha256, profile, args.input_id)
        result = {'verified': True, 'accepted': False, 'input_id': manifest['input_id']}
    result['duration_seconds'] = round(time.monotonic() - started, 3)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'prepared': False, 'accepted': False, 'error': str(error)[:2000]}), file=sys.stderr)
        raise SystemExit(2)
