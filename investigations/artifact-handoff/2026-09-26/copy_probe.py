#!/usr/bin/python3
"""Copy fixed synthetic bytes in a user service with the worker's memory cap."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

SIZE = 4 * 1024**3


def child(root):
    from artifact import copy_blob, hash_file
    source = root / 'source'
    target = root / 'target'
    with source.open('xb') as stream:
        stream.truncate(SIZE)
    deadline = time.monotonic() + 90
    expected = '8479e43911dc45e89f934fe48d01297e16f51d17aa561d4d1c216b1ae0fcddca'
    started = time.monotonic()
    copy_blob(source, target, SIZE, expected, deadline)
    group = Path('/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1].lstrip('/')
    result = {'bytes': SIZE, 'sha256': expected, 'copy_seconds': time.monotonic()-started,
              'memory': {name:(group/name).read_text().strip() for name in ['memory.max', 'memory.peak', 'memory.events']}}
    result['bounded_copy_memory'] = int(result['memory']['memory.peak']) < 256 * 1024**2
    assert hash_file(target, SIZE, deadline) == expected
    (root / 'result.json').write_text(json.dumps(result))
    if not result['bounded_copy_memory']:
        raise RuntimeError('Copy cache exceeded the regression budget')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--child', type=Path)
    args = parser.parse_args()
    if args.child:
        child(args.child)
        return
    base = Path.home() / '.local/state/eqemu-vm-proof'
    if shutil.disk_usage(base).free < 180 * 1024**3:
        raise RuntimeError('Disk admission failed')
    root = Path(tempfile.mkdtemp(prefix='copy-probe-', dir=base))
    unit = 'eqemu-copy-probe-' + uuid.uuid4().hex[:12] + '.service'
    outcome = {'unit': unit, 'scope': 'synthetic host bytes only', 'cleanup': False}
    try:
        result = subprocess.run(['systemd-run', '--user', '--wait', '--pipe', '--unit='+unit,
            '-p', 'MemoryMax=960M', '-p', 'MemorySwapMax=0', '-p', 'RuntimeMaxSec=120',
            '-p', 'TimeoutStopSec=10', '-p', 'KillMode=control-group', '-p', 'TasksMax=16',
            '-p', 'CPUQuota=100%', sys.executable, str(Path(__file__).resolve()), '--child', str(root)],
            capture_output=True, text=True, timeout=140)
        outcome.update(exit_code=result.returncode, service_output=result.stderr[-4000:])
        if (root/'result.json').exists(): outcome['copy'] = json.loads((root/'result.json').read_text())
    finally:
        subprocess.run(['systemctl', '--user', 'stop', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        result = subprocess.run(['systemctl', '--user', 'show', unit, '-p', 'MainPID', '-p', 'ControlPID', '-p', 'ActiveState'], capture_output=True, text=True, check=True)
        props = dict(line.split('=',1) for line in result.stdout.splitlines())
        if props['MainPID'] != '0' or props['ControlPID'] != '0' or props['ActiveState'] not in ['failed','inactive']:
            raise RuntimeError('Retain copy probe: service still active')
        shutil.rmtree(root)
        outcome['cleanup'] = True
        subprocess.run(['systemctl', '--user', 'reset-failed', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(json.dumps(outcome, indent=2))


if __name__ == '__main__': main()
