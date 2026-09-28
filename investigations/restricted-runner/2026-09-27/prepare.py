#!/usr/bin/python3
"""Seal the reviewed installation file set; never install or start a VM."""
import hashlib
import json
from pathlib import Path

SOURCE = Path(__file__).resolve().parent
FILES = ('control.py', 'client.py', 'install.py', 'remove.py', 'preflight.py',
         'worker.py.in', 'suite.py.in', 'inputs.json', 'provenance.json', 'probe.py')


def main():
    manifest = {'version': 1, 'files': {name: hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() for name in FILES}}
    (SOURCE / 'manifest.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    print('Sealed installer manifest; no installation or VM started')


if __name__ == '__main__':
    main()
