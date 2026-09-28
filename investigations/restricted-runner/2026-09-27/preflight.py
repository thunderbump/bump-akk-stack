#!/usr/bin/python3 -I
"""Installed preflight: verify code, qualified build, media and static confinement only."""
import importlib.util
from pathlib import Path
import sys
import types


def main():
    version = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('control', version / 'control.py')
    control = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(control)
    control.verify_installation()
    code = control.render('0000000001')
    suite = types.ModuleType('suite')
    suite.__file__ = str(version / 'suite.py.in')
    exec(compile(code['suite.py'], suite.__file__, 'exec'), suite.__dict__)
    suite.prerequisites()
    worker = types.ModuleType('worker')
    worker.__file__ = str(version / 'worker.py.in')
    exec(compile(code['consumer-worker.py'], worker.__file__, 'exec'), worker.__dict__)
    sys.argv = ['worker', '--check']
    worker.main()


if __name__ == '__main__':
    main()
