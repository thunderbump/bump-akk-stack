#!/usr/bin/python3
"""Prepare two fresh workers and one fixed foreground sequencing command; starts no VM."""
import hashlib
import importlib.util
import json
from pathlib import Path

SOURCE=Path(__file__).resolve().parent
LOCAL=Path('/home/bump/.local/state/eqemu-vm-proof')


def main():
    target=LOCAL/'offline-runtime-lifecycle-01.py'
    receipt=LOCAL/'runtime-lifecycle-preparation-01.json'
    if any(p.exists() or p.is_symlink() for p in [target,receipt,Path('/var/lib/eqemu-vm-proof/runtime-lifecycle-01')]):
        raise RuntimeError('Preserve existing lifecycle preparation')
    for number in ['05','06']:
        for p in [LOCAL/('runtime-reuse-inputs-'+number),LOCAL/('offline-runtime-reuse-'+number+'.py'),Path('/var/lib/eqemu-vm-proof')/('runtime-reuse-'+number)]:
            if p.exists() or p.is_symlink():raise RuntimeError('Preserve existing child preparation')
    spec=importlib.util.spec_from_file_location('prepare_runtime',SOURCE/'prepare.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    launchers={}
    for number in ['05','06']:
        module.prepare(number)
        launchers[number]=module.sha(LOCAL/('offline-runtime-reuse-'+number+'.py'))
    code=(SOURCE/'lifecycle.py').read_text().replace('LAUNCHERS={}  # Bound to the two prepared launcher digests during preparation.','LAUNCHERS='+repr(launchers))
    compile(code,str(target),'exec');target.write_text(code)
    receipt.write_text(json.dumps({'scope':'cancel suite after readiness, verify cleanup, then fresh diagnostic repeat; no candidate acceptance',
        'launchers':launchers,'driver_sha256':module.sha(target),'driver_source_sha256':module.sha(SOURCE/'lifecycle.py')},indent=2)+'\n')
    print(json.dumps({'driver':str(target),'prepared':True,'vm_started':False}))


if __name__=='__main__':main()
