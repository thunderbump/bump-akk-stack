#!/usr/bin/python3 -I
"""Prepare an immutable installer package from pinned proof recipes; starts no VM."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import HERE, sha

REPO=HERE.parent
LOCAL=Path('/home/bump/.local/state/eqemu-vm-proof')
PROOF=LOCAL/'candidate-build-inputs-01'


def prepare(output):
    if os.geteuid()==0:
        raise ValueError('Prepare as the normal user')
    previous=json.loads((PROOF/'preparation.json').read_text())
    expected=json.loads((REPO/'investigations/candidate-build/2026-09-28/receipts/preparation.json').read_text())
    for key in ('worker_files','launcher_sha256','build_id','input_id'):
        if previous[key]!=expected[key]:raise ValueError('Build proof template receipt changed')
    for name,digest in dict(previous['worker_files'],**{'launcher.py':previous['launcher_sha256']}).items():
        if sha(PROOF/name)!=digest:raise ValueError('Build proof recipe changed: '+name)
    output=Path(output);output.mkdir(mode=0o700)
    files=['common.py','render.py','host.py','candidate.py','install.py','disable.py']
    for name in files:shutil.copyfile(HERE/name,output/name)
    sources={'host_support.py':'restricted-runner/2026-09-27/control.py',
             'installer_support.py':'restricted-runner/2026-09-27/install.py',
             'inputs.py':'candidate-inputs/2026-09-28/inputs.py',
             'profile.json':'candidate-inputs/2026-09-28/profile.json'}
    for name,path in sources.items():shutil.copyfile(REPO/'investigations'/path,output/name)
    # Cloud-init payloads must be extracted from the sealed seed identities, not
    # trusted merely because adjacent user-data files exist in the local store.
    import ast,subprocess
    for role in ('producer','consumer'):
        worker=(PROOF/(role+'-worker.py')).read_text()
        values=next(ast.literal_eval(n.value) for n in ast.parse(worker).body if isinstance(n,ast.Assign)
                    and any(isinstance(t,ast.Name) and t.id=='FILES' for t in n.targets))
        path,size,digest=values['seed.iso'];seed=LOCAL/path
        if seed.stat().st_size!=size or sha(seed)!=digest:raise ValueError('Sealed guest recipe changed')
        raw=subprocess.check_output(['/usr/bin/isoinfo','-i',str(seed),'-x','/USER_DAT.;1'],timeout=30).decode()
        user=json.loads(raw.split('\n',1)[1])
        (output/(role+'-user.json')).write_text(json.dumps(user))
        (output/(role+'-worker.py.in')).write_text(worker)
    shutil.copyfile(PROOF/'launcher.py',output/'suite.py.in')
    profile=json.loads((output/'profile.json').read_text())
    host_inputs={name:dict(source=str(LOCAL/profile['dependencies'][key]['path']),
                          **{k:profile['dependencies'][key][k] for k in ('bytes','sha256')})
                 for name,key in [('base.qcow2','base'),('fixture.iso','media')]}
    (output/'host-inputs.json').write_text(json.dumps(host_inputs,indent=2)+'\n')
    (output/'previous.json').write_text(json.dumps(previous,indent=2)+'\n')
    config=dict(input_store=str(LOCAL),websocketpp='/home/bump/Projects/bump-eqemu/bump-EQEmu/submodules/websocketpp')
    (output/'client-config.json').write_text(json.dumps(config,indent=2)+'\n')
    manifest={'version':1,'files':{p.name:sha(p) for p in sorted(output.iterdir())}}
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
    return {'prepared':str(output),'manifest_sha256':sha(output/'manifest.json'),'vm_started':False}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    print(json.dumps(prepare(parser.parse_args().output)))
