#!/usr/bin/python3
"""Render one reviewed offline debugger VM proof from the pinned isolation controller."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

VALIDATION = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(VALIDATION))
from actor import verify_media
from inputs import file_record

# Published beaa47e3a1eb5df3c10053360021ca50bc3c4f94, first-vm-trial.py.
CONTROLLER_SHA = 'd1282bf26dc69e061d7ce65871d3464604b24a6be5fdc31714b5667b153c0b23'


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def assign(text, name, expression):
    nodes = [node for node in ast.parse(text).body if isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)]
    if len(nodes) != 1: raise ValueError('Controller seam changed: '+name)
    node = nodes[0]; lines = text.splitlines(keepends=True)
    return ''.join(lines[:node.lineno-1])+name+'='+expression+'\n'+''.join(lines[node.end_lineno:])


def prepare(store, template, output):
    store = store.resolve(strict=True); template = template.resolve(strict=True)
    if sha(template) != CONTROLLER_SHA: raise ValueError('Pinned isolation controller changed')
    output = output.resolve()
    if output.exists(): raise ValueError('Use a new proof directory')
    fixture = json.loads((VALIDATION/'runtime-fixture.json').read_text())
    verified = verify_media(store, fixture, file_record)
    output.mkdir(mode=0o700)
    files = {}
    sources = {name: VALIDATION/name for name in
               ('actor.py','actor_runtime.py','debugger.py','debugger-gdb.py','runtime-fixture.json')}
    sources['guest_build.py'] = VALIDATION/'recipes/consumer-guest.py'
    sources['proof_guest.py'] = Path(__file__).with_name('proof_guest.py')
    sources['test_debugger.py'] = VALIDATION.parent/'tests/validation/test_debugger.py'
    for name, source in sources.items():
        files['/opt/eqemu-proof/'+name] = source.read_text()
    files['/opt/eqemu-proof/BUILD_GUEST_ONLY'] = 'debugger-provisioning-proof\n'
    user = dict(package_update=False, package_upgrade=False, users=[], ssh_pwauth=False,
                disable_root=True, growpart=dict(mode='auto', devices=['/'], ignore_growroot_disabled=False),
                write_files=[dict(path=name, permissions='0600', content=data) for name,data in files.items()],
                runcmd=[['systemctl','mask','--now','apt-daily.timer','apt-daily-upgrade.timer'],
                        ['python3','-B','/opt/eqemu-proof/proof_guest.py']])
    data = output/'user-data'; data.write_text('#cloud-config\n'+json.dumps(user)+'\n')
    meta = output/'meta-data'; meta.write_text('instance-id: eqemu-debugger-proof-20261008\n')
    seed = output/'seed.iso'
    subprocess.run(['cloud-localds',str(seed),str(data),str(meta)],check=True,timeout=30)
    profile = json.loads((VALIDATION/'profile.json').read_text())
    inputs = {'base.qcow2': profile['dependencies']['base'], 'fixture.iso': profile['dependencies']['media'],
              'runtime.iso': fixture['iso'], 'seed.iso':dict(path=str(seed),bytes=seed.stat().st_size,sha256=sha(seed))}
    for item in inputs.values():
        path = store/item['path']
        if file_record(path, item['bytes']) != {k:item[k] for k in ('bytes','sha256')}:
            raise ValueError('Proof input identity')
    text = template.read_text()
    # Unique exact-owned names preserve all historical controller state.
    text = text.replace('first-trial', 'debugger-proof-20261008').replace('first-trial.service','debugger-proof-20261008.service')
    text = text.replace('eqemuvmtrial', 'eqemuvmdebugger20261008').replace('eqemu-first-trial','eqemu-debugger-proof-20261008')
    text = assign(text, 'INPUTS', 'P('+repr(str(store))+')')
    text = assign(text, 'FILES', repr({name:(item['path'],item['bytes'],item['sha256']) for name,item in inputs.items()}))
    text = text.replace('{DATA}/fixture.iso rk,','{DATA}/fixture.iso rk,\n  {DATA}/runtime.iso rk,')
    disk = '<disk type="file" device="cdrom"><driver name="qemu" type="raw"/><source file="{DATA}/runtime.iso"/><target dev="sdc" bus="sata"/><readonly/></disk>'
    text = text.replace('    <serial type="unix">','    '+disk+'\n    <serial type="unix">')
    text = text.replace("for name in ['seed.iso','fixture.iso']", "for name in ['seed.iso','fixture.iso','runtime.iso']")
    old = "{'guest_root','no_virtual_nic','no_nested_virtualization','approved_input','no_host_mounts','no_host_control_socket','no_external_route','container_exchange','intentional_failure_distinct','containers_removed'}"
    new = "{'guest_root','no_virtual_nic','approved_inputs','runtime_install','matching_debug_packages','gdb_python','source_trace','no_private_values','bounded_controls','no_cores'}"
    if text.count(old) != 1: raise ValueError('Controller result seam changed')
    text = text.replace(old,new).replace('offline-container-trial','debugger-provisioning-trial')
    text = text.replace('deadline=time.monotonic()+900','deadline=time.monotonic()+1500')
    compile(text,'debugger-controller.py','exec')
    controller = output/'controller.py'; controller.write_text(text)
    receipt = dict(controller_sha256=sha(controller), seed_sha256=sha(seed),
                   verified_runtime=verified, vm_started=False)
    (output/'preparation.json').write_text(json.dumps(receipt,indent=2)+'\n')
    subprocess.run(['python3','-B',str(controller),'--check'],check=True,timeout=60)
    return receipt


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-store',type=Path,required=True)
    parser.add_argument('--controller-template',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(prepare(args.input_store,args.controller_template,args.output)))
