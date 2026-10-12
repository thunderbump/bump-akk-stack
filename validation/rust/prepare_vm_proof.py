#!/usr/bin/python3
"""Render one finite no-NIC Rust provisioning VM and operator wrapper. Never launches work."""
import argparse
import json
from pathlib import Path
import shutil
import shlex
import subprocess
import sys

VALIDATION=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(VALIDATION))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common
import inputs
import prepare_proof
import proof
import rust

debugger=common.load('rust_controller_seams',VALIDATION/'debugger/prepare_proof.py')
CONTROLLER_SHA=debugger.CONTROLLER_SHA
REQUIRED={'guest_root','no_virtual_nic','no_host_mounts','approved_inputs','native_packages',
          'rust_stages','native_call','candidate_controls','compiler_unavailable_replay','source_unchanged'}


def replace(text,old,new):
    if text.count(old)!=1:raise ValueError('Pinned VM proof seam changed')
    return text.replace(old,new,1)


def controller(text,files,store):
    text=text.replace('first-trial','rust-proof-20261011').replace('eqemuvmtrial','eqemuvmrust20261011')
    text=debugger.assign(text,'NAME',repr('eqemu-rust-1011'))
    text=debugger.assign(text,'INPUTS','P('+repr(str(store))+')')
    text=debugger.assign(text,'FILES',repr(files))
    text=text.replace('first synthetic offline VM trial; not full isolation acceptance',
                      'offline Rust provisioning/CXX VM proof; no EQEmu build or gameplay acceptance')
    text=replace(text,'{DATA}/fixture.iso rk,','{DATA}/fixture.iso rk,\n  {DATA}/rust.iso rk,')
    disk='<disk type="file" device="cdrom"><driver name="qemu" type="raw"/><source file="{DATA}/rust.iso"/><target dev="sdc" bus="sata"/><readonly/></disk>'
    text=replace(text,'    <serial type="unix">','    '+disk+'\n    <serial type="unix">')
    text=replace(text,"for name in ['seed.iso','fixture.iso']","for name in ['seed.iso','fixture.iso','rust.iso']")
    old="{'guest_root','no_virtual_nic','no_nested_virtualization','approved_input','no_host_mounts','no_host_control_socket','no_external_route','container_exchange','intentional_failure_distinct','containers_removed'}"
    text=replace(text,old,repr(REQUIRED)).replace('offline-container-trial','rust-provisioning-trial')
    text=replace(text,'deadline=time.monotonic()+900','deadline=time.monotonic()+2400')
    text=replace(text,"'RuntimeMaxSec=1800'","'RuntimeMaxSec=3000'")
    control_codes={name:2 if name in ('tool-drift','vendor-drift','config-drift','ancestor-config') else 1 for name in proof.CONTROLS}
    control_codes['positive']=0
    text=replace(text,"report['checks']['guest_synthetic_workload']=True", "controls=guest.get('controls',{})\n        expected_controls="+repr(control_codes)+"\n        if set(controls)!=set(expected_controls) or any(type(v.get('exit_code')) is not int or v['exit_code']!=expected_controls[name] or v.get('source_unchanged') is not True for name,v in controls.items()):raise RuntimeError('Rust VM control evidence missing')\n        for name in ('bundle_sha256','fixture_sha256','native_binary_sha256'):\n            if not isinstance(guest.get(name),str) or not re.fullmatch('[a-f0-9]{64}',guest[name]):raise RuntimeError('Rust VM output identity missing')\n        report['checks']['rust_provisioning_workload']=True")
    compile(text,'rust-vm-controller.py','exec')
    return text


def prepare(store,bundle,template,output):
    store=store.resolve(strict=True);bundle=bundle.resolve(strict=True);template=template.resolve(strict=True);output=output.resolve()
    if common.sha(template)!=CONTROLLER_SHA:raise ValueError('Pinned isolation controller changed')
    if output.exists() or output.is_relative_to(store) or output.is_relative_to(bundle.parent) or output.is_relative_to(VALIDATION):
        raise ValueError('Use a new VM proof output outside inputs/source')
    profile=json.loads((VALIDATION/'profile.json').read_text())
    fixed={name:profile['dependencies'][key] for name,key in [('base.qcow2','base'),('fixture.iso','media')]}
    for item in fixed.values():
        if inputs.file_record(store/item['path'],item['bytes'])!={key:item[key] for key in ('bytes','sha256')}:
            raise ValueError('VM native input identity mismatch')
    output.mkdir(mode=0o700)
    try:
        receipt=prepare_proof.prepare(VALIDATION/'rust/fixture',bundle,output/'inputs')
        media=output/'rust.iso'
        subprocess.run(['/usr/bin/genisoimage','-quiet','-R','-J','-V','EQEMURUST','-o',str(media),str(output/'inputs')],check=True,timeout=120)
        helpers={name:(VALIDATION/name).read_text() for name in ('common.py','rust.py','rust_guest.py','rust-toolchain.json',
                    'recipes/producer-guest.py','rust/proof.py','rust/vm_guest.py')}
        fixture=proof.authority(VALIDATION/'rust/fixture')
        for item in fixture['entries']:
            helpers['fixture/'+item['path']]=(VALIDATION/'rust/fixture'/item['path']).read_text()
        helpers['BUILD_GUEST_ONLY']='rust-provisioning-vm-proof\n'
        declaration=dict(bundle_sha256=receipt['contract']['bundle']['sha256'],fixture=fixture,
                         fixture_sha256=rust.digest(fixture))
        helpers['vm-inputs.json']=json.dumps(declaration)
        user=dict(package_update=False,package_upgrade=False,users=[],ssh_pwauth=False,disable_root=True,
                  growpart=dict(mode='auto',devices=['/'],ignore_growroot_disabled=False),
                  write_files=[dict(path='/opt/eqemu-proof/'+name,permissions='0600',content=text) for name,text in helpers.items()],
                  runcmd=[['systemctl','mask','--now','apt-daily.timer','apt-daily-upgrade.timer'],
                          ['python3','-B','/opt/eqemu-proof/rust/vm_guest.py']])
        (output/'user-data').write_text('#cloud-config\n'+json.dumps(user)+'\n')
        (output/'meta-data').write_text('instance-id: eqemu-rust-proof-20261011\n')
        seed=output/'seed.iso'
        subprocess.run(['/usr/bin/cloud-localds',str(seed),str(output/'user-data'),str(output/'meta-data')],check=True,timeout=30)
        files={name:(item['path'],item['bytes'],item['sha256']) for name,item in fixed.items()}
        files.update({name:(str(path),path.stat().st_size,common.sha(path)) for name,path in [('seed.iso',seed),('rust.iso',media)]})
        script=output/'controller.py';script.write_text(controller(template.read_text(),files,store))
        wrapper=output/'reviewed-run.sh'
        checks=''.join('printf \"%s  %s\\\\n\" \"'+common.sha(path)+'\" \"'+path.name+'\" | sha256sum -c -\n' for path in (script,seed,media))
        wrapper.write_text('#!/bin/sh\nset -eu\n'+
            'cd '+shlex.quote(str(output))+'\n'+checks+
            'exec sudo /usr/bin/python3 -I '+shlex.quote(str(script))+'\n')
        wrapper.chmod(0o700)
        result=dict(receipt,controller_sha256=common.sha(script),wrapper_sha256=common.sha(wrapper),
                    seed_sha256=common.sha(seed),rust_iso_sha256=common.sha(media),
                    controller_template_sha256=CONTROLLER_SHA,files=files,vm_started=False,installed=False)
        (output/'preparation.json').write_text(json.dumps(result,indent=2)+'\n')
        subprocess.run(['/usr/bin/python3','-I',str(script),'--check'],check=True,timeout=120)
        return result
    except BaseException:
        shutil.rmtree(output)
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('input-store','bundle','controller-template','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(prepare(args.input_store,args.bundle,args.controller_template,args.output),indent=2))
