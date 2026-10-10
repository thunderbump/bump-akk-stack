#!/usr/bin/python3
"""Render one fixed offline LLVM proof using the qualified isolation controller."""
import argparse
import hashlib
import json
import shlex
from pathlib import Path
import subprocess
import sys

VALIDATION=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(VALIDATION))
from common import load
shared=load('llvm_proof_controller_adapter',VALIDATION/'debugger/prepare_proof.py')
assign=shared.assign
CONTROLLER_SHA=shared.CONTROLLER_SHA
from inputs import file_record


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def prepare(store,template,output):
    store=store.resolve(strict=True);template=template.resolve(strict=True);output=output.resolve()
    if sha(template)!=CONTROLLER_SHA:raise ValueError('Pinned isolation controller changed')
    if output.exists():raise ValueError('Use a new proof directory')
    profile=json.loads((VALIDATION/'profile.json').read_text());output.mkdir(mode=0o700)
    sources={'guest_build.py':VALIDATION/'recipes/producer-guest.py',
             'proof_guest.py':Path(__file__).with_name('proof_guest.py')}
    for name in ('native_diagnostics.py','actor.py','common.py','profile.json'):
        sources['validation/'+name]=VALIDATION/name
    sources['tests/validation/test_native_diagnostics.py']=VALIDATION.parent/'tests/validation/test_native_diagnostics.py'
    files={'/opt/eqemu-proof/'+name:path.read_text() for name,path in sources.items()}
    files['/opt/eqemu-proof/BUILD_GUEST_ONLY']='llvm-provisioning-proof\n'
    user=dict(package_update=False,package_upgrade=False,users=[],ssh_pwauth=False,disable_root=True,
        growpart=dict(mode='auto',devices=['/'],ignore_growroot_disabled=False),
        write_files=[dict(path=name,permissions='0600',content=text) for name,text in files.items()],
        runcmd=[['systemctl','mask','--now','apt-daily.timer','apt-daily-upgrade.timer'],
                ['python3','-B','/opt/eqemu-proof/proof_guest.py']])
    data=output/'user-data';data.write_text('#cloud-config\n'+json.dumps(user)+'\n')
    meta=output/'meta-data';meta.write_text('instance-id: eqemu-llvm-proof-20261009\n')
    seed=output/'seed.iso';subprocess.run(['cloud-localds',str(seed),str(data),str(meta)],check=True,timeout=30)
    inputs={'base.qcow2':profile['dependencies']['base'],'fixture.iso':profile['dependencies']['media'],
            'seed.iso':dict(path=str(seed),bytes=seed.stat().st_size,sha256=sha(seed))}
    for item in inputs.values():
        if file_record(store/item['path'],item['bytes'])!={k:item[k] for k in ('bytes','sha256')}:
            raise ValueError('Proof input identity')
    text=template.read_text().replace('first-trial','llvm-proof-20261009').replace('eqemuvmtrial','eqemuvmllvm20261009')
    text=assign(text,'NAME',repr('eqemu-llvm-1009'))
    text=assign(text,'INPUTS','P('+repr(str(store))+')')
    text=assign(text,'FILES',repr({n:(v['path'],v['bytes'],v['sha256']) for n,v in inputs.items()}))
    old="{'guest_root','no_virtual_nic','no_nested_virtualization','approved_input','no_host_mounts','no_host_control_socket','no_external_route','container_exchange','intentional_failure_distinct','containers_removed'}"
    new="{'guest_root','no_virtual_nic','approved_inputs','offline_install','pinned_llvm','gcc_zlib','safe_control','unsafe_control','incomplete_context','no_game_build'}"
    if text.count(old)!=1:raise ValueError('Controller result seam changed')
    text=text.replace(old,new).replace('offline-container-trial','llvm-provisioning-trial')
    text=text.replace('deadline=time.monotonic()+900','deadline=time.monotonic()+1500')
    compile(text,'llvm-controller.py','exec')
    controller=output/'controller.py';controller.write_text(text)
    receipt=dict(controller_sha256=sha(controller),seed_sha256=sha(seed),
        build_media=profile['dependencies']['media'],vm_started=False)
    (output/'preparation.json').write_text(json.dumps(receipt,indent=2)+'\n')
    subprocess.run(['python3','-B',str(controller),'--check'],check=True,timeout=60)
    # Compile only the reviewed bytes, then run from a private root-owned copy.
    # The controller itself later copies __file__ for systemd's internal modes.
    code="import os,stat,hashlib,tempfile,pathlib,sys; p="+repr(str(controller))+"; fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); f=os.fdopen(fd,'rb'); s=os.fstat(f.fileno()); assert stat.S_ISREG(s.st_mode) and s.st_size<=256*1024,'invalid controller'; data=f.read(256*1024+1); f.close(); assert hashlib.sha256(data).hexdigest()=="+repr(receipt['controller_sha256'])+",'reviewed controller changed'\n"
    code+="with tempfile.TemporaryDirectory(prefix='.llvm-reviewed-',dir='/var/lib/eqemu-vm-proof') as d:\n q=pathlib.Path(d)/'controller.py';q.write_bytes(data);q.chmod(0o400);sys.argv=[str(q)];exec(compile(data,str(q),'exec'),{'__file__':str(q),'__name__':'__main__'})\n"
    wrapper=output/'run-reviewed-proof.sh'
    wrapper.write_text('#!/bin/sh\nset -eu\n[ "$#" -eq 0 ] || exit 2\nexec /usr/bin/sudo /usr/bin/python3 -I -c '+shlex.quote(code)+'\n')
    wrapper.chmod(0o700)
    return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-store',type=Path,required=True)
    parser.add_argument('--controller-template',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(prepare(args.input_store,args.controller_template,args.output)))
