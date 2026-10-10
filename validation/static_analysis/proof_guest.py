"""Fresh offline LLVM provisioning and enforcement proof; no EQEmu build/game."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path('/opt/eqemu-proof')


def proof():
    if os.geteuid()!=0 or not (ROOT/'BUILD_GUEST_ONLY').is_file():raise RuntimeError('Proof is guest-only')
    if sorted(p.name for p in Path('/sys/class/net').iterdir())!=['lo']:raise RuntimeError('Unexpected guest NIC')
    spec=importlib.util.spec_from_file_location('build',ROOT/'guest_build.py')
    build=importlib.util.module_from_spec(spec);spec.loader.exec_module(build)
    build.DEADLINE=time.monotonic()+1200;build.EMIT=lambda _:None;build.emit=lambda _:None
    build.WORK.mkdir();build.LOGS.mkdir();build.MEDIA.mkdir()
    build.command('mount-build',['mount','-o','ro,nosuid,nodev,noexec','/dev/disk/by-label/EQEMUBUILD',str(build.MEDIA)])
    build.verify_inputs();build.apt_preflight();zlib=build.system_zlib_probe()
    versions={}
    for name in ('clang-18','clang-tidy-18','clang-format-18'):
        text=build.command('llvm-version-'+name,['/usr/bin/'+name,'--version'],timeout=10,cap=8192).read_text()
        if '18.1.3' not in text:raise RuntimeError('LLVM version mismatch: '+name)
        versions[name]=text[:600]
    result=subprocess.run(['/usr/bin/python3','-B',str(ROOT/'tests/validation/test_native_diagnostics.py')],
        capture_output=True,text=True,timeout=60,env=build.ENV)
    if result.returncode!=0 or 'Ran 5 tests' not in result.stderr or 'skipped' in result.stderr:
        raise RuntimeError('Native diagnostic controls failed: '+result.stderr[-3000:])
    build.verify_inputs()
    return dict(schema=1,kind='llvm-provisioning-trial',ok=True,
        checks={name:True for name in ('guest_root','no_virtual_nic','approved_inputs','offline_install',
            'pinned_llvm','gcc_zlib','safe_control','unsafe_control','incomplete_context','no_game_build')},
        versions=versions,zlib=zlib,controls=result.stderr[-2000:])


if __name__=='__main__':
    try:value=proof()
    except Exception as error:value=dict(schema=1,kind='llvm-provisioning-trial',ok=False,error=str(error)[-3000:])
    data=('\nEQEMU_TRIAL_RESULT '+json.dumps(value)+'\n').encode()
    if len(data)>16384:raise RuntimeError('Proof result output budget')
    with open('/dev/ttyS0','wb',buffering=0) as serial:serial.write(data)
    subprocess.run(['systemctl','poweroff'],check=False,timeout=20)
