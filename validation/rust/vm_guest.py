"""Finite offline tool/CXX VM proof; no EQEmu build, world or installed activation."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path('/opt/eqemu-proof')
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(ROOT/'rust'))
import common
import proof


def control_finding(control,result):
    """A deliberate control must fail for its selected reason, not any nonzero exit."""
    if control is None:return result.get('native_call') is True
    error=result.get('error','');finding=result.get('observations',{}).get('rust-failure',{})
    if control in ('tool-drift','vendor-drift','config-drift','ancestor-config'):
        return 'Protected Rust tool/vendor/config input drift' in error
    if control=='link':return error.startswith('proof-native-link: exit 1\n') and 'undefined reference' in error
    wanted={'format':('rust-fmt','format'),'lint':('rust-clippy','lint'),
            'test':('rust-tests','test'),'doctest':('rust-doctests','test'),
            'unsafe':('rust-clippy','compile'),'syntax':('rust-fmt','compile'),
            'missing-marker':('rust-native-link','link')}
    if (finding.get('stage'),finding.get('finding'))!=wanted[control]:return False
    return control!='missing-marker' or finding.get('tool_exit_code')==0


def run():
    if os.geteuid()!=0 or not (ROOT/'BUILD_GUEST_ONLY').is_file():
        raise RuntimeError('Guest-only Rust VM proof')
    if sorted(p.name for p in Path('/sys/class/net').iterdir())!=['lo']:
        raise RuntimeError('Unexpected VM network interface')
    if any(item in Path('/proc/mounts').read_text() for item in (' virtiofs ',' 9p ',' nfs ',' nfs4 ')):
        raise RuntimeError('Unexpected host share')
    native=common.load('rust_vm_native',ROOT/'recipes/producer-guest.py')
    native.DEADLINE=time.monotonic()+2200
    native.EMIT=lambda _:None; native.emit=lambda _:None
    native.WORK.mkdir();native.LOGS.mkdir();native.MEDIA.mkdir()
    native.command('mount-native',['mount','-o','ro,nosuid,nodev,noexec',
                   '/dev/disk/by-label/EQEMUBUILD',str(native.MEDIA)],timeout=30)
    native.verify_inputs();native.apt_preflight()
    media=Path('/opt/rust-media');media.mkdir()
    native.command('mount-rust',['mount','-o','ro,nosuid,nodev,noexec',
                   '/dev/disk/by-label/EQEMURUST',str(media)],timeout=30)
    declaration=json.loads((ROOT/'vm-inputs.json').read_text())
    bundle=media/'rust-inputs.tar'
    if common.sha(bundle)!=declaration['bundle_sha256']:
        raise RuntimeError('VM Rust input mismatch')
    source=ROOT/'fixture'
    if proof.authority(source)!=declaration['fixture']:
        raise RuntimeError('VM fixture identity mismatch')
    results={}
    parent=Path('/opt/rust-proof');parent.mkdir()
    for control in (None,*proof.CONTROLS):
        name=control or 'positive'
        if time.monotonic()>=native.DEADLINE:raise TimeoutError('Rust VM proof global deadline')
        result=proof.run(source,bundle,parent/name,control,deadline=native.DEADLINE)
        wanted=0 if control is None else 2 if control in ('tool-drift','vendor-drift','config-drift','ancestor-config') else 1
        if (result['exit_code']!=wanted or result['accepted']!=(control is None)
                or result['source_unchanged'] is not True or not control_finding(control,result)):
            raise RuntimeError('VM Rust control '+name+': '+json.dumps(result)[-2200:])
        results[name]=dict(exit_code=wanted,source_unchanged=True,
                          elapsed_seconds=result['elapsed_seconds'],
                          failure=result['observations'].get('rust-failure'),
                          error=result.get('error','')[-300:])
        # Keep at most one component/tool/cache copy live across the finite corpus.
        shutil.rmtree(parent/name/'rust')
    positive=parent/'positive'
    binary=positive/'proof-native';identity=common.sha(binary)
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}
    if shutil.which('rustc',path=env['PATH']) or shutil.which('cargo',path=env['PATH']):
        raise RuntimeError('Unexpected system Rust compiler in VM replay')
    replay=subprocess.run([str(binary)],env=env,capture_output=True,text=True,timeout=10)
    if replay.returncode or replay.stdout!='EQEMU_RUST_BRIDGE_RESULT 42\n' or common.sha(binary)!=identity:
        raise RuntimeError('Native runtime replay failed without Rust tools')
    if common.sha(bundle)!=declaration['bundle_sha256'] or proof.authority(source)!=declaration['fixture']:
        raise RuntimeError('VM proof input drift')
    return dict(schema=1,kind='rust-provisioning-trial',ok=True,
        checks={name:True for name in ('guest_root','no_virtual_nic','no_host_mounts','approved_inputs',
                'native_packages','rust_stages','native_call','candidate_controls','compiler_unavailable_replay','source_unchanged')},
        controls=results,bundle_sha256=declaration['bundle_sha256'],fixture_sha256=declaration['fixture_sha256'],
        native_binary_sha256=identity,
        rust_observations=json.loads((positive/'result.json').read_text())['observations'])


if __name__=='__main__':
    try:
        result=run()
    except Exception as error:
        result=dict(schema=1,kind='rust-provisioning-trial',ok=False,error=str(error)[-3000:])
    data=('\nEQEMU_TRIAL_RESULT '+json.dumps(result)+'\n').encode()
    if len(data)>16384:
        data=b'\nEQEMU_TRIAL_RESULT {"schema":1,"kind":"rust-provisioning-trial","ok":false,"error":"proof evidence overflow"}\n'
    with open('/dev/ttyS0','wb',buffering=0) as serial:serial.write(data)
    subprocess.run(['systemctl','poweroff'],check=False,timeout=20)
