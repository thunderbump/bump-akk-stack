#!/usr/bin/python3
"""Prepare the fixed, synthetic producer/consumer proof. Starts no VM."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parent
ARCHIVE = SOURCE.parents[1] / 'runtime-proof' / '2026-09-26'
LOCAL = Path('/home/bump/.local/state/eqemu-vm-proof')
OUTPUT = LOCAL / 'artifact-handoff-inputs-01'
LAUNCHER = LOCAL / 'offline-artifact-handoff-01.py'
ROOT = Path('/var/lib/eqemu-vm-proof/artifact-handoff-01')
BASE_FILE = ('inputs/ubuntu-noble-20260911/ubuntu-24.04-server-cloudimg-amd64.img',
             625256960, '612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354')


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def replace_once(text, old, new):
    if text.count(old) != 1: raise ValueError('Pinned template does not match: ' + old[:100])
    return text.replace(old, new, 1)


def replace_function(text, name, replacement):
    start = text.index('def '+name+'(')
    end = text.find('\ndef ', start+1)
    if end < 0: end = text.index("\nif __name__", start)
    return text[:start] + replacement.rstrip() + '\n\n' + text[end:]


def prepare():
    if ROOT.exists(): raise RuntimeError('Refuse modifying a launched proof')
    if OUTPUT.exists() or LAUNCHER.exists(): raise RuntimeError('Preparation already exists; preserve or explicitly reconcile it')
    stage = Path(tempfile.mkdtemp(prefix='.handoff-preparation-', dir=LOCAL))
    try:
        payload = b'eqemu-artifact-handoff\n' * 2048
        payload_sha = hashlib.sha256(payload).hexdigest()
        manifest = {'version':1, 'identity':'synthetic-artifact-v1', 'files':[
            {'path':'payload.bin', 'type':'file', 'bytes':len(payload), 'sha256':payload_sha}]}
        manifest_sha = hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()
        worker_base = (ARCHIVE/'runtime-proof-inputs-03/build-worker.py').read_text()
        worker_hashes = {}
        for role,short in [('producer','prod'),('consumer','cons')]:
            guest = (SOURCE/'guest.py').read_text().replace('@ROLE@', role)
            user = {'package_update':False,'package_upgrade':False,'users':[], 'ssh_pwauth':False,
                    'disable_root':True,'growpart':{'mode':'auto','devices':['/'],'ignore_growroot_disabled':False},
                    'write_files':[
                        {'path':'/opt/handoff/guest.py','permissions':'0700','content':guest},
                        {'path':'/opt/handoff/artifact.py','permissions':'0600','content':(SOURCE/'artifact.py').read_text()},
                        {'path':'/opt/handoff/diagnostics.py','permissions':'0600','content':(SOURCE/'diagnostics.py').read_text()},
                        {'path':'/opt/handoff/GUEST_ONLY','permissions':'0600','content':'fixed synthetic artifact proof\n'},
                        {'path':'/etc/cloud/cloud.cfg.d/99-offline.cfg','content':'network: {config: disabled}\n'}],
                    'runcmd':[['systemctl','mask','--now','apt-daily.timer','apt-daily-upgrade.timer'],
                              ['python3','-I','/opt/handoff/guest.py']]}
            ud = stage/(role+'-user-data');md=stage/(role+'-meta-data');seed=stage/(role+'-seed.iso')
            ud.write_text('#cloud-config\n'+json.dumps(user,indent=2)+'\n')
            md.write_text('instance-id: eqemu-handoff-01-'+role+'\nlocal-hostname: eqemu-handoff\n')
            subprocess.run(['cloud-localds','--disk-format','raw',str(seed),str(ud),str(md)],check=True)
            worker = worker_base.replace('runtime-proof-03','artifact-handoff-01').replace('runtime-03','handoff-'+short+'01').replace('runtime03worker','handoff'+short+'01worker').replace('runtime03ctl','handoff01ctl')
            worker = replace_once(worker,"ROOT=BASE/'artifact-handoff-01'/'build'", "ROOT=BASE/'artifact-handoff-01'/"+repr(role))
            worker = replace_once(worker,"CASE='build'",'CASE='+repr(role))
            files = {'base.qcow2':BASE_FILE,'seed.iso':('artifact-handoff-inputs-01/'+seed.name,seed.stat().st_size,sha(seed))}
            worker = re.sub(r'FILES=\{.*?\n\}', 'FILES='+repr(files), worker, count=1, flags=re.S)
            worker = '\n'.join(line for line in worker.split('\n') if '{DATA}/fixture.iso' not in line and '{DATA}/runtime.iso' not in line)
            mode = 'rwk' if role=='producer' else 'rk'
            worker = replace_once(worker,'  {DATA}/serial.sock rw,','  {DATA}/artifact.raw '+mode+',\n  {DATA}/serial.sock rw,')
            readonly = '' if role=='producer' else '<readonly/>'
            disk = '    <disk type="file" device="disk"><driver name="qemu" type="raw" cache="none" discard="ignore"/><source file="{DATA}/artifact.raw"/><target dev="vdb" bus="virtio"/>'+readonly+'</disk>\n'
            worker = replace_once(worker,'    <serial type="unix">', disk+'    <serial type="unix">')
            worker = replace_once(worker,"        raw=DATA/'root.raw'", "        prepare_artifact()\n        raw=DATA/'root.raw'")
            effective = '''        disks=tree.findall('./devices/disk')
        if len(disks)!=3:raise RuntimeError('Unexpected disk count')
        artifact_disk=next((disk for disk in disks if disk.find('target').get('dev')=='vdb'),None)
        if artifact_disk is None or artifact_disk.find('source').get('file')!=str(DATA/'artifact.raw') or artifact_disk.find('driver').get('type')!='raw' or artifact_disk.find('driver').get('discard')!='ignore' or (artifact_disk.find('readonly') is not None)!=(CASE=='consumer'):
            raise RuntimeError('Artifact device policy mismatch')
'''
            worker = replace_once(worker,"        if virsh('domstate',s['uuid'])",effective+"        if virsh('domstate',s['uuid'])")
            worker = worker.replace("for name in ['seed.iso','fixture.iso','runtime.iso']", "for name in ['seed.iso']")
            worker = replace_once(worker,"        if DATA.exists():safe_dir(DATA);shutil.rmtree(DATA)","        artifact_before_data_removal(receipt)\n        if DATA.exists():safe_dir(DATA);shutil.rmtree(DATA)")
            worker = worker.replace('RuntimeMaxSec=17400','RuntimeMaxSec=900')
            # Retain the hardened JSON/serial decoder, remove the old game/build result policy.
            start=worker.index('class BuildProtocol:');end=worker.index('def main():',start)
            worker=worker[:start]+worker[end:]
            main=worker.index("if __name__=='__main__':")
            extension=(SOURCE/'worker_extension.py').read_text().replace('@MANIFEST@',manifest_sha).replace('@PAYLOAD@',payload_sha)
            worker=worker[:main]+(SOURCE/'artifact.py').read_text()+'\n'+extension+'\n'+worker[main:]
            compile(worker,role+'-worker.py','exec')
            target=stage/(role+'-worker.py');target.write_text(worker);worker_hashes[target.name]=sha(target)
        suite=(ARCHIVE/'offline-runtime-proof-03.py').read_text().replace('runtime-proof-03','artifact-handoff-01').replace('runtime-03','handoff-01').replace('runtime03','handoff01')
        suite=suite.replace('runtime-proof-inputs-03','artifact-handoff-inputs-01')
        suite=replace_once(suite,"CASES=('build',)","CASES=('producer','consumer')")
        suite=re.sub(r'HASHES=\{[^\n]+\}', 'HASHES='+repr(worker_hashes),suite,count=1)
        # The new proof has current input identities, not a historical receipt chain.
        suite=replace_function(suite,'prerequisites',"def prerequisites():\n    return None")
        start=suite.index("    prior=BASE/'build-proof-04/suite-result.json';")
        end=suite.index('    if ROOT.exists()',start)
        suite=suite[:start]+suite[end:]
        suite=suite.replace("module('build',local=True)","module('producer',local=True)")
        suite=suite.replace("module('build')", "module('producer')")
        old="    target=ROOT/'build-worker.py';target.write_bytes((LOCAL/'build-worker.py').read_bytes());target.chmod(0o600)\n    if digest(target)!=HASHES['build-worker.py']:raise RuntimeError('Worker changed during copy')"
        new="    for case in CASES:\n        target=ROOT/(case+'-worker.py');target.write_bytes((LOCAL/target.name).read_bytes());target.chmod(0o600)\n        if digest(target)!=HASHES[target.name]:raise RuntimeError('Worker changed during copy')"
        suite=replace_once(suite,old,new)
        old="        prerequisites();module('producer',local=True);run(['/usr/bin/python3','-I',str(LOCAL/'build-worker.py'),'--check'],timeout=90)"
        new="        for case in CASES:\n            module(case,local=True);run(['/usr/bin/python3','-I',str(LOCAL/(case+'-worker.py')),'--check'],timeout=90)"
        suite=replace_once(suite,old,new)
        suite=suite.replace('RuntimeMaxSec=18000','RuntimeMaxSec=2400')
        suite=suite.replace("str(ROOT/'build/evidence/report.json')","str(ROOT/'suite-result.json')")
        # Remove superseded case functions, then supply the small two-case sequence.
        for name in ['admit','supervise','cleanup']:
            suite=replace_function(suite,name,'')
        main=suite.index("if __name__=='__main__':")
        suite=suite[:main]+(SOURCE/'suite_extension.py').read_text()+'\n'+suite[main:]
        suite=suite.replace('Fixed offline EQEmu build and runtime proof.','Fixed synthetic artifact handoff proof; no EQEmu build or server.')
        compile(suite,'launcher.py','exec')
        (stage/'launcher.py').write_text(suite)
        (stage/'preparation.json').write_text(json.dumps({'scope':'synthetic artifact handoff, unexecuted',
            'worker_files':worker_hashes,'launcher_sha256':sha(stage/'launcher.py'),
            'sources':{p.name:sha(p) for p in SOURCE.glob('*.py')},'artifact_bytes':4*1024**3},indent=2)+'\n')
        stage.rename(OUTPUT)
        LAUNCHER.write_text(suite)
        print(json.dumps({'prepared':str(OUTPUT),'launcher':str(LAUNCHER),'vm_started':False}))
    finally:
        if stage.exists():shutil.rmtree(stage)


if __name__=='__main__':prepare()
