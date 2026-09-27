#!/usr/bin/python3
"""Prepare a fixed real-build producer and fresh consumer. Starts no VM."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parent
REPO = SOURCE.parents[2]
ARTIFACT = REPO/'investigations/artifact-handoff/2026-09-26'
CORRECTED = REPO/'investigations/corrected-build/2026-09-26'
LOCAL = Path('/home/bump/.local/state/eqemu-vm-proof')
PREVIOUS = LOCAL/'corrected-build-inputs-01'
OUTPUT = LOCAL/'build-handoff-inputs-01'
LAUNCHER = LOCAL/'offline-build-handoff-01.py'
ROOT = Path('/var/lib/eqemu-vm-proof/build-handoff-01')
spec = importlib.util.spec_from_file_location('handoff_prepare', ARTIFACT/'prepare.py')
helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
replace_once = helper.replace_once
replace_function = helper.replace_function


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare():
    if any(p.exists() or p.is_symlink() for p in [OUTPUT, LAUNCHER, ROOT]):
        raise RuntimeError('Preserve existing preparation/attempt')
    previous = json.loads((CORRECTED/'receipts/preparation.json').read_text())
    for name, key in [('build-worker.py','worker_sha256'),('seed.iso','seed_sha256')]:
        if sha(PREVIOUS/name) != previous[key]: raise RuntimeError('Corrected template changed')
    # Read our own pinned cloud-init seed as data; never mount a guest filesystem.
    data = subprocess.run(['isoinfo','-i',str(PREVIOUS/'seed.iso'),'-x','/USER_DAT.;1'],
                          check=True,capture_output=True).stdout.decode()
    user_template = json.loads(data.split('\n',1)[1])
    guest_base = next(f['content'] for f in user_template['write_files'] if f['path'].endswith('/guest_build.py'))
    prior02 = json.loads((ARTIFACT/'preparation-02.json').read_text())
    suite_path = LOCAL/'artifact-handoff-inputs-02/launcher.py'
    if sha(suite_path) != prior02['launcher_sha256']: raise RuntimeError('Handoff suite changed')
    identity_inputs = {'corrected_recipe':previous['experiment_sha256'],
        'candidate':previous['candidate'], 'format':1,
        'base_sha256':helper.BASE_FILE[2],
        'media_sha256':'02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4'}
    build_id = hashlib.sha256(json.dumps(identity_inputs,sort_keys=True).encode()).hexdigest()
    source_files = [*SOURCE.glob('*.py'), ARTIFACT/'artifact.py', ARTIFACT/'worker_extension.py', ARTIFACT/'suite_extension.py']
    sources = {str(p.relative_to(REPO)):sha(p) for p in sorted(source_files)}
    recipe = hashlib.sha256(json.dumps({'sources':sources,'build_id':build_id},sort_keys=True).encode()).hexdigest()
    stage = Path(tempfile.mkdtemp(prefix='.build-handoff-',dir=LOCAL))
    try:
        hashes = {}
        for role,short in [('producer','prod'),('consumer','cons')]:
            guest = guest_base.replace(previous['experiment_sha256'], recipe)
            ext = '\n'.join(p.read_text() for p in [ARTIFACT/'artifact.py',SOURCE/'payload.py',SOURCE/'guest_handoff.py'])
            ext = ext.replace('@ROLE@',role).replace('@BUILD_ID@',build_id)
            guest = replace_once(guest,"if __name__=='__main__':main()",ext+"\nif __name__=='__main__':main()")
            if role == 'consumer':
                guest = replace_once(guest,' global FD,NONCE,DEADLINE,EMIT',' global FD,NONCE,DEADLINE,EMIT,EXPECTED_ARTIFACT')
                guest = replace_once(guest,"set(c)!={'op','nonce'}", "set(c)!={'op','nonce','artifact_manifest_sha256'}")
                guest = replace_once(guest,'  NONCE=c[\'nonce\'];DEADLINE=',"  EXPECTED_ARTIFACT=c['artifact_manifest_sha256']\n  if not isinstance(EXPECTED_ARTIFACT,str) or not re.fullmatch('[a-f0-9]{64}',EXPECTED_ARTIFACT):raise RuntimeError('Artifact identity command')\n  NONCE=c['nonce'];DEADLINE=")
            user = json.loads(json.dumps(user_template))
            for entry in user['write_files']:
                if entry['path'].endswith('/guest_build.py'): entry['content'] = guest
            if role == 'consumer': user['write_files'] = [f for f in user['write_files'] if not f['path'].endswith('/candidate.json')]
            (stage/(role+'-guest.py')).write_text(guest)
            ud=stage/(role+'-user-data');md=stage/(role+'-meta-data');seed=stage/(role+'-seed.iso')
            ud.write_text('#cloud-config\n'+json.dumps(user,indent=2)+'\n')
            md.write_text('instance-id: eqemu-build-handoff-01-'+role+'\nlocal-hostname: eqemu-handoff\n')
            subprocess.run(['cloud-localds',str(seed),str(ud),str(md)],check=True)
            worker = (PREVIOUS/'build-worker.py').read_text().replace(previous['experiment_sha256'],recipe)
            worker = worker.replace('corrected-build-01','build-handoff-01').replace('correctedbuild01worker','buildhandoff'+short+'01worker').replace('correctedbuild01ctl','buildhandoff01ctl')
            worker = replace_once(worker,"NAME='eqemu-cbuild-01'", "NAME='eqemu-bh-"+short+"01'")
            worker = replace_once(worker,"UNIT='eqemu-vm-build-handoff-01-worker.service'", "UNIT='eqemu-vm-bh-"+short+"01-worker.service'")
            worker = replace_once(worker,"ROOT=BASE/'build-handoff-01'/'build'", "ROOT=BASE/'build-handoff-01'/"+repr(role))
            worker = replace_once(worker,"CASE='build'", 'CASE='+repr(role))
            worker = re.sub(r"'seed.iso':\([^\n]+", "'seed.iso':"+repr(('build-handoff-inputs-01/'+seed.name,seed.stat().st_size,sha(seed)))+',',worker,count=1)
            worker = replace_once(worker,'  {DATA}/serial.sock rw,','  {DATA}/artifact.raw '+('rwk' if role=='producer' else 'rk')+',\n  {DATA}/serial.sock rw,')
            readonly = '' if role=='producer' else '<readonly/>'
            disk='    <disk type="file" device="disk"><driver name="qemu" type="raw" cache="none" discard="ignore"/><source file="{DATA}/artifact.raw"/><target dev="vdb" bus="virtio"/>'+readonly+'</disk>\n'
            worker = replace_once(worker,'    <serial type="unix">',disk+'    <serial type="unix">')
            worker = replace_once(worker,"        raw=DATA/'root.raw'", "        prepare_artifact()\n        info=(DATA/'artifact.raw').stat()\n        if info.st_size!=4*GIB or info.st_blocks*512<4*GIB:raise RuntimeError('Artifact allocation incomplete')\n        raw=DATA/'root.raw'")
            effective='''        disks=tree.findall('./devices/disk')
        artifact_disk=next((d for d in disks if d.find('target').get('dev')=='vdb'),None)
        if len(disks)!=4 or artifact_disk is None or artifact_disk.find('source').get('file')!=str(DATA/'artifact.raw') or artifact_disk.find('driver').get('type')!='raw' or artifact_disk.find('driver').get('discard')!='ignore' or (artifact_disk.find('readonly') is not None)!=(CASE=='consumer'):
            raise RuntimeError('Artifact device policy mismatch')
'''
            worker = replace_once(worker,"        if virsh('domstate',s['uuid'])",effective+"        if virsh('domstate',s['uuid'])")
            worker = replace_once(worker,"        if DATA.exists():safe_dir(DATA);shutil.rmtree(DATA)","        artifact_before_data_removal(receipt)\n        if DATA.exists():safe_dir(DATA);shutil.rmtree(DATA)")
            custody = (ARTIFACT/'worker_extension.py').read_text().split('\ndef collect_build(',1)[0]
            custody = '\n'.join(line for line in custody.split('\n') if not line.startswith('EXPECTED_'))
            custody = custody.replace('EXPECTED_MANIFEST','expected_manifest()').replace("'scope': 'synthetic proof only'", "'scope': 'identified build handoff', 'identity': BUILD_ID")
            custody = replace_once(custody,"    safe_dir(STORE)\n    return value", "    if value.get('identity')!=BUILD_ID or value.get('discarded') or value.get('expires_at',time.time()+1)<=time.time():raise RuntimeError('Wrong, discarded or expired build')\n    safe_dir(STORE)\n    return value")
            extension = (ARTIFACT/'artifact.py').read_text()+'\n'+custody+'\n'+(SOURCE/'host_handoff.py').read_text().replace('@BUILD_ID@',build_id)
            worker = replace_once(worker,"if __name__=='__main__':",extension+"\nif __name__=='__main__':")
            if role == 'consumer':
                worker = worker.replace('RuntimeMaxSec=17400','RuntimeMaxSec=2700')
                worker = replace_once(worker,"json.dumps({'op':'build','nonce':nonce})", "json.dumps({'op':'build','nonce':nonce,'artifact_manifest_sha256':custody()['manifest_sha256']})")
            target = stage/(role+'-worker.py');target.write_text(worker);hashes[target.name]=sha(target)
            compile(guest,role+'-guest.py','exec');compile(worker,role+'-worker.py','exec')
            name=re.search(r"^NAME='([^']+)'$",worker,re.M)[1]
            if not re.fullmatch('[a-z0-9-]{1,20}',name):raise RuntimeError('Invalid generated domain name')
        suite = suite_path.read_text().split('# Replaces only suite case sequencing',1)[0]
        suite = suite.replace('artifact-handoff-02','build-handoff-01').replace('artifact-handoff-inputs-02','build-handoff-inputs-01').replace('handoff-02','build-handoff-01').replace('handoff02ctl','buildhandoff01ctl')
        suite = suite.replace('Fixed synthetic artifact handoff proof; no EQEmu build or server.','Fixed build export and fresh consumer proof.')
        suite = re.sub(r'HASHES=\{[^\n]+\}', 'HASHES='+repr(hashes),suite,count=1)
        suite = suite.replace('RuntimeMaxSec=2400','RuntimeMaxSec=18000')
        identities=json.loads((CORRECTED/'receipts/attempt-01/identities.json').read_text())
        prerequisite='''def prerequisites():
    prior=BASE/'corrected-build-01'
    for name,expected in PRIOR_HASHES.items():
        read(prior/name)
        if digest(prior/name)!=expected:raise RuntimeError('Successful corrected build evidence changed')
    if read(prior/'suite-result.json').get('suite_passed') is not True or read(prior/'leases.json')['active']:
        raise RuntimeError('Corrected build success and cleanup required')
'''
        suite = replace_function(suite,'prerequisites',prerequisite)
        common = (ARTIFACT/'suite_extension.py').read_text()
        common = replace_once(common,'        for case in CASES:\n            m = admit(case)', '        deadline = time.monotonic() + 17700\n        for case in CASES:\n            m = admit(case)')
        common = replace_once(common,'            deadline = time.monotonic() + 1200\n','')
        start=common.index("        store = ROOT / 'retained'");end=common.index('        try:\n            receipt[\'controller_budget\']',start)
        common=common[:start]+common[end:]
        common=replace_once(common,"        receipt['controller_slice_file_absent'] = not CTLFILE.exists()", "        receipt['controller_slice_file_absent'] = not CTLFILE.exists()\n        retain_or_discard(receipt)")
        suite=suite.replace("['check','supervise','cleanup']", "['check','supervise','cleanup','discard-artifact']")
        suite=replace_once(suite,"    if a.supervise or a.cleanup:", "    if a.discard_artifact:\n        if P(__file__).resolve()!=SCRIPT:raise RuntimeError('Use the root-owned suite.py for discard')\n        return discard_artifact()\n    if a.supervise or a.cleanup:")
        suite+='\nPRIOR_HASHES='+repr(identities)+'\n'+common+'\n'+(SOURCE/'retention.py').read_text()+"\nif __name__=='__main__':sys.exit(main())\n"
        compile(suite,'launcher.py','exec');(stage/'launcher.py').write_text(suite)
        (stage/'preparation.json').write_text(json.dumps({'scope':'real build export and fresh consumer; unexecuted',
            'build_id':build_id,'identity_inputs':identity_inputs,'recipe_sha256':recipe,'worker_files':hashes,
            'launcher_sha256':sha(stage/'launcher.py'),'sources':sources,
            'retention_bytes':4*1024**3,'retention_days':7,'retention_cleanup':'explicit discard; no scheduled collector'},indent=2)+'\n')
        stage.rename(OUTPUT);LAUNCHER.write_text(suite)
        print(json.dumps({'prepared':str(OUTPUT),'launcher':str(LAUNCHER),'vm_started':False}))
    finally:
        if stage.exists():shutil.rmtree(stage)


if __name__=='__main__':prepare()
