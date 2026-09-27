#!/usr/bin/python3
"""Prepare one diagnostic-only service scenario against the retained build; no VM launch."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

SOURCE=Path(__file__).resolve().parent;REPO=SOURCE.parents[2]
LOCAL=Path('/home/bump/.local/state/eqemu-vm-proof')
PREVIOUS=LOCAL/'build-handoff-inputs-01';OUTPUT=LOCAL/'runtime-reuse-inputs-01'
LAUNCHER=LOCAL/'offline-runtime-reuse-01.py';ROOT=Path('/var/lib/eqemu-vm-proof/runtime-reuse-01')
HANDOFF=REPO/'investigations/build-handoff/2026-09-27'
ARTIFACT=REPO/'investigations/artifact-handoff/2026-09-26'
ARCHIVE=REPO/'investigations/runtime-proof/2026-09-26/runtime-proof-inputs-03/guest-runtime.py'
spec=importlib.util.spec_from_file_location('helpers',ARTIFACT/'prepare.py');helpers=importlib.util.module_from_spec(spec);spec.loader.exec_module(helpers)
replace_once=helpers.replace_once;replace_function=helpers.replace_function


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def fixture_helpers():
    source=ARCHIVE.read_text();tree=ast.parse(source)
    names={'scrub','check_guest','verify_runtime','allocated','guard','connection','stage_runtime_packages',
           'install_runtime','Database','configure','shared_evidence','oom_kills','verify_binaries'}
    parts=[]
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in names:
            if node.name=='Database':
                node.body=[n for n in node.body if not isinstance(n,ast.FunctionDef) or n.name!='snapshot']
                parts.append(ast.unparse(node))
            else:parts.append(ast.get_source_segment(source,node))
    result='\n\n'.join(parts)
    return replace_once(result," if case=='negative':(server/'maps/water/poknowledge.wtr').unlink()\n",'')


def prepare():
    if any(p.exists() or p.is_symlink() for p in [ROOT,OUTPUT,LAUNCHER]):raise RuntimeError('Preserve existing attempt/preparation')
    prior=json.loads((HANDOFF/'receipts/preparation.json').read_text())
    worker_path=PREVIOUS/'consumer-worker.py'
    if sha(worker_path)!=prior['worker_files'][worker_path.name]:raise RuntimeError('Consumer template changed')
    worker_base=worker_path.read_text()
    tree=ast.parse(worker_base)
    files=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='FILES' for t in n.targets))
    seed=LOCAL/files['seed.iso'][0]
    if sha(seed)!=files['seed.iso'][2]:raise RuntimeError('Consumer seed changed')
    raw=subprocess.run(['isoinfo','-i',str(seed),'-x','/USER_DAT.;1'],check=True,capture_output=True).stdout.decode()
    user=json.loads(raw.split('\n',1)[1]);build=next(f['content'] for f in user['write_files'] if f['path'].endswith('/guest_build.py'))
    identities=json.loads((HANDOFF/'receipts/attempt-01/identities.json').read_text())
    original=Path('/var/lib/eqemu-vm-proof/build-handoff-01')
    for name,expected in identities.items():
        if sha(original/name)!=expected:raise RuntimeError('Handoff receipt changed')
    retained=json.loads((original/'suite-result.json').read_text())['cleanup']['artifact_retained']
    import time
    if retained['expires_at']<=time.time():raise RuntimeError('Retained build expired')
    sources={str(p.relative_to(REPO)):sha(p) for p in [*sorted(SOURCE.glob('*.py')),ARCHIVE,ARTIFACT/'diagnostics.py']}
    recipe=hashlib.sha256(json.dumps({'sources':sources,'artifact':retained,'build_id':prior['build_id']},sort_keys=True).encode()).hexdigest()
    build=build.replace(prior['recipe_sha256'],recipe)
    build=replace_once(build,'cap=64*1024**2,expected_exit=0):','cap=64*1024**2,expected_exit=0,stdin=None):')
    build=replace_once(build,'stdin=subprocess.DEVNULL,env=ENV','stdin=stdin if stdin is not None else subprocess.DEVNULL,env=ENV')
    build=replace_once(build," path=LOGS/(name+'.log');", " global LAST_COMMAND\n path=LOGS/(name+'.log');LAST_COMMAND=path;")
    build=replace_once(build,"    if time.monotonic()>end:", "    GUARD()\n    if time.monotonic()>end:")
    build=replace_once(build,' end=time.monotonic()+10',' end=min(time.monotonic()+10,SEND_DEADLINE)')
    build=replace_once(build,"if __name__=='__main__':main()", "LAST_COMMAND=None\nGUARD=lambda:None\nSEND_DEADLINE=float('inf')\nif __name__=='__main__':main()")
    header='''#!/usr/bin/python3
import hashlib,importlib.util,json,os,pathlib,pwd,re,resource,secrets,select,shutil,signal,subprocess,tarfile,time,tty,zipfile
P=pathlib.Path
spec=importlib.util.spec_from_file_location('build',P(__file__).with_name('guest-build.py'));B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
RM=P('/opt/runtime-inputs');ROOT=P('/opt/eqemu-runtime');GIB=1024**3
RUNTIME_SHA='b51d4751fe2a31689dd906b392da1e24d9510e26418067b09788f43b78403b28'
BUILD_USED=0;LAST_CHECK=0;SERVICES=[];SECRET_VALUES=[]
ANSI=re.compile(r'\\x1b\\[[0-?]*[ -/]*[@-~]')
'''
    guest=header+(ARTIFACT/'diagnostics.py').read_text()+'\n'+(SOURCE/'services.py').read_text()+'\n'+fixture_helpers()+'\n'+(SOURCE/'scenario.py').read_text().replace('@RECIPE@',recipe)
    stage=Path(tempfile.mkdtemp(prefix='.runtime-reuse-',dir=LOCAL))
    try:
        user['write_files']=[{'path':'/opt/eqemu-proof/guest-build.py','permissions':'0700','content':build},
            {'path':'/opt/eqemu-proof/guest-runtime.py','permissions':'0700','content':guest},
            {'path':'/opt/eqemu-proof/RUNTIME_GUEST_ONLY','permissions':'0600','content':'diagnostic-only runtime reuse\n'},
            {'path':'/etc/cloud/cloud.cfg.d/99-offline.cfg','content':'network: {config: disabled}\n'}]
        user['runcmd'][-1]=['python3','-I','/opt/eqemu-proof/guest-runtime.py']
        (stage/'user-data').write_text('#cloud-config\n'+json.dumps(user,indent=2)+'\n')
        (stage/'meta-data').write_text('instance-id: eqemu-runtime-reuse-01\nlocal-hostname: eqemu-runtime\n')
        seed=stage/'seed.iso';subprocess.run(['cloud-localds',str(seed),str(stage/'user-data'),str(stage/'meta-data')],check=True)
        worker=worker_base.replace(prior['recipe_sha256'],recipe).replace('build-handoff-01','runtime-reuse-01').replace('bh-cons01','rreuse01').replace('buildhandoffcons01worker','rreuse01worker').replace('buildhandoff01ctl','rreuse01ctl')
        worker=worker.replace('offline EQEmu build experiment; guest evidence remains untrusted','diagnostic-only reused-build service scenario; guest evidence remains untrusted')
        # The prior producer/custody is immutable input. Only this worker's copy is writable state.
        worker=replace_once(worker,"STORE = ROOT.parent / 'retained'", "ARTIFACT_OWNER=BASE/'build-handoff-01'\nSTORE=ARTIFACT_OWNER/'retained'")
        worker=replace_once(worker,"CUSTODY = ROOT.parent / 'custody.json'", "CUSTODY=ARTIFACT_OWNER/'custody.json'")
        worker=replace_once(worker,"path = ROOT.parent/'producer/evidence/report.json'", "path = ARTIFACT_OWNER/'producer/evidence/report.json'")
        worker=replace_once(worker,'    safe_dir(ROOT.parent)\n    facts = CUSTODY.lstat()', '    safe_dir(ARTIFACT_OWNER)\n    facts = CUSTODY.lstat()')
        worker=replace_once(worker,"    safe_dir(STORE)\n    return value", "    if value.get('consumer_verified') is not True:raise RuntimeError('Unqualified retained artifact')\n    safe_dir(STORE)\n    return value")
        files['seed.iso']=('runtime-reuse-inputs-01/seed.iso',seed.stat().st_size,sha(seed))
        files['runtime.iso']=('runtime-inputs-20260926/runtime-inputs.iso',171806720,'5fa2a4822e03ee7693c566e8670ddab5ee35c7a5d25d4671ac57c53ddf82c767')
        worker=re.sub(r'FILES=\{.*?\n\}', 'FILES='+repr(files),worker,count=1,flags=re.S)
        worker=replace_once(worker,'  {DATA}/fixture.iso rk,','  {DATA}/fixture.iso rk,\n  {DATA}/runtime.iso rk,')
        disk='    <disk type="file" device="cdrom"><driver name="qemu" type="raw"/><source file="{DATA}/runtime.iso"/><target dev="sdc" bus="sata"/><readonly/></disk>\n'
        worker=replace_once(worker,'    <serial type="unix">',disk+'    <serial type="unix">')
        worker=replace_once(worker,'len(disks)!=4','len(disks)!=5')
        worker=worker.replace("['seed.iso','fixture.iso']", "['seed.iso','fixture.iso','runtime.iso']")
        worker=replace_once(worker,"with sock,(EVIDENCE/'serial.log').open('xb') as log:", "with sock,(EVIDENCE/'serial.log').open('xb') as log,(EVIDENCE/'diagnostics.jsonl').open('xb') as diagnostics:\n        os.chown(EVIDENCE/'diagnostics.jsonl',0,pwd.getpwnam('bump').pw_gid);os.chmod(EVIDENCE/'diagnostics.jsonl',0o640)")
        anchor="                elif kind=='observation':report"
        handlers="""                elif kind=='reuse':report['reuse_untrusted']=v
                elif kind=='scenario-event':
                    report.setdefault('scenario_events_untrusted',[]).append(dict(v,host_received_at=time.time()))
                elif kind=='diagnostic':
                    diagnostics.write((json.dumps(v)+'\\n').encode());diagnostics.flush()
                    report['diagnostic_streams_untrusted']=protocol.streams
"""
        worker=replace_once(worker,anchor,handlers+anchor)
        worker=replace_once(worker,"report['ready_at']=time.time();deadline=time.monotonic()+1800","report['ready_at']=time.time();deadline=time.monotonic()+2040")
        worker=replace_once(worker,"    report['workload_ok']=True", "    report['diagnostic_complete']=protocol.result.get('ok') is True and protocol.result.get('evidence_complete') is True\n    write_json(EVIDENCE/'report.json',report)\n    raise RuntimeError('Diagnostic-only replay is not accepted validation; inspect service evidence and database warning')")
        worker=replace_once(worker,"(EVIDENCE/'serial.log').chmod(0o644)", "os.chown(EVIDENCE/'serial.log',0,pwd.getpwnam('bump').pw_gid);(EVIDENCE/'serial.log').chmod(0o640)")
        # Scenario failure has structured context instead of the old single error string.
        worker=replace_once(worker,"protocol.result['error']", "str(protocol.result.get('first_failure','Scenario incomplete'))")
        worker=replace_once(worker,"if __name__=='__main__':", (SOURCE/'protocol.py').read_text()+"\nif __name__=='__main__':")
        (stage/'consumer-worker.py').write_text(worker)
        previous_suite=LOCAL/'corrected-build-inputs-01/launcher.py'
        expected=json.loads((REPO/'investigations/corrected-build/2026-09-26/receipts/preparation.json').read_text())['launcher_sha256']
        if sha(previous_suite)!=expected:raise RuntimeError('Single-worker suite template changed')
        suite=previous_suite.read_text().replace('corrected-build-01','runtime-reuse-01').replace('corrected-build-inputs-01','runtime-reuse-inputs-01').replace('correctedbuild01','rreuse01').replace('build-worker.py','consumer-worker.py').replace("'build'","'consumer'")
        suite=suite.replace('build/evidence/report.json','consumer/evidence/report.json')
        suite=suite.replace('RuntimeMaxSec=18000','RuntimeMaxSec=3000').replace('time.monotonic()+17700','time.monotonic()+2700')
        suite=re.sub(r'HASHES=\{[^\n]+\}', 'HASHES='+repr({'consumer-worker.py':sha(stage/'consumer-worker.py')}),suite,count=1)
        start=suite.index("    prior=BASE/'build-proof-03/suite-result.json';");end=suite.index('    if ROOT.exists()',start)
        suite=suite[:start]+suite[end:]
        prerequisite='''def prerequisites():
    prior=BASE/'build-handoff-01'
    for name,expected in PRIOR_HASHES.items():
        read(prior/name)
        if digest(prior/name)!=expected:raise RuntimeError('Qualified handoff evidence changed')
    if read(prior/'suite-result.json').get('suite_passed') is not True or read(prior/'leases.json')['active']:raise RuntimeError('Handoff qualification missing')
    if read(prior/'suite-result.json')['cleanup']['artifact_retained']['expires_at']<=time.time():raise RuntimeError('Artifact expired')
'''
        suite=replace_function(suite,'prerequisites',prerequisite)
        suite=replace_once(suite,"write(ROOT/'case-result.json',result);report['case']=result", "write(ROOT/'case-result.json',result);report['case']=result;report['diagnostic_complete']=r.get('diagnostic_complete',False);report['diagnostic_only']=True")
        suite=replace_once(suite,"'cleanup':c.get('complete') is True and c.get('readonly_inputs_unchanged') is True", "'cleanup':c.get('complete') is True and c.get('readonly_inputs_unchanged') is True and c.get('artifact_input_unchanged') is True")
        suite=replace_once(suite,"if __name__=='__main__':", 'PRIOR_HASHES='+repr(identities)+"\nif __name__=='__main__':")
        for name,code in [('guest-build.py',build),('guest-runtime.py',guest),('consumer-worker.py',worker),('launcher.py',suite)]:
            compile(code,name,'exec');(stage/name).write_text(code)
        (stage/'preparation.json').write_text(json.dumps({'scope':'diagnostic-only startup replay; no accepted runtime validation or new compilation',
            'recipe_sha256':recipe,'build_id':prior['build_id'],'artifact':retained,'sources':sources,
            'worker_sha256':sha(stage/'consumer-worker.py'),'launcher_sha256':sha(stage/'launcher.py'),'seed_sha256':sha(seed)},indent=2)+'\n')
        stage.rename(OUTPUT);LAUNCHER.write_text(suite)
        print(json.dumps({'prepared':str(OUTPUT),'launcher':str(LAUNCHER),'vm_started':False}))
    finally:
        if stage.exists():shutil.rmtree(stage)


if __name__=='__main__':prepare()
