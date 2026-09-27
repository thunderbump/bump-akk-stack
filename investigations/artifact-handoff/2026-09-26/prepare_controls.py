#!/usr/bin/python3
"""Prepare fixed negative controls from the successful attempt02. No VM launch."""
import ast
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from prepare import replace_once, replace_function

SOURCE = Path(__file__).resolve().parent
LOCAL = Path('/home/bump/.local/state/eqemu-vm-proof')
PREVIOUS = LOCAL/'artifact-handoff-inputs-02'
OUTPUT = LOCAL/'artifact-handoff-inputs-03'
LAUNCHER = LOCAL/'offline-artifact-handoff-03.py'
ROOT = Path('/var/lib/eqemu-vm-proof/artifact-handoff-03')


def digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()


def prepare():
    if any(p.exists() or p.is_symlink() for p in [ROOT,OUTPUT,LAUNCHER]):
        raise RuntimeError('Preserve existing preparation or attempt')
    previous = json.loads((SOURCE/'preparation-02.json').read_text())
    if digest(PREVIOUS/'producer-worker.py') != previous['worker_files']['producer-worker.py'] or digest(PREVIOUS/'launcher.py') != previous['launcher_sha256']:
        raise RuntimeError('Successful controller template changed')
    if digest(PREVIOUS/'producer-user-data') != '466ec353a2410e3acda22c03414cffb128087448c0a96c02dced9f230b5d2f31':
        raise RuntimeError('Successful seed configuration changed')
    stage = Path(tempfile.mkdtemp(prefix='.handoff-controls-',dir=LOCAL))
    try:
        hashes = {}
        for case,short in [('cancel','can'),('publish','pub')]:
            guest = (SOURCE/'guest.py').read_text().replace('@ROLE@','producer')
            if case=='cancel':
                guest=replace_once(guest,"            (MOUNT / 'payload.bin').write_bytes(PAYLOAD)","""            (MOUNT / 'payload.bin').write_bytes(PAYLOAD)
            emit({'kind':'export_started','role':ROLE})
            time.sleep(60)
            raise RuntimeError('Cancellation did not arrive at export checkpoint')""")
            user=json.loads((PREVIOUS/'producer-user-data').read_text().split('\n',1)[1])
            for entry in user['write_files']:
                if entry['path'].endswith('/guest.py'):entry['content']=guest
                elif entry['path'].endswith('/artifact.py'):entry['content']=(SOURCE/'artifact.py').read_text()
                elif entry['path'].endswith('/diagnostics.py'):entry['content']=(SOURCE/'diagnostics.py').read_text()
            ud=stage/(case+'-user-data');md=stage/(case+'-meta-data');seed=stage/(case+'-seed.iso')
            ud.write_text('#cloud-config\n'+json.dumps(user,indent=2)+'\n')
            md.write_text('instance-id: eqemu-handoff-03-'+case+'\nlocal-hostname: eqemu-handoff\n')
            subprocess.run(['cloud-localds','--disk-format','raw',str(seed),str(ud),str(md)],check=True)
            worker=(PREVIOUS/'producer-worker.py').read_text()
            worker=worker.replace('artifact-handoff-02','artifact-handoff-03').replace('handoff-prod02','handoff-'+short+'03').replace('handoffprod02','handoff'+short+'03').replace('handoff02ctl','handoff03ctl')
            worker=replace_once(worker,"ROOT=BASE/'artifact-handoff-03'/'producer'","ROOT=BASE/'artifact-handoff-03'/"+repr(case))
            worker=replace_once(worker,"CASE='producer'",'CASE='+repr(case))
            oldline=next(line for line in worker.splitlines() if line.startswith('FILES='))
            files=ast.literal_eval(oldline[len('FILES='):]);files['seed.iso']=('artifact-handoff-inputs-03/'+seed.name,seed.stat().st_size,digest(seed))
            worker=replace_once(worker,oldline,'FILES='+repr(files))
            start=worker.index('# Appended to the pinned worker');end=worker.index("if __name__=='__main__':",start)
            # Keep the successful payload identities while applying publication-error handling.
            manifest=next(line.split(' = ',1)[1] for line in worker.splitlines() if line.startswith('EXPECTED_MANIFEST = '))
            payload=next(line.split(' = ',1)[1] for line in worker.splitlines() if line.startswith('EXPECTED_PAYLOAD = '))
            extension=(SOURCE/'worker_extension.py').read_text().replace("'@MANIFEST@'",manifest).replace("'@PAYLOAD@'",payload)
            extension=extension.replace("CASE == 'producer'","CASE in ('cancel','publish')").replace("value.get('role') != CASE","value.get('role') != 'producer'")
            anchor="                elif value.get('kind') == 'result' and ready and value.get('nonce') == nonce:"
            checkpoint="""                elif CONTROL == 'cancel' and value.get('kind') == 'export_started' and ready and value.get('nonce') == nonce and not report.get('export_started'):
                    report['export_started'] = True
"""
            extension=replace_once(extension,anchor,checkpoint+anchor)
            adapter=(SOURCE/'control_worker.py').read_text().replace('@CONTROL@',case)
            worker=worker[:start]+extension+'\n'+adapter+'\n'+worker[end:]
            compile(worker,case+'-worker.py','exec')
            target=stage/(case+'-worker.py');target.write_text(worker);hashes[target.name]=digest(target)
        suite=(PREVIOUS/'launcher.py').read_text().replace('artifact-handoff-02','artifact-handoff-03').replace('artifact-handoff-inputs-02','artifact-handoff-inputs-03').replace('handoff-02','handoff-03').replace('handoff02','handoff03')
        suite=replace_once(suite,"CASES=('producer','consumer')","CASES=('cancel','publish')")
        hashline=next(line for line in suite.splitlines() if line.startswith('HASHES='));suite=replace_once(suite,hashline,'HASHES='+repr(hashes))
        suite=suite.replace("module('producer'","module('cancel'")
        start=suite.index('# Replaces only suite case sequencing');suite=suite[:start]
        identities=json.loads((SOURCE/'receipts/attempt-02/identities.json').read_text())
        prerequisite="""def prerequisites():
    m=module('cancel',local=True)
    prior=BASE/'artifact-handoff-02'
    m.safe_dir(BASE);m.safe_dir(prior)
    for name,expected in PRIOR_HASHES.items():
        read(prior/name)
        if digest(prior/name)!=expected:raise RuntimeError('Successful baseline evidence changed')
    if read(prior/'suite-result.json').get('suite_passed') is not True or read(prior/'leases.json')['active']:
        raise RuntimeError('Successful baseline required')
"""
        suite=replace_function(suite,'prerequisites',prerequisite)
        common=(SOURCE/'suite_extension.py').read_text()
        admit=common[common.index('def admit('):common.index('\ndef supervise(')]
        cleanup=common[common.index('def cleanup('):].replace("module('producer')","module('cancel')")
        suite+='\nPRIOR_HASHES='+repr(identities)+'\n'+admit+'\n'+(SOURCE/'control_suite.py').read_text()+'\n'+cleanup+"\nif __name__=='__main__':sys.exit(main())\n"
        compile(suite,'launcher.py','exec')
        (stage/'launcher.py').write_text(suite)
        (stage/'preparation.json').write_text(json.dumps({'scope':'fixed cancellation and failed-publication controls; unexecuted',
            'worker_files':hashes,'launcher_sha256':digest(stage/'launcher.py'),
            'sources':{p.name:digest(p) for p in SOURCE.glob('*.py')}},indent=2)+'\n')
        stage.rename(OUTPUT);LAUNCHER.write_text(suite)
        print(json.dumps({'prepared':str(OUTPUT),'launcher':str(LAUNCHER),'vm_started':False}))
    finally:
        if stage.exists():shutil.rmtree(stage)


if __name__=='__main__':prepare()
