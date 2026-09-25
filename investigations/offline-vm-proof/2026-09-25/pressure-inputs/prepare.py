"""Generate fixed investigation artifacts from the verified lifetime baseline."""
from pathlib import Path
import hashlib,json,subprocess
B=Path('/home/bump/.local/state/eqemu-vm-proof');D=B/'pressure-inputs'
CASES=['resources','oom','tasks','malformed','oversized','duplicate','forged','flood']
base=(B/'lifetime-inputs/timeout-worker.py').read_text()
assert hashlib.sha256(base.encode()).hexdigest()=='02eb90d282721e45b82ed3d0c4ec20b48b4d2e92fb850979fe98e03064a6f27f'
life=(B/'lifetime-tests.py').read_text();assert hashlib.sha256(life.encode()).hexdigest()=='42aa6c7b17244845d796f525ecca53c713d579406960a5995596fcf0eff76951'
guest=(B/'first-trial-inputs/guest_trial.py').read_text();guest=guest[:guest.index('finally:\n')]+ 'finally:\n'+(D/'guest-suffix.py').read_text()
parser=(D/'evidence.py').read_text();host=(D/'host-pressure.py').read_text();task=(D/'task-probe.py').read_text()
manifest={}
for case in CASES:
    gd=D/case;gd.mkdir(exist_ok=True)
    g=guest.replace('P = pathlib.Path',f"CASE={case!r}\nP = pathlib.Path")
    compile(g,str(gd/'guest.py'),'exec');(gd/'guest.py').write_text(g)
    config=json.loads((B/'first-trial-inputs/user-data').read_text().split('\n',1)[1])
    for item in config['write_files']:
        if item['path']=='/opt/eqemu-proof/guest_trial.py':item['content']=g
    (gd/'user-data').write_text('#cloud-config\n'+json.dumps(config,indent=2)+'\n')
    (gd/'meta-data').write_text('instance-id: eqemu-pressure-'+case+'-v1\nlocal-hostname: eqemu-pressure\n')
    if not (gd/'seed.iso').exists():subprocess.run(['cloud-localds',str(gd/'seed.iso'),str(gd/'user-data'),str(gd/'meta-data')],check=True)
    size=(gd/'seed.iso').stat().st_size;sha=hashlib.sha256((gd/'seed.iso').read_bytes()).hexdigest()
    code=base.replace("ROOT=BASE/'lifetime-tests'/'timeout'",f"ROOT=BASE/'pressure-tests'/'{case}'").replace('eqemu-vm-lifetime-timeout.service',f'eqemu-vm-pressure-{case}.service').replace('eqemuvmlifetimetimeout',f'eqemuvmpressure{case}').replace('eqemu-lt-timeout',f'eqemu-pr-{case}').replace('RuntimeMaxSec=300','RuntimeMaxSec=600')
    code=code.replace("'lifetime-inputs/seed.iso',378880,'bb13fa13d45f6e5f459922b34a194694e312d33cb452629dae82446ff260193e'",f"'pressure-inputs/{case}/seed.iso',{size},'{sha}'")
    code=code.replace('GIB=1024**3',f"CASE={case!r}\nPROBEUNIT=UNIT.replace('.service','-probe.service')\nTASK_SOURCE={task!r}\nGIB=1024**3")
    code=code.replace("    if ROOT.exists() or ROOT.is_symlink():", "    if CASE=='tasks' and run(['systemctl','show',PROBEUNIT,'-p','LoadState','--value']).stdout.strip()!='not-found':raise RuntimeError('Task probe unit already exists')\n    if ROOT.exists() or ROOT.is_symlink():",1)
    if case=='resources':
        code=code.replace('  {DATA}/root.raw rwk,','  {DATA}/root.raw rwk,\n  {DATA}/pressure.raw rwk,')
        target='    <serial type="unix">'
        extra='    <disk type="file" device="disk"><driver name="qemu" type="raw" cache="none"/><source file="{DATA}/pressure.raw"/><target dev="vdb" bus="virtio"/><serial>EQPROBE</serial></disk>\n'
        code=code.replace(target,extra+target)
        needle="        report['allocated_disk_bytes']=raw.stat().st_blocks*512"
        code=code.replace(needle,needle+"\n        extra=DATA/'pressure.raw'\n        with extra.open('xb') as f:os.posix_fallocate(f.fileno(),0,32*1024**2)\n        extra.chmod(0o600);os.chown(extra,account.pw_uid,account.pw_gid)\n        if extra.stat().st_size!=32*1024**2 or extra.stat().st_blocks*512<32*1024**2:raise RuntimeError('Synthetic disk not allocated')")
    a=code.index('        deadline=time.monotonic()+900;');z=code.index('    except Exception as exc:report',a)
    code=code[:a]+'        collect_pressure(sock,s,report,cg)\n'+code[z:]
    code=code.replace("    s=state();receipt={'complete':False,'uuid':s['uuid'],'started_at':time.time()}\n    try:","    s=state();receipt={'complete':False,'uuid':s['uuid'],'started_at':time.time()}\n    try:\n        task_cleanup()")
    idx=code.index('\ndef main():');code=code[:idx]+'\n'+parser+'\n'+host+code[idx:]
    f=D/(case+'-worker.py');compile(code,str(f),'exec');f.write_text(code);manifest[f.name]=hashlib.sha256(f.read_bytes()).hexdigest()
(D/'worker-hashes.json').write_text(json.dumps(manifest,indent=2)+'\n')
# A separate supervisor retains the already-proven ownership and rescue pattern.
code=life.replace("ROOT=BASE/'lifetime-tests'","ROOT=BASE/'pressure-tests'").replace("/eqemu-vm-proof/lifetime-inputs","/eqemu-vm-proof/pressure-inputs").replace('eqemu-vm-lifetime-suite.service','eqemu-vm-pressure-suite.service').replace("CASES=('timeout','cancel','death')",'CASES='+repr(tuple(CASES))).replace("module('timeout'","module('resources'").replace('RuntimeMaxSec=1800','RuntimeMaxSec=3600')
a=code.index('HASHES=');z=code.index('\nENV=',a);code=code[:a]+'HASHES='+json.dumps(manifest,indent=2)+code[z:]
a=code.index('\ndef classify(');z=code.index('\ndef supervise(',a)
code=code[:a]+(D/'supervisor-cases.py').read_text()+code[z:]
f=B/'pressure-tests.py';compile(code,str(f),'exec');f.write_text(code)
print(json.dumps({'suite_sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'workers':manifest},indent=2))
