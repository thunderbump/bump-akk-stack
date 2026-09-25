"""Generate new fixed helpers without editing any prior proof artifact."""
from pathlib import Path
import hashlib,json,subprocess
B=Path('/home/bump/.local/state/eqemu-vm-proof');D=B/'recovery-inputs'
CASES=('supervisor','stale','io','left','right','third')
base=(B/'lifetime-inputs/timeout-worker.py').read_text()
assert hashlib.sha256(base.encode()).hexdigest()=='02eb90d282721e45b82ed3d0c4ec20b48b4d2e92fb850979fe98e03064a6f27f'
guest=(B/'first-trial-inputs/guest_trial.py').read_text();guest=guest[:guest.index('finally:\n')]+'finally:\n'+(D/'guest-suffix.py').read_text()
parser=(B/'pressure-inputs/evidence.py').read_text();parser=parser[parser.index('class EvidenceError'):parser.index('class SerialReader')]
host=(D/'host-transport.py').read_text();manifest={}
for case in CASES:
    gd=D/case;gd.mkdir(exist_ok=True)
    g=guest.replace('P = pathlib.Path',f'CASE={case!r}\nP = pathlib.Path');compile(g,str(gd/'guest.py'),'exec');(gd/'guest.py').write_text(g)
    config=json.loads((B/'first-trial-inputs/user-data').read_text().split('\n',1)[1])
    for item in config['write_files']:
        if item['path']=='/opt/eqemu-proof/guest_trial.py':item['content']=g
    data='#cloud-config\n'+json.dumps(config,indent=2)+'\n'
    changed=not (gd/'user-data').exists() or (gd/'user-data').read_text()!=data
    (gd/'user-data').write_text(data);(gd/'meta-data').write_text('instance-id: eqemu-recovery-'+case+'-v1\nlocal-hostname: eqemu-recovery\n')
    if changed and (gd/'seed.iso').exists():(gd/'seed.iso').unlink()
    if not (gd/'seed.iso').exists():subprocess.run(['cloud-localds',str(gd/'seed.iso'),str(gd/'user-data'),str(gd/'meta-data')],check=True)
    size=(gd/'seed.iso').stat().st_size;sha=hashlib.sha256((gd/'seed.iso').read_bytes()).hexdigest()
    code=base.replace("ROOT=BASE/'lifetime-tests'/'timeout'",f"ROOT=BASE/'recovery-tests'/'{case}'").replace('eqemu-vm-lifetime-timeout.service',f'eqemu-vm-recovery-{case}.service').replace('eqemuvmlifetimetimeout',f'eqemuvmrecovery{case}').replace('eqemu-lt-timeout',f'eqemu-rc-{case}').replace('RuntimeMaxSec=300','RuntimeMaxSec=1200')
    code=code.replace("'lifetime-inputs/seed.iso',378880,'bb13fa13d45f6e5f459922b34a194694e312d33cb452629dae82446ff260193e'",f"'recovery-inputs/{case}/seed.iso',{size},'{sha}'")
    code=code.replace('GIB=1024**3',f"CASE={case!r}\nGIB=1024**3")
    code=code.replace("'-p','MemoryMax=960M'","'-p','Slice=eqemuvmrecoveryctl.slice','-p','MemoryMax=960M'")
    code=code.replace("'scope':'deliberately interrupted synthetic VM; never a successful workload'","'scope':'synthetic recovery and concurrency proof; guest evidence remains untrusted'")
    code=code.replace("        receipt['domain_absent']=True","        receipt['domain_absent']=True\n        cleanup_barrier(s)")
    # Pin the copied controller as part of ownership state before starting it.
    code=code.replace("SCRIPT.chmod(0o600)\n    # Copies", "SCRIPT.chmod(0o600)\n    s['controller_sha256']=digest(SCRIPT);write_json(STATE,s)\n    # Copies")
    code=code.replace("    s=json.loads(STATE.read_text())","    s=regular_root_json(STATE)")
    if case=='io':
        code=code.replace('  {DATA}/root.raw rwk,','  {DATA}/root.raw rwk,\n  {DATA}/io.raw rwk,')
        code=code.replace('    <serial type="unix">','    <disk type="file" device="disk"><driver name="qemu" type="raw" cache="none"/><source file="{DATA}/io.raw"/><target dev="vdb" bus="virtio"/><serial>EQIOPROBE</serial></disk>\n    <serial type="unix">')
        needle="        report['allocated_disk_bytes']=raw.stat().st_blocks*512"
        code=code.replace(needle,needle+"\n        extra=DATA/'io.raw'\n        with extra.open('xb') as f:os.posix_fallocate(f.fileno(),0,128*1024**2)\n        extra.chmod(0o600);os.chown(extra,account.pw_uid,account.pw_gid)\n        if extra.stat().st_size!=128*1024**2 or extra.stat().st_blocks*512<128*1024**2:raise RuntimeError('I/O disk not allocated')")
    a=code.index('        deadline=time.monotonic()+900;');z=code.index('    except Exception as exc:report',a)
    code=code[:a]+'        collect_recovery(sock,s,report,cg)\n'+code[z:]
    idx=code.index('\ndef main():');code=code[:idx]+'\n'+parser+'\n'+host+code[idx:]
    f=D/(case+'-worker.py');compile(code,str(f),'exec');f.write_text(code);manifest[f.name]=hashlib.sha256(f.read_bytes()).hexdigest()
(D/'worker-hashes.json').write_text(json.dumps(manifest,indent=2)+'\n')
template=(D/'suite-template.py').read_text().replace('HASHES={}', 'HASHES='+repr(manifest))
f=B/'recovery-tests.py';compile(template,str(f),'exec');f.write_text(template)
print(json.dumps({'suite_sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'workers':manifest},indent=2))
