"""Generate fixed runtime proof media/launcher from the proven build controller."""
from pathlib import Path
import hashlib,json,subprocess
B=Path(__file__).resolve().parent;D=B/'runtime-proof-inputs-03';O=B/'build-proof-inputs-v4'
assert not Path('/var/lib/eqemu-vm-proof/runtime-proof-03').exists(),'Refuse altering preparation after launch'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
# Preserve the known build code except bounded-command stdin and watchdog support.
u=json.loads((O/'user-data').read_text().split('\n',1)[1])
u['write_files']=[{'path':'/opt/eqemu-proof/guest-build.py','permissions':'0700','content':(D/'guest-build.py').read_text()},{'path':'/opt/eqemu-proof/guest-runtime.py','permissions':'0700','content':(D/'guest-runtime.py').read_text()},{'path':'/opt/eqemu-proof/RUNTIME_GUEST_ONLY','permissions':'0600','content':'fixed offline runtime proof\n'},{'path':'/etc/cloud/cloud.cfg.d/99-offline.cfg','content':'network: {config: disabled}\n'}]
u['runcmd'][-1]=['python3','-I','/opt/eqemu-proof/guest-runtime.py']
(D/'user-data').write_text('#cloud-config\n'+json.dumps(u,indent=2)+'\n');(D/'meta-data').write_text('instance-id: eqemu-runtime-proof-03\nlocal-hostname: eqemu-runtime\n')
seed=D/'seed.iso'
if seed.exists():seed.unlink() # This generator owns only this unlaunched preparation seed.
subprocess.run(['cloud-localds','--disk-format','raw',str(seed),str(D/'user-data'),str(D/'meta-data')],check=True)
worker=(O/'build-worker.py').read_text().replace('build-proof-04','runtime-proof-03').replace('build-04','runtime-03').replace('build04','runtime03').replace('build-proof-inputs-v4','runtime-proof-inputs-03')
worker=worker.replace("387072,'4e08ad92914498a5ae5bacd261598e2b0296f82d8f877763822ee6d4d12dca8d'",str(seed.stat().st_size)+",'"+sha(seed)+"'")
worker=worker.replace(" 'fixture.iso':", " 'runtime.iso':('runtime-inputs-20260926/runtime-inputs.iso',171806720,'5fa2a4822e03ee7693c566e8670ddab5ee35c7a5d25d4671ac57c53ddf82c767'),\n 'fixture.iso':")
worker=worker.replace('  {DATA}/fixture.iso rk,','  {DATA}/fixture.iso rk,\n  {DATA}/runtime.iso rk,')
xml='    <disk type="file" device="cdrom"><driver name="qemu" type="raw"/><source file="{DATA}/runtime.iso"/><target dev="sdc" bus="sata"/><readonly/></disk>\n'
worker=worker.replace('    <serial type="unix">',xml+'    <serial type="unix">')
worker=worker.replace("for name in ['seed.iso','fixture.iso']", "for name in ['seed.iso','fixture.iso','runtime.iso']")
i=worker.index('def collect_build(');worker=worker[:i]+(D/'runtime-protocol.py').read_text()+'\n\n'+worker[i:]
worker=worker.replace("len(report['stages'])>=50", "len(report['stages'])>=100")
worker=worker.replace("elif kind=='preflight':report['preflight_untrusted']=v;deadline=time.monotonic()+14400", "elif kind=='preflight':report['preflight_untrusted']=v;deadline=time.monotonic()+14400\n                elif kind=='runtime':\n                    report.setdefault('runtime_events_untrusted',[]).append(v)\n                    if len(report['runtime_events_untrusted'])>80:raise RuntimeError('Runtime event count')")
worker=worker.replace("if protocol.result is None:raise RuntimeError('Missing guest result')", "if parser.tail.strip():raise RuntimeError('Truncated trailing serial evidence')\n    if protocol.result is None:raise RuntimeError('Missing guest result')")
worker=worker.replace("report['workload_ok']=True", "events=dict(line.split() for line in (cg/'memory.events').read_text().splitlines())\n    if int(events.get('oom_kill',0)) or int(events.get('oom',0)):raise RuntimeError('Worker memory failure')\n    report['workload_ok']=True")
(D/'build-worker.py').write_text(worker)
suite=(B/'offline-build-proof-v4.py').read_text().replace('build-proof-04','runtime-proof-03').replace('build-04','runtime-03').replace('build04','runtime03').replace('build-proof-inputs-v4','runtime-proof-inputs-03')
suite=suite.replace('a9e49677ab1a83a67dafaf97f288b67307611e02679a6a9840c2d4a6f543a2d2',sha(D/'build-worker.py'))
suite=suite.replace('build-proof-03','build-proof-04').replace('3dc79bb99749f6d202e37aa217e94b3e3eb27fe12d4418c70aa93b0e3da834d7','b6f4d0f6dc83b1f4dc1aedcdd0e19a3e6629ea96da8a6262d977d83ee3980bc9')
suite=suite.replace('offline EQEmu build proof','offline EQEmu build and runtime proof')

# A failed prior workload remains failed; only its exact completed cleanup permits a retry.
retry_check="""    previous=BASE/'runtime-proof-02';r=read(previous/'suite-result.json')
    if digest(previous/'suite-result.json')!='6947335e0f44e317bd20004af5c6cbeb2a33088fb1c842fc874ea4c0cccfba93' or r.get('suite_passed') is not False or r.get('cleanup',{}).get('complete') is not True or r['cleanup'].get('rescued') or read(previous/'leases.json')['active'] or (previous/'build/data').exists():raise RuntimeError('Prior failed runtime attempt evidence or cleanup changed')
    if digest(previous/'build/evidence/report.json')!='9c894aa6e61bb39ed14f3da6c4b24a53031e07f15906926a0c2d59353ca1165c' or digest(previous/'build/evidence/cleanup.json')!='49653de5620e59ac4e85e4675a179309c413106a2dfd71218facb2a9c75b1806':raise RuntimeError('Prior runtime receipts changed')
"""
suite=suite.replace('def prerequisites():\n','def prerequisites():\n'+retry_check)

(B/'offline-runtime-proof-03.py').write_text(suite)
for p in [D/'guest-build.py',D/'guest-runtime.py',D/'build-worker.py',B/'offline-runtime-proof-03.py']:compile(p.read_text(),str(p),'exec')
(D/'generated-manifest.json').write_text(json.dumps({'status':'prepared-unexecuted','seed_bytes':seed.stat().st_size,'files':{p.name:sha(p) for p in [D/'guest-build.py',D/'guest-runtime.py',D/'runtime-protocol.py',D/'build-worker.py',D/'seed.iso',B/'offline-runtime-proof-03.py']},'runtime_input_iso_sha256':'5fa2a4822e03ee7693c566e8670ddab5ee35c7a5d25d4671ac57c53ddf82c767','build_input_iso_sha256':'02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4'},indent=2)+'\n')
print('Generated fixed runtime proof inputs; no VM started')
