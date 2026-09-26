"""Generate a fixed build adapter without changing earlier proof artifacts."""
import ast,hashlib,json,subprocess
from pathlib import Path
B=Path('/home/bump/.local/state/eqemu-vm-proof');D=B/'build-proof-inputs-v3'
base=(B/'lifetime-inputs/timeout-worker.py').read_text()
assert hashlib.sha256(base.encode()).hexdigest()=='02eb90d282721e45b82ed3d0c4ec20b48b4d2e92fb850979fe98e03064a6f27f'
config=json.loads((B/'first-trial-inputs/user-data').read_text().split('\n',1)[1])
config['write_files']=[{'path':'/opt/eqemu-proof/guest_build.py','permissions':'0700','content':(D/'guest.py').read_text()},{'path':'/opt/eqemu-proof/BUILD_GUEST_ONLY','content':'offline-build-v1\n'},{'path':'/etc/cloud/cloud.cfg.d/99-offline.cfg','content':'network: {config: disabled}\n'}]
config['runcmd']=[['systemctl','mask','--now','apt-daily.timer','apt-daily-upgrade.timer'],['python3','-I','/opt/eqemu-proof/guest_build.py']]
(D/'user-data').write_text('#cloud-config\n'+json.dumps(config,indent=2)+'\n');(D/'meta-data').write_text('instance-id: eqemu-build-proof-03\nlocal-hostname: eqemu-build\n')
if (D/'seed.iso').exists():(D/'seed.iso').unlink()
subprocess.run(['cloud-localds',str(D/'seed.iso'),str(D/'user-data'),str(D/'meta-data')],check=True)
seed=D/'seed.iso';seedsha=hashlib.sha256(seed.read_bytes()).hexdigest()
base=base.replace('Operator-owned, synthetic first-VM trial. No candidate or production inputs.', 'Operator-owned offline EQEmu build trial. Fixed source inputs; no production data.')
code=base.replace("ROOT=BASE/'lifetime-tests'/'timeout'","ROOT=BASE/'build-proof-03'/'build'").replace('eqemu-vm-lifetime-timeout.service','eqemu-vm-build-03-worker.service').replace('eqemuvmlifetimetimeout','eqemuvmbuild03worker').replace('eqemu-lt-timeout','eqemu-build-03').replace('RuntimeMaxSec=300','RuntimeMaxSec=17400')
code=code.replace("'lifetime-inputs/seed.iso',378880,'bb13fa13d45f6e5f459922b34a194694e312d33cb452629dae82446ff260193e'",f"'build-proof-inputs-v3/seed.iso',{seed.stat().st_size},'{seedsha}'")
code=code.replace("'first-trial-inputs/fixture.iso',73652224,'ade9896dc2b26c8c5a2b81838b4bfe5734b59eb8e69ccad0a0618167364ab3bd'","'build-inputs-20260925-v3/build-inputs.iso',469000192,'02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4'")
code=code.replace('GIB=1024**3',"CASE='build'\nGIB=1024**3").replace("'-p','MemoryMax=960M'","'-p','Slice=eqemuvmbuild03ctl.slice','-p','MemoryMax=960M'")
code=code.replace("'scope':'deliberately interrupted synthetic VM; never a successful workload'","'scope':'offline EQEmu build experiment; guest evidence remains untrusted'")
code=code.replace("SCRIPT.chmod(0o600)\n    # Copies","SCRIPT.chmod(0o600)\n    s['controller_sha256']=digest(SCRIPT);write_json(STATE,s)\n    # Copies")
a=code.index('        deadline=time.monotonic()+900;');z=code.index('    except Exception as exc:report',a)
code=code[:a]+'        collect_build(sock,s,report,cg)\n'+code[z:]
parser=(B/'pressure-inputs/evidence.py').read_text();parser=parser[parser.index('class EvidenceError'):parser.index('class SerialReader')]
idx=code.index('\ndef main():');code=code[:idx]+'\n'+parser+'\n'+(D/'host-transport.py').read_text()+code[idx:]
compile(code,str(D/'build-worker.py'),'exec');(D/'build-worker.py').write_text(code)
hash=hashlib.sha256(code.encode()).hexdigest()
suite=(B/'recovery-inputs/suite-template.py').read_text();tree=ast.parse(suite)
keep=['run','write','read','digest','properties','quiescent','wait_until','module','absent','validate_identity','ownership','release','controller_budget','stop']
header=suite[:suite.index('\ndef run')]
header=header.replace('Fixed synthetic recovery/concurrency proof.', 'Fixed offline EQEmu build proof.').replace('Owned synthetic recovery proof controllers','Owned offline build proof controllers')
header=header.replace("ROOT=BASE/'recovery-tests'","ROOT=BASE/'build-proof-03'").replace("/recovery-inputs'","/build-proof-inputs-v3'").replace('eqemu-vm-recovery-suite.service','eqemu-vm-build-03-suite.service').replace('eqemuvmrecoveryctl','eqemuvmbuild03ctl').replace("CASES=('supervisor','stale','io','left','right','third')","CASES=('build',)").replace('HASHES={}','HASHES='+repr({'build-worker.py':hash}))
funcs='\n\n'.join(ast.get_source_segment(suite,n) for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in keep)
full=header+'\n'+funcs+'\n\n'+(D/'suite-body.py').read_text()
compile(full,str(B/'offline-build-proof-v3.py'),'exec');(B/'offline-build-proof-v3.py').write_text(full)
(D/'generated-manifest.json').write_text(json.dumps({'worker_sha256':hash,'launcher_sha256':hashlib.sha256(full.encode()).hexdigest(),'seed_sha256':seedsha,'seed_bytes':seed.stat().st_size},indent=2)+'\n')
print((D/'generated-manifest.json').read_text())
