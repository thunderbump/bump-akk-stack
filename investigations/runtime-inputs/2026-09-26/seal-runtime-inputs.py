"""Seal inert runtime inputs and independently hash every ISO payload without mounting it."""
import hashlib,json,shutil,subprocess
from pathlib import Path
R=Path(__file__).resolve().parent
assert shutil.disk_usage(R).free>180*1024**3
rows=[]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def add(local,path,role):
 p=R/local;assert p.is_file() and not p.is_symlink()
 assert not Path(path).is_absolute() and '..' not in Path(path).parts
 rows.append({'path':path,'bytes':p.stat().st_size,'sha256':sha(p),'role':role,'local':local})
for d in json.loads((R/'evidence/public-downloads.json').read_text()):
 assert sha(R/d['path'])==d['sha256'] and (R/d['path']).stat().st_size==d['bytes']
 name=Path(d['path']).name
 if name.endswith('.zip'):path='database/'+name
 elif name.endswith('.gz'):path='quests/'+name
 else:path='maps/'+{'map':'base','nav':'nav','wtr':'water'}[name.rsplit('.',1)[1]]+'/'+name
 add(d['path'],path,'public-fixture')
u=json.loads((R/'evidence/runtime-package-proof.json').read_text())
for p in u['packages']:
 assert sha(R/p['local_path'])==p['SHA256']
 add(p['local_path'],'debs/'+Path(p['local_path']).name,'guest-package')
for m in u['metadata']:
 assert sha(R/m['path'])==m['sha256']
 add(m['path'],'apt-lists/'+Path(m['path']).name,'signed-package-metadata')
add('apt/ubuntu-archive-keyring.gpg','ubuntu-archive-keyring.gpg','ubuntu-keyring')
for p in (R/'media').rglob('*'):
 if p.is_file():add(str(p.relative_to(R)),str(p.relative_to(R/'media')),'runtime-data')
for name in ['public-downloads.json','database-inspection.json','quest-inspection.json','opcode-inspection.json','runtime-package-proof.json','runtime-apt-plan.txt','runtime-package-roots.json','package-size-admission.json']:
 add('evidence/'+name,'provenance/'+name,'provenance')
assert len(rows)==len({r['path'] for r in rows})
manifest={'schema':1,'status':'prepared-unexecuted','scope':'public input integrity and static inventory only; not runtime acceptance','requires_build_iso_sha256':'02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4','files':[{k:v for k,v in row.items() if k!='local'} for row in rows]}
m=R/'runtime-bundle-manifest.json';assert not m.exists();m.write_text(json.dumps(manifest,indent=2)+'\n')
iso=R/'runtime-inputs.iso';assert not iso.exists()
cmd=['genisoimage','-quiet','-R','-J','-V','EQEMURUNTIME','-o',str(iso),'-graft-points','runtime-bundle-manifest.json='+str(m)]
subprocess.run(cmd+[row['path']+'='+str(R/row['local']) for row in rows],check=True)
for row in rows+[{'path':m.name,'bytes':m.stat().st_size,'sha256':sha(m)}]:
 process=subprocess.Popen(['isoinfo','-R','-i',str(iso),'-x','/'+row['path']],stdout=subprocess.PIPE)
 h=hashlib.sha256();n=0
 while chunk:=process.stdout.read(1024*1024):h.update(chunk);n+=len(chunk)
 assert process.wait()==0 and h.hexdigest()==row['sha256'] and n==row['bytes'],row['path']
iso.chmod(0o444);m.chmod(0o444)
proof={'status':'prepared-unexecuted','iso_bytes':iso.stat().st_size,'iso_sha256':sha(iso),'manifest_sha256':sha(m),'files_verified_from_media':len(rows)+1,'payload_bytes':sum(r['bytes'] for r in rows),'host_free_bytes':shutil.disk_usage(R).free,'production_access':False,'host_execution_of_acquired_content':False}
(R/'sealed-runtime-proof.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
