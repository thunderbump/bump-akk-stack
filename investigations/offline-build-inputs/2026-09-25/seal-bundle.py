#!/usr/bin/env python3
"""Seal hash-verified inert inputs in ISO media and verify every media payload."""
import hashlib,json,subprocess,tempfile
from pathlib import Path
R=Path(__file__).resolve().parent
D=json.loads((R/'verified-downloads.json').read_text());U=json.loads((R/'ubuntu-package-proof.json').read_text());S=json.loads((R/'source-tree-proof.json').read_text())
rows=[]
def add(local,media,role,origin=None):
 p=R/local;assert p.is_file() and not p.is_symlink()
 assert not Path(media).is_absolute() and '..' not in Path(media).parts
 with p.open('rb') as f:h=hashlib.file_digest(f,'sha256').hexdigest()
 rows.append({'path':media,'bytes':p.stat().st_size,'sha256':h,'role':role,'origin':origin,'local':local})
for f in D['files']:
 assert hashlib.file_digest((R/f['path']).open('rb'),'sha512').hexdigest()==f['sha512']
 add(f['path'],f['path'],f['role'],{'url':f['url'],'sha512':f['sha512'],'authority':f['authority']})
for f in S:
 assert hashlib.file_digest((R/f['path']).open('rb'),'sha256').hexdigest()==f['sha256']
 add(f['path'],f['path'],'source-tree',{'commit':f['commit']})
for f in U['packages']:
 assert hashlib.file_digest((R/f['path']).open('rb'),'sha256').hexdigest()==f['sha256']
 add(f['path'],'debs/'+Path(f['path']).name,'ubuntu-package',{'package':f['package'],'version':f['version'],'architecture':f['architecture'],'signed_index_matches':f['signed_index_matches']})
for f in U['indexes']+U['releases']:add(f['path'],'apt-lists/'+Path(f['path']).name,'ubuntu-metadata')
add('apt/ubuntu-archive-keyring.gpg','ubuntu-archive-keyring.gpg','ubuntu-keyring')
for f in ['ubuntu-package-proof.json','source-tree-proof.json','static-input-plan.json']:add(f,'provenance/'+f,'provenance')
assert len({f['path'] for f in rows})==len(rows)
manifest={'schema':1,'status':'prepared-unexecuted','target_triplet':'x64-linux','host_triplet':'x64-linux','base_image_sha256':'612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354','scope':'Static port enumeration and authenticated package acquisition; real guest solver, installation and offline build pending','files':[{k:v for k,v in f.items() if k!='local'} for f in rows]}
m=R/'bundle-manifest.json';m.write_text(json.dumps(manifest,indent=2)+'\n')
iso=R/'build-inputs.iso'
assert not iso.exists(),'Refuse replacing sealed media'
cmd=['genisoimage','-quiet','-R','-J','-V','EQEMUBUILD','-o',str(iso),'-graft-points','bundle-manifest.json='+str(m)]
cmd += [f['path']+'='+str(R/f['local']) for f in rows]
subprocess.run(cmd,check=True)
for f in rows+[{'path':'bundle-manifest.json','bytes':m.stat().st_size,'sha256':hashlib.file_digest(m.open('rb'),'sha256').hexdigest()}]:
 p=subprocess.Popen(['isoinfo','-R','-i',str(iso),'-x','/'+f['path']],stdout=subprocess.PIPE)
 h=hashlib.sha256();n=0
 while block:=p.stdout.read(1024*1024):h.update(block);n+=len(block)
 assert p.wait()==0 and h.hexdigest()==f['sha256'] and n==f['bytes'],f['path']
iso.chmod(0o444)
proof={'files_verified_from_media':len(rows)+1,'payload_bytes':sum(f['bytes'] for f in rows),'iso_bytes':iso.stat().st_size,'iso_sha256':hashlib.file_digest(iso.open('rb'),'sha256').hexdigest(),'manifest_sha256':hashlib.file_digest(m.open('rb'),'sha256').hexdigest(),'status':'prepared-unexecuted'}
(R/'sealed-bundle-proof.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof))
