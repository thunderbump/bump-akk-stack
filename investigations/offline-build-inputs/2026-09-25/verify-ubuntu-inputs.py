#!/usr/bin/env python3
"""Verify archive signatures, package indexes, and each acquired .deb as inert data."""
import hashlib,json,re,shutil,subprocess
from pathlib import Path
R=Path(__file__).resolve().parent;L=R/'apt/state/lists';key=R/'apt/ubuntu-archive-keyring.gpg'
shutil.copyfile('/usr/share/keyrings/ubuntu-archive-keyring.gpg',key)
packages={}
for f in sorted((R/'apt/cache/archives').glob('*.deb')):
 fields=subprocess.check_output(['dpkg-deb','-f',str(f),'Package','Version','Architecture'],text=True)
 d=dict(l.split(': ',1) for l in fields.splitlines());identity=(d['Package'],d['Version'],d['Architecture'])
 assert identity not in packages
 packages[identity]={'package':identity[0],'version':identity[1],'architecture':identity[2],'path':str(f.relative_to(R)),'bytes':f.stat().st_size,'sha256':hashlib.file_digest(f.open('rb'),'sha256').hexdigest(),'signed_index_matches':[]}
indexes=[];releases=[]
for suite in ['noble','noble-updates','noble-security']:
 prefix=f'archive.ubuntu.com_ubuntu_dists_{suite}_';release=L/(prefix+'InRelease')
 result=subprocess.run(['gpgv','--keyring',str(key),str(release)],capture_output=True,text=True,check=True)
 (R/'evidence'/f'{suite}-signature.txt').write_text(result.stdout+result.stderr)
 text=release.read_text();block=text.split('\nSHA256:\n',1)[1].split('\nSHA512:',1)[0]
 checks={parts[2]:(parts[0],int(parts[1])) for l in block.splitlines() if len(parts:=l.split())==3 and re.fullmatch('[0-9a-f]{64}',parts[0])}
 releases.append({'suite':suite,'path':str(release.relative_to(R)),'sha256':hashlib.file_digest(release.open('rb'),'sha256').hexdigest(),'signature':'verified','date':re.search(r'^Date: (.+)',text,re.M)[1],'valid_until':(re.search(r'^Valid-Until: (.+)',text,re.M) or [None,None])[1]})
 for component in ['main','universe']:
  f=L/(prefix+component+'_binary-amd64_Packages');raw=f.read_bytes()
  expected=checks[component+'/binary-amd64/Packages']
  assert (hashlib.sha256(raw).hexdigest(),len(raw))==expected
  indexid=f'{suite}/{component}/binary-amd64/Packages'
  indexes.append({'id':indexid,'path':str(f.relative_to(R)),'sha256':expected[0],'bytes':expected[1]})
  for paragraph in raw.decode().split('\n\n'):
   d=dict(l.split(': ',1) for l in paragraph.splitlines() if ': ' in l and not l.startswith(' '))
   identity=(d.get('Package'),d.get('Version'),d.get('Architecture'))
   if identity in packages:
    p=packages[identity]
    assert p['sha256']==d['SHA256'] and p['bytes']==int(d['Size']),identity
    p['signed_index_matches'].append({'index':indexid,'archive_path':d['Filename']})
for p in packages.values():assert p['signed_index_matches'],p['package']
proof={'guest_resolution':'manifest-derived placeholders; real guest solver and installation pending','host_install':False,'keyring_sha256':hashlib.file_digest(key.open('rb'),'sha256').hexdigest(),'releases':releases,'indexes':indexes,'packages':list(packages.values())}
(R/'ubuntu-package-proof.json').write_text(json.dumps(proof,indent=2)+'\n')
print(json.dumps({'packages':len(packages),'download_bytes':sum(p['bytes'] for p in packages.values()),'signed_indexes':len(indexes)}))
