"""Authenticate retained Ubuntu metadata, then acquire the exact inert guest package closure."""
import hashlib,json,re,shutil,subprocess
from pathlib import Path
R=Path(__file__).resolve().parent;L=R/'apt/state/lists';key=R/'apt/ubuntu-archive-keyring.gpg'
plan=(R/'evidence/runtime-apt-plan.txt').read_text();wanted=dict(re.findall(r'^Inst (\S+) \((\S+)',plan,re.M));assert len(wanted)==15
packages={};metadata=[]
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
for suite in ['noble','noble-updates','noble-security']:
 prefix=f'archive.ubuntu.com_ubuntu_dists_{suite}_';release=L/(prefix+'InRelease')
 result=subprocess.run(['gpgv','--keyring',str(key),str(release)],capture_output=True,text=True,check=True)
 (R/'evidence'/f'{suite}-signature.txt').write_text(result.stdout+result.stderr)
 s=release.read_text();block=s.split('\nSHA256:\n',1)[1].split('\nSHA512:',1)[0]
 checks={v[2]:(v[0],int(v[1])) for l in block.splitlines() if len(v:=l.split())==3 and re.fullmatch('[0-9a-f]{64}',v[0])}
 metadata.append({'path':str(release.relative_to(R)),'sha256':sha(release),'bytes':release.stat().st_size,'signature_verified':True})
 for component in ['main','universe']:
  p=L/(prefix+component+'_binary-amd64_Packages');expected=checks[component+'/binary-amd64/Packages'];assert (sha(p),p.stat().st_size)==expected
  metadata.append({'path':str(p.relative_to(R)),'sha256':expected[0],'bytes':expected[1]})
  for para in p.read_text().split('\n\n'):
   d=dict(l.split(': ',1) for l in para.splitlines() if ': ' in l and not l.startswith(' '))
   if d.get('Package') in wanted and wanted[d['Package']]==d.get('Version'):
    if d['Package'] in packages:assert packages[d['Package']]['SHA256']==d['SHA256']
    d['signed_index']=str(p.relative_to(R));packages[d['Package']]=d
assert set(packages)==set(wanted)
size=sum(int(d['Size']) for d in packages.values());installed=sum(int(d['Installed-Size'])*1024 for d in packages.values())
assert size<512*1024**2 and installed<2*1024**3
(R/'evidence/package-size-admission.json').write_text(json.dumps({'compressed_bytes':size,'installed_bytes':installed,'count':len(packages),'host_free_bytes':shutil.disk_usage(R).free},indent=2)+'\n')
print('admitted',size,'compressed;',installed,'installed',flush=True)
for d in packages.values():
 assert shutil.disk_usage(R).free>180*1024**3
 dest=R/'apt/cache/archives'/Path(d['Filename']).name;assert not dest.exists()
 url='https://archive.ubuntu.com/ubuntu/'+d['Filename']
 subprocess.run(['curl','-fsSL','--proto','=https','--proto-redir','=https','--max-time','120','--max-filesize',d['Size'],'-o',str(dest),url],check=True)
 assert dest.stat().st_size==int(d['Size']) and sha(dest)==d['SHA256']
 fields=subprocess.check_output(['dpkg-deb','-f',str(dest),'Package','Version','Architecture'],text=True)
 actual=dict(l.split(': ',1) for l in fields.splitlines())
 assert all(actual[k]==d[k] for k in ['Package','Version','Architecture'])
 d['local_path']=str(dest.relative_to(R));d['url']=url
 print(d['Package'],d['Version'],flush=True)
(R/'evidence/runtime-package-proof.json').write_text(json.dumps({'signature_chain':'Ubuntu archive keyring -> retained InRelease -> package index SHA256 -> archive SHA256','keyring_sha256':sha(key),'metadata':metadata,'packages':list(packages.values()),'host_install':False,'guest_solver_install_pending':True},indent=2)+'\n')
