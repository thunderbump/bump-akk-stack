"""Add the signed, version-pinned system zlib development archive to separate media."""
import hashlib,json,shutil,subprocess,urllib.request
from pathlib import Path
B=Path(__file__).resolve().parent;old=B/'build-inputs-20260925-v2';new=B/'build-inputs-20260925-v3'
assert not new.exists()
assert shutil.disk_usage(B).free>180*1024**3
shutil.copytree(old,new,ignore=shutil.ignore_patterns('build-inputs.iso','sealed-bundle-proof.json','pkgcache.bin','srcpkgcache.bin','__pycache__'))
# Authenticate retained metadata before using it to select the additional archive.
subprocess.run(['/usr/bin/python3',str(new/'verify-ubuntu-inputs.py')],check=True)
index=new/'apt/state/lists/archive.ubuntu.com_ubuntu_dists_noble-updates_main_binary-amd64_Packages'
rows=[]
for paragraph in index.read_text().split('\n\n'):
 fields=dict(line.split(': ',1) for line in paragraph.splitlines() if ': ' in line and not line.startswith(' '))
 if fields.get('Package')=='zlib1g-dev':rows.append(fields)
assert len(rows)==1
row=rows[0]
assert row['Version']=='1:1.3.dfsg-3.1ubuntu2.2' and row['Architecture']=='amd64'
assert row['SHA256']=='e9152a08af21ab22bc99e8bfa98f1eb83955b2cc3653bcefecab394ecf9d1b63'
assert row['Depends']=='zlib1g (= 1:1.3.dfsg-3.1ubuntu2.2), libc6-dev | libc-dev'
url='https://archive.ubuntu.com/ubuntu/'+row['Filename'];dest=new/'apt/cache/archives'/(row['Package']+'_'+row['Version'].replace(':','%3a')+'_'+row['Architecture']+'.deb')
assert not dest.exists()
with urllib.request.urlopen(url,timeout=60) as response,dest.open('xb') as output:
 data=response.read(int(row['Size'])+1)
 assert len(data)==int(row['Size']) and hashlib.sha256(data).hexdigest()==row['SHA256']
 output.write(data)
subprocess.run(['/usr/bin/python3',str(new/'verify-ubuntu-inputs.py')],check=True)
contents=subprocess.check_output(['dpkg-deb','--contents',str(dest)],text=True)
assert './usr/lib/x86_64-linux-gnu/libz.so -> libz.so.1.3' in contents
assert './usr/lib/x86_64-linux-gnu/libz.a' in contents and './usr/include/zlib.h' in contents
(new/'evidence/zlib-development-contents.txt').write_text(contents)
# Avoid copied APT configuration referring back to earlier preparation directories.
for name in ['apt.conf','sources.list']:
 p=new/'apt'/name;p.write_text(p.read_text().replace(str(B/'build-inputs-20260925'),str(new)))
subprocess.run(['/usr/bin/python3',str(new/'seal-bundle.py')],check=True)
a=json.loads((old/'bundle-manifest.json').read_text());z=json.loads((new/'bundle-manifest.json').read_text());pa={r['path']:r for r in a['files']};pz={r['path']:r for r in z['files']}
added='debs/'+dest.name
assert set(pz)-set(pa)=={added} and not set(pa)-set(pz)
for path in pa:
 if path!='provenance/ubuntu-package-proof.json':assert pa[path]['sha256']==pz[path]['sha256'],path
(new/'revision.json').write_text(json.dumps({'previous_iso_sha256':'7bc933747f2d4a089129c0dde78355f53306939bee31eb206e29a2c7d3609145','change':'Add system zlib development package required by upstream tests plain -lz link. All prior payloads unchanged except package provenance.','added':{'package':row['Package'],'version':row['Version'],'architecture':row['Architecture'],'url':url,'bytes':int(row['Size']),'sha256':row['SHA256'],'depends':row['Depends']},'base_manifest_dependencies':{'zlib1g:amd64':'1:1.3.dfsg-3.1ubuntu2.2','libc6-dev:amd64':'2.39-0ubuntu8.9'},'scope':'Acquired archive inspected as data only; real guest installation/link probe and build remain pending.'},indent=2)+'\n')
print('v3 regression passed: only zlib1g-dev and package provenance added/changed')
