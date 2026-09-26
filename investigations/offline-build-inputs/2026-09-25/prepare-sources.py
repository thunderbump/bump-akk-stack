#!/usr/bin/env python3
"""Enumerate pinned inputs as data; hash-check copies/downloads without executing them."""
import hashlib,json,os,re,shutil,subprocess,sys,time,urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parent
EQ=Path('/home/bump/Projects/bump-eqemu/bump-EQEmu')
VP=EQ/'submodules/vcpkg'
SHA='d1ff36c6520ee43f1a656c03cd6425c2974a449e'
EQSHA='4aceae18b94ffaafc08e2b17bc41cd72c77f795d'
WSSHA='b9aeec6eaf3d5610503439b4fae3581d9aff08e8'
LIMIT=2*1024**3
MAXFILE=512*1024**2

def git(repo,*args):
 return subprocess.check_output(['git','-C',str(repo),*args],text=True)
def show(p):return git(VP,'show',SHA+':'+p)
def digest(p,alg='sha512'):
 with p.open('rb') as f:return hashlib.file_digest(f,alg).hexdigest()
def guard():
 total=sum(p.stat().st_size for p in ROOT.rglob('*') if p.is_file())
 if total>LIMIT or shutil.disk_usage(ROOT).free<180*1024**3:raise RuntimeError('Preparation cap or host reserve reached')
def platform(s):
 known={'!windows':True,'windows':False,'windows & !mingw':False,'!native & (arm64 | x64) & (!windows | mingw)':False,'!native & ((arm & !arm64) | x86) & (!windows | mingw)':False}
 if s not in known:raise ValueError('Unreviewed platform expression '+s)
 return known[s]
def enumerate_inputs():
 m=json.loads(git(EQ,'show',EQSHA+':vcpkg.json'));queue=list(m['dependencies']);seen=set();ports={};selected={}
 while queue:
  d=queue.pop(0);d={'name':d} if isinstance(d,str) else d
  if d.get('platform') and not platform(d['platform']):continue
  n=d['name'];key=(n,tuple(d.get('features',[])),d.get('default-features',True))
  if key in seen:continue
  seen.add(key);p=json.loads(show('ports/'+n+'/vcpkg.json'));ports[n]=p;queue.extend(p.get('dependencies',[]))
  features=list(d.get('features',[]))
  if d.get('default-features',True):
   for f in p.get('default-features',[]):
    if isinstance(f,str):features.append(f)
    elif not f.get('platform') or platform(f['platform']):features.append(f['name'])
  selected.setdefault(n,set()).update(features)
  for f in features:queue.extend(p.get('features',{}).get(f,{}).get('dependencies',[]))
 inputs=[];portrows=[]
 for n,p in sorted(ports.items()):
  version=next(p[k] for k in ['version','version-semver','version-date','version-string'] if k in p)
  portrows.append({'port':n,'version':version,'port_version':p.get('port-version',0),'features':sorted(selected[n])})
  txt=show('ports/'+n+'/portfile.cmake').replace('${VERSION}',version)
  for b in re.findall(r'vcpkg_from_github\((.*?)\n\)',txt,re.S):
   def field(k):
    match=re.search(r'^\s*'+k+r'\s+"?([^\s"]+)',b,re.M)
    if not match:raise ValueError((n,k))
    return match[1]
   repo,ref,h=field('REPO'),field('REF'),field('SHA512')
   assert '${' not in ref and re.fullmatch('[0-9a-f]{128}',h)
   filename=repo.replace('/','-')+'-'+ref.replace('/','_-')+'.tar.gz'
   inputs.append({'role':'port-source','port':n,'path':'downloads/'+filename,'url':f'https://github.com/{repo}/archive/{ref}.tar.gz','sha512':h,'authority':f'ports/{n}/portfile.cmake'})
  for b in re.findall(r'vcpkg_download_distfile\((.*?)\n\)',txt,re.S):
   def field(k):return re.search(r'^\s*'+k+r'\s+"?([^\s"]+)',b,re.M)[1]
   inputs.append({'role':'port-extra','port':n,'path':'downloads/'+field('FILENAME'),'url':field('URLS'),'sha512':field('SHA512'),'authority':f'ports/{n}/portfile.cmake'})
 for t in json.loads(show('scripts/vcpkg-tools.json'))['tools']:
  if t['name'] in ['cmake','ninja'] and t.get('os')=='linux' and t.get('arch') in ['amd64','x64']:
   inputs.append({'role':'portable-tool','name':t['name'],'path':'downloads/'+t['archive'],'url':t['url'],'sha512':t['sha512'],'authority':'scripts/vcpkg-tools.json'})
 meta=dict(l.split('=',1) for l in show('scripts/vcpkg-tool-metadata.txt').splitlines() if '=' in l)
 inputs.append({'role':'vcpkg-executable','path':'tools/vcpkg','url':f'https://github.com/microsoft/vcpkg-tool/releases/download/{meta["VCPKG_TOOL_RELEASE_TAG"]}/vcpkg-glibc','sha512':meta['VCPKG_GLIBC_SHA'],'authority':'scripts/vcpkg-tool-metadata.txt'})
 for x in inputs:
  assert re.fullmatch('[0-9a-f]{128}',x['sha512']) and '${' not in x['url']
  assert Path(x['path']).parts[0] in ['downloads','tools'] and '..' not in Path(x['path']).parts
 return {'status':'static-enumeration-not-solver-proof','eqemu_commit':EQSHA,'vcpkg_commit':SHA,'websocketpp_commit':WSSHA,'ports':portrows,'files':inputs}

def acquire(row):
 guard();dest=ROOT/row['path'];h=row['sha512'];cache=VP/'downloads'/dest.name
 if dest.exists():
  if digest(dest)!=h:raise RuntimeError('Existing output hash mismatch '+dest.name)
  origin='verified-existing-output'
 elif cache.is_file() and digest(cache)==h:
  shutil.copyfile(cache,dest);origin='verified-local-cache-copy'
 else:
  temp=dest.with_name(dest.name+'.partial');total=0
  try:
   with urllib.request.urlopen(row['url'],timeout=45) as r,temp.open('wb') as f:
    while b:=r.read(1024*1024):
     total+=len(b)
     if total>MAXFILE:raise RuntimeError('File cap exceeded')
     f.write(b);guard()
   if digest(temp)!=h:raise RuntimeError('Downloaded hash mismatch '+dest.name)
   temp.rename(dest);origin='downloaded-and-hash-verified'
  finally:
   if temp.exists():temp.unlink()
 if digest(dest)!=h:raise RuntimeError('Copy verification failed')
 row.update(bytes=dest.stat().st_size,sha256=digest(dest,'sha256'),acquisition=origin)
 print(dest.name,row['bytes'],origin,flush=True)

if __name__=='__main__':
 plan=enumerate_inputs();(ROOT/'static-input-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
 if '--acquire' in sys.argv:
  for row in plan['files']:
   acquire(row)
   (ROOT/'acquisition-progress.json').write_text(json.dumps(plan,indent=2)+'\n')
  (ROOT/'verified-downloads.json').write_text(json.dumps(plan,indent=2)+'\n')
 else:
  print('ports',len(plan['ports']),'files',len(plan['files']))
  print('cached_bytes',sum((VP/'downloads'/Path(r['path']).name).stat().st_size for r in plan['files'] if (VP/'downloads'/Path(r['path']).name).is_file()))
