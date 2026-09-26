"""Bounded HTTPS downloads. Never execute fetched content."""
import hashlib,json,urllib.request,shutil,subprocess
from pathlib import Path
R=Path(__file__).resolve().parent
rows=[]
def get(url,name,cap,exact=None,gitsha=None):
 assert shutil.disk_usage(R).free>180*1024**3
 p=R/'downloads'/name;assert not p.exists();h=hashlib.sha256();n=0
 subprocess.run(['curl','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-time','180','--max-filesize',str(cap),'--output',str(p),url],check=True)
 n=p.stat().st_size;assert n<=cap
 with p.open('rb') as source:
  while b:=source.read(1024*1024):h.update(b)
 if exact is not None:assert n==exact
 if gitsha:
  raw=p.read_bytes();assert hashlib.sha1(b'blob '+str(n).encode()+b'\0'+raw).hexdigest()==gitsha
 rows.append({'url':url,'path':str(p.relative_to(R)),'bytes':n,'sha256':h.hexdigest(),'git_blob':gitsha})
 (R/'evidence/public-downloads.json').write_text(json.dumps(rows,indent=2)+'\n')
 print(name,n,h.hexdigest(),flush=True)
get('https://db.eqemu.dev/api/v1/dump/archive/peq-1787356814.zip','peq-1787356814.zip',64*1024**2,32153606)
get('https://codeload.github.com/ProjectEQ/projecteqquests/tar.gz/b3e34b84457d570401ea954ddd66de19179d0e41','quests-b3e34b8.tar.gz',32*1024**2)
for row in json.loads((R/'evidence/map-tree.json').read_text())['tree']:
 if row['path'] in ['base/poknowledge.map','water/poknowledge.wtr','nav/poknowledge.nav']:
  get('https://raw.githubusercontent.com/EQEmu/maps/e8efa8ed4f4ea4c434c03c40d2a758388a54f4d6/'+row['path'],Path(row['path']).name,2*1024**2,row['size'],row['sha'])
