"""Preserve v1 and add the single hash-pinned tool identified by attempt 01."""
import hashlib,importlib.util,json,shutil,subprocess
from pathlib import Path
B=Path(__file__).resolve().parent;old=B/'build-inputs-20260925';new=B/'build-inputs-20260925-v2'
assert not new.exists()
# All files copied belong to this experiment; neither v1 nor historical caches change.
shutil.copytree(old,new,ignore=shutil.ignore_patterns('build-inputs.iso','sealed-bundle-proof.json','pkgcache.bin','srcpkgcache.bin','__pycache__'))
spec=importlib.util.spec_from_file_location('acquire',new/'prepare-sources.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
row={'role':'portable-tool','name':'patchelf','path':'downloads/patchelf-0.15.5-x86_64.tar.gz','url':'https://github.com/NixOS/patchelf/releases/download/0.15.5/patchelf-0.15.5-x86_64.tar.gz','sha512':'1a638467dc71119d88657e83825bf9c4e65dbb2d3bbbd0267963a507e29429569dc7777490724928c86efc50af82d91b0163b29a09f8f99e62ebf6d9bb1567d2','authority':'scripts/cmake/vcpkg_find_acquire_program(PATCHELF).cmake'}
assert not (old/row['path']).exists(),'Expected the reproduced v1 input gap'
m.acquire(row)
for name in ['verified-downloads.json','static-input-plan.json']:
 p=new/name;d=json.loads(p.read_text());assert not any(x['path']==row['path'] for x in d['files']);d['files'].append(row);p.write_text(json.dumps(d,indent=2)+'\n')
subprocess.run(['/usr/bin/python3',str(new/'seal-bundle.py')],check=True)
(new/'revision.json').write_text(json.dumps({'previous_iso_sha256':'8c296a41d6a23d33985a4d820cab1727738155d1d2ad10e2583775597455cb9b','change':'Add missing pinned patchelf post-build tool; ports, OS packages and source commits unchanged','added':row},indent=2)+'\n')
# Regression at the input seam: all previous payload paths remain, exactly one is added.
a=json.loads((old/'bundle-manifest.json').read_text());z=json.loads((new/'bundle-manifest.json').read_text());pa={r['path']:r for r in a['files']};pz={r['path']:r for r in z['files']}
assert set(pz)-set(pa)=={row['path']} and not set(pa)-set(pz)
for path in pa:
 if path!='provenance/static-input-plan.json':assert pa[path]['sha256']==pz[path]['sha256'],path
print('v2 payload regression passed; original payloads unchanged except updated provenance')
