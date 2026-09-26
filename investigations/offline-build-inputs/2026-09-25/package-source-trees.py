#!/usr/bin/env python3
"""Package exact tracked source; verify registry bundle without host build execution."""
import hashlib,json,shutil,subprocess
from pathlib import Path
R=Path(__file__).resolve().parent
EQ=Path('/home/bump/Projects/bump-eqemu/bump-EQEmu')
plan=json.loads((R/'static-input-plan.json').read_text())
records=[]
for name,repo,sha in [('eqemu',EQ,plan['eqemu_commit']),('websocketpp',EQ/'submodules/websocketpp',plan['websocketpp_commit'])]:
 out=R/'sources'/f'{name}.tar.gz'
 subprocess.run(['git','-C',str(repo),'archive','--format=tar.gz','--output='+str(out),sha],check=True)
 records.append({'path':str(out.relative_to(R)),'commit':sha,'bytes':out.stat().st_size,'sha256':hashlib.file_digest(out.open('rb'),'sha256').hexdigest(),'recursive_submodules':'packaged separately'})
vp=EQ/'submodules/vcpkg';sha=plan['vcpkg_commit'];out=R/'sources/vcpkg.bundle'
assert subprocess.check_output(['git','-C',str(vp),'rev-parse','HEAD'],text=True).strip()==sha
subprocess.run(['git','-C',str(vp),'-c','pack.threads=1','bundle','create',str(out),'HEAD'],check=True)
check=R/'registry-check.git'
assert not check.exists()
subprocess.run(['git','clone','--bare',str(out),str(check)],check=True)
subprocess.run(['git','-C',str(check),'fsck','--full','--strict'],check=True)
assert not (check/'objects/info/alternates').exists()
verified=[]
for p in plan['ports']:
 n=p['port'];rel=f'versions/{n[0]}-/{n}.json'
 versions=json.loads(subprocess.check_output(['git','-C',str(check),'show',sha+':'+rel],text=True))['versions']
 found=[v for v in versions if v.get('port-version',0)==p['port_version'] and any(v.get(k)==p['version'] for k in ['version','version-date','version-semver','version-string'])]
 assert len(found)==1,(n,found)
 tree=found[0]['git-tree'];subprocess.run(['git','-C',str(check),'cat-file','-e',tree+'^{tree}'],check=True)
 verified.append({'port':n,'git_tree':tree})
records.append({'path':str(out.relative_to(R)),'commit':sha,'bytes':out.stat().st_size,'sha256':hashlib.file_digest(out.open('rb'),'sha256').hexdigest(),'independent_clone_fsck':'passed','versioned_port_trees':verified})
(R/'source-tree-proof.json').write_text(json.dumps(records,indent=2)+'\n')
# Only this invocation's owned verification clone is disposable.
shutil.rmtree(check)
print(json.dumps({'source_bytes':sum(r['bytes'] for r in records),'versioned_trees_checked':len(verified)}))
