"""Check new media and isolated APT simulation; no host package installation."""
from pathlib import Path
import json,subprocess,os,re,ast
b=Path(__file__).resolve().parent;r=b/'build-inputs-20260925-v3'
idx=r/'apt/state/lists/archive.ubuntu.com_ubuntu_dists_noble-updates_main_binary-amd64_Packages'
block=next(x for x in idx.read_text().split('\n\n') if x.startswith('Package: zlib1g\n'))
parts=(r/'apt/guest-status').read_text().split('\n\n')
# The earlier manifest-derived placeholder omits dependency metadata. Use the
# signed stanza for this runtime in this simulation only; the guest uses real dpkg.
parts=[block+'\nStatus: install ok installed' if x.startswith('Package: zlib1g\n') else x for x in parts]
target=r/'apt/guest-status-zlib-metadata';target.write_text('\n\n'.join(parts))
p=json.loads((r/'ubuntu-package-proof.json').read_text())
run=subprocess.run(['apt-get','-s','--no-download','--no-remove','--no-install-recommends','-o','Dir::State::status='+str(target),'install',*[x['package']+'='+x['version'] for x in p['packages']]],env=dict(os.environ,APT_CONFIG=str(r/'apt/apt.conf')),capture_output=True,text=True)
(r/'evidence/apt-plan-v3-zlib-metadata.txt').write_text(run.stdout+run.stderr)
assert run.returncode==0,run.stdout+run.stderr
allowed={(x['package'],x['version']) for x in p['packages']}
for line in run.stdout.splitlines():
 assert not line.startswith('Remv '),line
 if line.startswith('Inst '):
  match=re.match(r'Inst (\S+)(?: \[[^]]+\])? \((\S+)',line);assert match and (match[1].split(':')[0],match[2]) in allowed,line
old=ast.parse((b/'build-proof-inputs-v2/build-worker.py').read_text());new=ast.parse((b/'build-proof-inputs-v3/build-worker.py').read_text())
names=['cleanup','prepare_disk','inspect_limits','owned_pids','wait_domain_absent','admission','policy']
for name in names:
 a=next(n for n in old.body if isinstance(n,ast.FunctionDef) and n.name==name);z=next(n for n in new.body if isinstance(n,ast.FunctionDef) and n.name==name);assert ast.dump(a)==ast.dump(z),name
receipt={'apt_simulation':'passed with manifest-derived status plus signed zlib stanza; real guest resolution still required','pinned_archives':len(p['packages']),'unchanged_worker_function_asts':names,'host_install':False,'vm_started':False}
(b/'build-proof-inputs-v3/revision-checks.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
