"""Resolve additional guest packages in an isolated APT state. No host installation."""
from pathlib import Path
import json,shutil,subprocess,os
R=Path(__file__).resolve().parent;B=R.parent/'build-inputs-20260925-v3';A=R/'apt'
assert not A.exists()
shutil.copytree(B/'apt',A,ignore=shutil.ignore_patterns('cache','log','lock','lock-frontend','partial'))
for p in ['cache/archives/partial','log','no-parts','no-sources']: (A/p).mkdir(parents=True,exist_ok=True)
for name in ['apt.conf','sources.list']:
 p=A/name;p.write_text(p.read_text().replace(str(B),str(R)))
# Overlay exact build package control records onto the preserved base-image manifest.
status={}
for block in (A/'guest-status').read_text().strip().split('\n\n'):
 package=next(l.split(': ',1)[1] for l in block.splitlines() if l.startswith('Package: '))
 status[package]=block
for p in sorted((B/'apt/cache/archives').glob('*.deb')):
 ctrl=subprocess.check_output(['dpkg-deb','-f',str(p)],text=True).strip()
 package=next(l.split(': ',1)[1] for l in ctrl.splitlines() if l.startswith('Package: '))
 status[package]=ctrl+'\nStatus: install ok installed'
(A/'guest-status').write_text('\n\n'.join(status.values())+'\n\n')
roots=['mariadb-server','mariadb-client','libdbi-perl','libdbd-mysql-perl','libjson-perl']
env={**os.environ,'APT_CONFIG':str(A/'apt.conf')}
cmd=['apt-get','-s','--no-remove','install',*roots]
p=subprocess.run(cmd,env=env,capture_output=True,text=True)
(R/'evidence/runtime-apt-plan.txt').write_text(p.stdout+p.stderr);print(p.stdout+p.stderr);p.check_returncode()
(R/'evidence/runtime-package-roots.json').write_text(json.dumps({'roots':roots,'build_bundle':'02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4','scope':'static solver on base placeholders plus exact build package control records; real guest preflight required'},indent=2)+'\n')
