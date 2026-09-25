import hashlib,json,os,pathlib,subprocess
P=pathlib.Path;D=P(__file__).parent
name='eqemuprtaskcheck.slice';unit='eqemu-pr-task-child-check.service'
path=P(os.environ['XDG_RUNTIME_DIR'])/'systemd/user'/name
content='[Unit]\nDescription=Owned EQEmu task-limit regression\n[Slice]\nTasksMax=16\nMemoryMax=64M\nMemorySwapMax=0\n'
def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True)
assert not path.exists()
props=dict(x.split('=',1) for x in run('systemctl','--user','show',name,'-p','ActiveState','-p','FragmentPath','-p','DropInPaths').stdout.splitlines())
assert props['ActiveState']=='inactive' and not props['FragmentPath'] and not props['DropInPaths']
path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content)
try:
 run('systemctl','--user','daemon-reload');run('systemctl','--user','start',name)
 group=run('systemctl','--user','show',name,'-p','ControlGroup','--value').stdout.strip();cg=P('/sys/fs/cgroup')/group.lstrip('/')
 before=int((cg/'pids.events').read_text().split()[1])
 result=run('systemd-run','--user','--quiet','--wait','--pipe','--unit='+unit,'--slice='+name,'--service-type=exec','-p','RuntimeMaxSec=30','-p','TimeoutStopSec=5','-p','TasksMax=infinity','/usr/bin/python3','-I',str(D/'task-probe.py'))
 report=json.loads(result.stdout);after=int((cg/'pids.events').read_text().split()[1])
 assert report['eagain'] and report['children']>0 and '/'+name+'/' in report['cgroup'] and after>before
 report['parent_pids_max']=(cg/'pids.max').read_text().strip();report['parent_events_delta']=after-before
 assert report['parent_pids_max']=='16'
finally:
 run('systemctl','--user','stop',name)
 assert path.read_text()==content;path.unlink();run('systemctl','--user','daemon-reload')
report['slice_file_removed']=not path.exists();report['cgroup_removed']=not cg.exists()
assert report['slice_file_removed'] and report['cgroup_removed']
(D/'task-control.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
