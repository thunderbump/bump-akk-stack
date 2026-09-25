"""Unprivileged probe of the shared slice lifetime; no VM or system unit."""
import json,os,pathlib,subprocess,time,uuid
P=pathlib.Path
name='eqemuctlprobe'+uuid.uuid4().hex[:12];sl=name+'.slice';unit=name+'.service'
root=P(os.environ['XDG_RUNTIME_DIR'])/'systemd/user';root.mkdir(parents=True,exist_ok=True)
f=root/sl

def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True).stdout.strip()
try:
    with f.open('x') as out:out.write('[Unit]\nStopWhenUnneeded=yes\n[Slice]\nMemoryMax=1G\nMemorySwapMax=0\n')
    run('systemctl','--user','daemon-reload')
    run('systemd-run','--user','--quiet','--unit='+unit,'-p','Slice='+sl,'-p','RuntimeMaxSec=30','/usr/bin/sleep','20')
    group=run('systemctl','--user','show',sl,'-p','ControlGroup','--value');cg=P('/sys/fs/cgroup')/group.lstrip('/')
    assert group and (cg/'memory.max').read_text().strip()==str(1024**3)
    assert (cg/'memory.swap.max').read_text().strip()=='0'
    f.unlink()  # Keep loaded policy until the last child leaves, without reloading.
    assert (cg/'memory.max').read_text().strip()==str(1024**3)
    run('systemctl','--user','stop',unit)
    for _ in range(100):
        if not cg.exists():break
        time.sleep(.1)
    assert not cg.exists(),'Slice cgroup remains'
    result={'passed':True,'memory_max':1024**3,'swap_max':0,'policy_retained_until_exit':True,'cgroup_removed':True,'at':time.time()}
    print(json.dumps(result));(P(__file__).parent/'controller-slice-proof.json').write_text(json.dumps(result,indent=2)+'\n')
finally:
    subprocess.run(['systemctl','--user','stop',unit],capture_output=True)
    if f.exists():f.unlink()
    subprocess.run(['systemctl','--user','daemon-reload'],capture_output=True)
