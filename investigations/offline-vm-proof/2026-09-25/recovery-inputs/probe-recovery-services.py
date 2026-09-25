"""Exercise systemd supervisor-death and cleanup-interruption mechanics as the user."""
import json,os,pathlib,signal,subprocess,tempfile,time,uuid
P=pathlib.Path
prefix='eqemurecoveryprobe'+uuid.uuid4().hex[:10];worker=prefix+'w.service';parent=prefix+'p.service';stale=prefix+'s.service'
units=[worker,parent,stale]

def run(args,check=True):
    r=subprocess.run(args,text=True,capture_output=True,timeout=20)
    if check and r.returncode:raise RuntimeError(r.stderr)
    return r.stdout.strip()

def props(unit):return dict(l.split('=',1) for l in run(['systemctl','--user','show',unit,'-p','ActiveState','-p','MainPID','-p','ControlPID','-p','Result','-p','ExecMainCode','-p','ExecMainStatus']).splitlines())
def wait(check):
    end=time.monotonic()+15
    while time.monotonic()<end:
        v=check()
        if v:return v
        time.sleep(.1)
    raise RuntimeError('Probe wait deadline')
def quiet(unit):
    p=props(unit);return p if p['ActiveState'] in ['failed','inactive'] and p['MainPID']==p['ControlPID']=='0' else False

def start(unit,script,mode,post):
    run(['systemd-run','--user','--quiet','--unit='+unit,'--service-type=exec','-p','MemoryMax=32M','-p','MemorySwapMax=0','-p','RuntimeMaxSec=30','-p','TimeoutStopSec=15','-p','ExecStopPost=/usr/bin/python3 '+str(script)+' '+post,'/usr/bin/python3',str(script),mode])

def kill(unit,field):
    pid=int(props(unit)[field]);assert pid>1;fd=os.pidfd_open(pid)
    try:signal.pidfd_send_signal(fd,signal.SIGKILL)
    finally:os.close(fd)

with tempfile.TemporaryDirectory(prefix='eqemu-recovery-services-') as temp:
    root=P(temp);script=root/'child.py'
    script.write_text('''import os,pathlib,signal,subprocess,sys,time
root=pathlib.Path(__file__).parent
mode=sys.argv[1]
if mode=='worker':
    signal.signal(signal.SIGTERM,lambda *_:sys.exit(1))
    (root/'ready').write_text('yes')
    while True:time.sleep(1)
elif mode=='parent':
    while True:time.sleep(1)
elif mode=='worker-clean':(root/'worker-clean').write_text(os.environ.get('SERVICE_RESULT',''))
elif mode=='parent-clean':
    subprocess.run(['systemctl','--user','stop',WORKER],check=True)
    (root/'parent-clean').write_text(os.environ.get('SERVICE_RESULT',''))
elif mode=='barrier':
    (root/'checkpoint').write_text(str(os.getpid()))
    while True:time.sleep(1)
'''.replace('WORKER',repr(worker)))
    try:
        start(worker,script,'worker','worker-clean');wait(lambda:(root/'ready').exists())
        start(parent,script,'parent','parent-clean');kill(parent,'MainPID');p=wait(lambda:quiet(parent));w=wait(lambda:quiet(worker))
        assert p['Result']=='signal' and p['ExecMainCode']=='2' and p['ExecMainStatus']=='9',p
        assert (root/'parent-clean').read_text()=='signal'
        assert w['Result']=='exit-code' and (root/'worker-clean').read_text()=='exit-code',w
        start(stale,script,'parent','barrier');run(['systemctl','--user','stop','--no-block',stale]);wait(lambda:(root/'checkpoint').exists())
        assert props(stale)['ControlPID']==(root/'checkpoint').read_text()
        kill(stale,'ControlPID');s=wait(lambda:quiet(stale))
        result={'passed':True,'supervisor':p,'worker':w,'interrupted_cleanup':s,'at':time.time()}
        (P(__file__).parent/'recovery-services-proof.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
    finally:
        for unit in units:
            run(['systemctl','--user','stop',unit],check=False);run(['systemctl','--user','reset-failed',unit],check=False)
