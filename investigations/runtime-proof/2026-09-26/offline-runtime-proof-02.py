#!/usr/bin/python3
"""Fixed offline EQEmu build and runtime proof. --check starts no VM; default needs sudo."""
import argparse,fcntl,hashlib,importlib.util,json,os,pathlib,shutil,signal,stat,subprocess,sys,time,uuid
P=pathlib.Path
BASE=P('/var/lib/eqemu-vm-proof');ROOT=BASE/'runtime-proof-02';SCRIPT=ROOT/'suite.py'
LOCAL=P('/home/bump/.local/state/eqemu-vm-proof/runtime-proof-inputs-02')
UNIT='eqemu-vm-runtime-02-suite.service';CHILD='eqemu-vm-recovery-parent.service'
CTL='eqemuvmruntime02ctl.slice';CTLFILE=P('/run/systemd/system')/CTL
CTLTEXT='[Unit]\nDescription=Owned offline build proof controllers\nStopWhenUnneeded=yes\n[Slice]\nMemoryMax=1G\nMemorySwapMax=0\n'
CASES=('build',)
HASHES={'build-worker.py': 'b0ef913e5e086a8e006a8315176f803988a883ce04ee49112317d4f0774297d3'}
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}
GIB=1024**3


def run(args,timeout=30,check=True):
    r=subprocess.run(args,text=True,capture_output=True,timeout=timeout,env=ENV,cwd='/')
    if check and r.returncode:raise RuntimeError(str(args[:3])+': '+r.stderr[-4000:]+r.stdout[-1000:])
    return r

def write(path,value):
    tmp=path.with_suffix('.new');tmp.write_text(json.dumps(value,indent=2)+'\n');tmp.chmod(0o644);os.replace(tmp,path)

def read(path):
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or st.st_size>1024**2:raise RuntimeError('Unsafe evidence/control file '+str(path))
    return json.loads(path.read_text())

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def properties(unit):
    keys=['LoadState','ActiveState','SubState','MainPID','ControlPID','Result','ExecMainCode','ExecMainStatus','MemoryMax','MemorySwapMax','RuntimeMaxUSec','Slice','FragmentPath','DropInPaths','Transient']
    r=run(['systemctl','show',unit,*sum((['-p',k] for k in keys),[])])
    return dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)

def quiescent(props):return props.get('ActiveState') in ['inactive','failed'] and props.get('MainPID')==props.get('ControlPID')=='0'

def wait_until(check,seconds,description):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        result=check()
        if result:return result
        time.sleep(.5)
    raise RuntimeError('Deadline: '+description)

def module(case,local=False):
    if case not in CASES:raise RuntimeError('Unknown fixed case')
    path=(LOCAL if local else ROOT)/(case+'-worker.py')
    if path.is_symlink() or digest(path)!=HASHES[path.name]:raise RuntimeError('Worker identity mismatch')
    if not local:
        s=path.stat()
        if s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('Unsafe worker owner/mode')
    spec=importlib.util.spec_from_file_location('recovery_'+case,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def absent(m,s):
    if s['uuid'] in m.virsh('list','--all','--uuid').stdout.split():return False
    return (not m.owned_pids(s) and not m.DATA.exists() and not m.DATA.is_symlink()
      and not m.SLICEFILE.exists() and not m.SLICEFILE.is_symlink()
      and not P('/sys/fs/cgroup',m.SLICE).exists()
      and s['profile'] not in P('/sys/kernel/security/apparmor/profiles').read_text())

def validate_identity(s,lease,name,worker_hash,controller_hash):
    if not isinstance(s,dict) or not isinstance(lease,dict):raise RuntimeError('Ownership metadata missing')
    try:ident=str(uuid.UUID(s['uuid']))
    except (ValueError,KeyError,TypeError,AttributeError):raise RuntimeError('Invalid ownership UUID')
    if ident!=s['uuid'] or s.get('name')!=name or s.get('profile')!='libvirt-'+ident or s.get('controller_sha256')!=worker_hash or controller_hash!=worker_hash or lease.get('uuid')!=ident or lease.get('name')!=name or lease.get('worker_sha256')!=worker_hash or lease.get('state')!='active':raise RuntimeError('Ownership mismatch; retain resources')

def ownership(m):
    s=m.state();leases=read(ROOT/'leases.json');lease=leases['active'].get(m.CASE)
    st=m.SCRIPT.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise RuntimeError('Unsafe owned controller')
    validate_identity(s,lease,m.NAME,HASHES[m.CASE+'-worker.py'],digest(m.SCRIPT));return s

def release(m):
    s=ownership(m)
    if not quiescent(properties(m.UNIT)) or not absent(m,s):raise RuntimeError('Cannot release unclean worker reservation')
    receipt=read(m.EVIDENCE/'cleanup.json')
    if receipt.get('complete') is not True or receipt.get('uuid')!=s['uuid']:raise RuntimeError('Missing cleanup proof')
    with (ROOT/'admission.lock').open('r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX);ledger=read(ROOT/'leases.json');ledger['released'].append(ledger['active'].pop(m.CASE));write(ROOT/'leases.json',ledger)

def controller_budget():
    cg=P('/sys/fs/cgroup')/CTL
    limits={name:(cg/name).read_text().strip() for name in ['memory.max','memory.swap.max','memory.current','memory.peak','memory.events']}
    if limits['memory.max']!=str(GIB) or limits['memory.swap.max']!='0':raise RuntimeError('Shared controller budget mismatch')
    if int(dict(l.split() for l in limits['memory.events'].splitlines()).get('oom_kill',0)):raise RuntimeError('Controller pool OOM')
    return limits

def stop(m):run(['systemctl','stop',m.UNIT],timeout=150)

def admit():
    m=module('build')
    with (ROOT/'admission.lock').open('r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX);ledger=read(ROOT/'leases.json')
        if ledger['active']:raise RuntimeError('Build worker already reserved')
        if any(n.startswith('eqemu-') for n in m.virsh('list','--all','--name').stdout.splitlines()):raise RuntimeError('Another proof domain exists')
        facts=m.admission();ledger['active']['build']={'state':'starting','name':m.NAME,'worker_sha256':HASHES['build-worker.py'],'admission':facts};write(ROOT/'leases.json',ledger)
        m.setup();s=m.state();ledger['active']['build'].update(state='active',uuid=s['uuid']);write(ROOT/'leases.json',ledger)
    return m

def acceptance(r,c,props,s,resources_absent):
    checks={'identity':r.get('uuid')==s['uuid']==c.get('uuid'),
      'host_pre_resume':r.get('checks',{}).get('host_pre_resume') is True,
      'workload':r.get('workload_ok') is True and r.get('ok') is True,
      'service':r.get('service_result')=='success' and props.get('Result')=='success',
      'cleanup':c.get('complete') is True and c.get('readonly_inputs_unchanged') is True,
      'cleanup_time':0<=c.get('finished_at',0)-c.get('started_at',1)<=120,
      'absence':resources_absent is True,'quiescent':quiescent(props)}
    return {'case_passed':all(checks.values()),'checks':checks}

def supervise():
    report={'suite_passed':False,'cases_passed':False,'started_at':time.time()};write(ROOT/'suite-result.json',report)
    def interrupted(*_):raise RuntimeError('Supervisor interrupted')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    try:
        controller_budget();m=admit();deadline=time.monotonic()+17700
        while time.monotonic()<deadline:
            props=properties(m.UNIT)
            if quiescent(props):break
            if props.get('Slice')!=CTL or props.get('MemoryMax')!=str(960*1024**2) or props.get('MemorySwapMax')!='0':raise RuntimeError('Worker controller budget mismatch')
            controller_budget();time.sleep(2)
        else:raise RuntimeError('Build worker deadline')
        s=ownership(m);r=read(m.EVIDENCE/'report.json');c=read(m.EVIDENCE/'cleanup.json')
        result=acceptance(r,c,props,s,absent(m,s));result.update(report_sha256=digest(m.EVIDENCE/'report.json'),cleanup_sha256=digest(m.EVIDENCE/'cleanup.json'))
        write(ROOT/'case-result.json',result);report['case']=result
        if not result['case_passed']:raise RuntimeError('Build attempt failed; inspect worker evidence')
        release(m);report['cases_passed']=True
    except Exception as e:report['error']=str(e)
    finally:report['finished_at']=time.time();write(ROOT/'suite-result.json',report)
    return 0 if report['cases_passed'] else 1

def cleanup():
    receipt={'complete':False,'rescued':[],'started_at':time.time()}
    try:
        m=module('build')
        if m.ROOT.exists():
            if not quiescent(properties(m.UNIT)):stop(m)
            s=m.state()
            if not absent(m,s):
                ownership(m)
                saved=m.EVIDENCE/'before-suite-rescue';saved.mkdir(mode=0o755);saved.chmod(0o755)
                for name in ['report.json','cleanup.json']:
                    if (m.EVIDENCE/name).exists():shutil.copyfile(m.EVIDENCE/name,saved/name)
                receipt['rescued'].append('build')
                if m.cleanup(preserve_failed_outcome=True):raise RuntimeError('Rescue failed')
            if not absent(m,s):raise RuntimeError('Owned resources remain')
            if 'build' in read(ROOT/'leases.json')['active']:release(m)
        if read(ROOT/'leases.json')['active']:raise RuntimeError('Unreleased reservation')
        receipt['controller_budget']=controller_budget()
        if CTLFILE.is_symlink() or CTLFILE.read_text()!=CTLTEXT:raise RuntimeError('Controller slice identity changed')
        CTLFILE.unlink();receipt['complete']=True
    except Exception as e:receipt['error']=str(e)
    receipt['finished_at']=time.time();write(ROOT/'suite-cleanup.json',receipt)
    r=read(ROOT/'suite-result.json') if (ROOT/'suite-result.json').exists() else {}
    r.update(cleanup=receipt,service_result=os.environ.get('SERVICE_RESULT','unknown'))
    r['suite_passed']=r.get('cases_passed') is True and receipt['complete'] and not receipt['rescued'] and r['service_result']=='success'
    write(ROOT/'suite-result.json',r);return 0 if receipt['complete'] else 1

def prerequisites():
    previous=BASE/'runtime-proof-01';r=read(previous/'suite-result.json')
    if digest(previous/'suite-result.json')!='fdbfd9aca8cec421c69087ec39a81980ba7a5ad54bca56f217169bf76a0b0c4c' or r.get('suite_passed') is not False or r.get('cleanup',{}).get('complete') is not True or r['cleanup'].get('rescued') or read(previous/'leases.json')['active'] or (previous/'build/data').exists():raise RuntimeError('Prior failed runtime attempt evidence or cleanup changed')
    if digest(previous/'build/evidence/report.json')!='08950d5200fcdd57300f62515f8e8dd3d5d3dcd3c3f8089a1fb7abd49f62667a' or digest(previous/'build/evidence/cleanup.json')!='14dbd5a4aa91318a9207ec25abe68c5ff08c3799d4063ac5f9bdcac71834cf43':raise RuntimeError('Prior runtime receipts changed')
    expected='04da930ff096d4f3daa81543092e14432c646db8a6b3de4f67e36531d8f792f4'
    p=BASE/'recovery-tests/suite-result.json';r=read(p)
    if digest(p)!=expected or r.get('suite_passed') is not True or r.get('cleanup',{}).get('complete') is not True or r['cleanup'].get('rescued'):raise RuntimeError('Prior isolation proof identity/success changed')

def setup():
    prerequisites()
    prior=BASE/'build-proof-04/suite-result.json';r=read(prior)
    if digest(prior)!='b6f4d0f6dc83b1f4dc1aedcdd0e19a3e6629ea96da8a6262d977d83ee3980bc9' or r.get('suite_passed') is not True or r.get('cleanup',{}).get('complete') is not True or r['cleanup'].get('rescued') or read(BASE/'build-proof-04/leases.json')['active'] or (BASE/'build-proof-04/build/data').exists():raise RuntimeError('Prior successful attempt cleanup/provenance changed')
    if ROOT.exists() or ROOT.is_symlink():raise RuntimeError('Retained attempt exists; inspect rather than overwrite')
    if properties(UNIT).get('LoadState')!='not-found':raise RuntimeError('Suite unit exists')
    props=properties(CTL)
    if CTLFILE.exists() or CTLFILE.is_symlink() or props.get('ActiveState')!='inactive' or props.get('FragmentPath') or props.get('DropInPaths') or props.get('Transient')!='no':raise RuntimeError('Controller slice exists')
    m=module('build',local=True);m.safe_dir(BASE);m.admission()
    ROOT.mkdir(mode=0o755);ROOT.chmod(0o755);SCRIPT.write_bytes(P(__file__).read_bytes());SCRIPT.chmod(0o600)
    target=ROOT/'build-worker.py';target.write_bytes((LOCAL/'build-worker.py').read_bytes());target.chmod(0o600)
    if digest(target)!=HASHES['build-worker.py']:raise RuntimeError('Worker changed during copy')
    write(ROOT/'leases.json',{'active':{},'released':[]});(ROOT/'admission.lock').touch(mode=0o600,exist_ok=False)
    with CTLFILE.open('x') as f:f.write(CTLTEXT)
    CTLFILE.chmod(0o644);run(['systemctl','daemon-reload'])
    try:
        run(['systemd-run','--quiet','--unit='+UNIT,'--service-type=exec','-p','Slice='+CTL,'-p','RuntimeMaxSec=18000','-p','TimeoutStopSec=300','-p','KillMode=control-group','-p','MemoryMax=64M','-p','MemorySwapMax=0','-p','TasksMax=64','-p','StandardOutput=null','-p','StandardError=journal','-p','LogRateLimitIntervalSec=30s','-p','LogRateLimitBurst=20','-p','ExecStopPost=/usr/bin/python3 -I '+str(SCRIPT)+' --cleanup','/usr/bin/python3','-I',str(SCRIPT),'--supervise'])
    except Exception:
        if quiescent(properties(UNIT)) and not read(ROOT/'leases.json')['active'] and CTLFILE.read_text()==CTLTEXT:CTLFILE.unlink();run(['systemctl','daemon-reload'])
        raise
    print(json.dumps({'started':True,'unit':UNIT,'report':str(ROOT/'suite-result.json'),'progress':str(ROOT/'build/evidence/report.json'),'cancel_command':'sudo systemctl stop '+UNIT}))

def main():
    parser=argparse.ArgumentParser(description=__doc__);group=parser.add_mutually_exclusive_group()
    for n in ['check','supervise','cleanup']:group.add_argument('--'+n,action='store_true')
    a=parser.parse_args()
    if a.check:
        prerequisites();module('build',local=True);run(['/usr/bin/python3','-I',str(LOCAL/'build-worker.py'),'--check'],timeout=90)
        print(json.dumps({'inputs_and_worker_verified':True,'vm_started':False}));return 0
    if os.geteuid()!=0:raise RuntimeError('sudo required to start the offline VM build')
    os.umask(0o077)
    if a.supervise or a.cleanup:
        if P(__file__).resolve()!=SCRIPT:raise RuntimeError('Internal modes require root-owned copied launcher')
        module('build').safe_dir(ROOT);return supervise() if a.supervise else cleanup()
    setup();return 0

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as e:print(json.dumps({'error':str(e)}),file=sys.stderr);sys.exit(1)
