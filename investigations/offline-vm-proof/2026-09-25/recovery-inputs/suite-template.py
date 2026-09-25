#!/usr/bin/python3
"""Fixed synthetic recovery/concurrency proof. --check starts no VM; default needs sudo."""
import argparse,fcntl,hashlib,importlib.util,json,os,pathlib,shutil,signal,stat,subprocess,sys,time,uuid
P=pathlib.Path
BASE=P('/var/lib/eqemu-vm-proof');ROOT=BASE/'recovery-tests';SCRIPT=ROOT/'suite.py'
LOCAL=P('/home/bump/.local/state/eqemu-vm-proof/recovery-inputs')
UNIT='eqemu-vm-recovery-suite.service';CHILD='eqemu-vm-recovery-parent.service'
CTL='eqemuvmrecoveryctl.slice';CTLFILE=P('/run/systemd/system')/CTL
CTLTEXT='[Unit]\nDescription=Owned synthetic recovery proof controllers\nStopWhenUnneeded=yes\n[Slice]\nMemoryMax=1G\nMemorySwapMax=0\n'
CASES=('supervisor','stale','io','left','right','third')
HASHES={}
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


def capacity_required(pair,allocated=0):return (220*GIB-min(max(allocated,0),40*GIB),21*GIB) if pair else (180*GIB,15*GIB)


def admission_decision(ledger,case,free,mem,inodes,allocated=0):
    active=ledger['active'];pair=ledger['phase']=='pair';cap=2 if pair else 1
    if len(active)>=cap:raise RuntimeError('Worker admission cap reached')
    if case in active:raise RuntimeError('Worker already reserved')
    if (pair and case not in ['left','right','third']) or (not pair and case not in ['supervisor','stale','io']):raise RuntimeError('Case outside admitted phase')
    disk,ram=capacity_required(pair,allocated)
    if free<disk or mem<ram or inodes<1000000:raise RuntimeError('Fresh capacity check failed')
    return {'free_bytes':free,'mem_available':mem,'free_inodes':inodes,'required_disk':disk,'required_ram':ram,'reserved_count':len(active),'at':time.time()}


def admit(case):
    m=module(case)
    with (ROOT/'admission.lock').open('r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX);ledger=read(ROOT/'leases.json');allocated=0
        for active in ledger['active']:
            other=module(active);ownership(other)
            for name in ['root.raw','seed.iso','fixture.iso','io.raw']:
                p=other.DATA/name
                if p.exists():
                    st=p.lstat()
                    if not stat.S_ISREG(st.st_mode):raise RuntimeError('Unexpected allocated input type')
                    allocated+=st.st_blocks*512
        fs=os.statvfs('/var/lib');mem=int(next(l.split()[1] for l in P('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:')))*1024
        facts=admission_decision(ledger,case,fs.f_bavail*fs.f_frsize,mem,fs.f_favail,allocated)
        ledger['active'][case]={'state':'starting','name':m.NAME,'worker_sha256':HASHES[case+'-worker.py'],'admission':facts};write(ROOT/'leases.json',ledger)
        # A failure retains the reservation. Outer cleanup scans all fixed case roots.
        m.setup();s=m.state();ledger['active'][case].update(state='active',uuid=s['uuid']);write(ROOT/'leases.json',ledger)
    return m


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


def ready(m,minimum=1):
    def check():
        props=properties(m.UNIT)
        if quiescent(props):raise RuntimeError('Worker exited before readiness '+m.CASE)
        if props.get('Slice')!=CTL or props.get('MemoryMax')!=str(960*1024**2) or props.get('MemorySwapMax')!='0':raise RuntimeError('Worker controller limit mismatch')
        p=m.EVIDENCE/'report.json'
        if not p.exists():return False
        r=read(p)
        if r.get('pulse_count',0)<minimum:return False
        s=ownership(m)
        if r.get('uuid')!=s['uuid'] or r.get('checks',{}).get('host_pre_resume') is not True:raise RuntimeError('Readiness ownership mismatch')
        m.live(s);controller_budget();return r
    return wait_until(check,480,'ready '+m.CASE)


def stop(m):run(['systemctl','stop',m.UNIT],timeout=150)


def completed(m,success):
    props=wait_until(lambda:properties(m.UNIT) if quiescent(properties(m.UNIT)) else False,160,'cleanup '+m.CASE)
    s=ownership(m);r=read(m.EVIDENCE/'report.json');c=read(m.EVIDENCE/'cleanup.json')
    checks={'identity':r.get('uuid')==s['uuid']==c.get('uuid'),'ready':bool(r.get('ready_at')) and r.get('pulse_count',0)>0,
       'clean':c.get('complete') is True and c.get('readonly_inputs_unchanged') is True,
       'bounded_cleanup':0<=c.get('finished_at',0)-c.get('started_at',1)<=120,
       'absent':absent(m,s),'serial_bounded':0<(m.EVIDENCE/'serial.log').stat().st_size<=1024**2,
       'outcome':r.get('ok') is success and r.get('workload_ok') is success}
    if success:checks['service']=r.get('service_result')=='success' and props.get('Result')=='success'
    else:checks['service']=r.get('service_result')=='exit-code' and props.get('Result')=='exit-code' and r.get('error')=='Controller interrupted'
    result={'case':m.CASE,'case_passed':all(checks.values()),'checks':checks,'uuid':s['uuid'],'unit_properties':props,'report_sha256':digest(m.EVIDENCE/'report.json'),'cleanup_sha256':digest(m.EVIDENCE/'cleanup.json')}
    write(m.EVIDENCE/'case-result.json',result)
    if not result['case_passed']:raise RuntimeError('Case acceptance failed '+m.CASE)
    release(m);return result


def kill_exact(unit,field,script,mode,expected_pid=None):
    pid=int(properties(unit)[field])
    if pid<=1 or (expected_pid is not None and pid!=expected_pid):raise RuntimeError('No matching live injection target')
    fd=os.pidfd_open(pid)
    try:
        args=(P('/proc')/str(pid)/'cmdline').read_bytes().split(b'\0')
        if pid<=1 or str(script).encode() not in args or mode.encode() not in args or properties(unit)[field]!=str(pid):raise RuntimeError('Injection process identity mismatch')
        signal.pidfd_send_signal(fd,signal.SIGKILL)
    finally:os.close(fd)
    return pid


def child_supervise():
    admit('supervisor')
    while True:time.sleep(1)


def child_cleanup():
    m=module('supervisor');stop(m)
    receipt={'complete':absent(m,ownership(m)),'service_result':os.environ.get('SERVICE_RESULT'),'at':time.time()}
    write(ROOT/'child-cleanup.json',receipt)
    return 0 if receipt['complete'] else 1


def supervisor_case():
    run(['systemd-run','--quiet','--unit='+CHILD,'--service-type=exec','-p','Slice='+CTL,'-p','MemoryMax=64M','-p','MemorySwapMax=0','-p','TasksMax=32','-p','RuntimeMaxSec=700','-p','TimeoutStopSec=160','-p','KillMode=control-group','-p','StandardOutput=null','-p','StandardError=journal','-p','LogRateLimitBurst=20','-p','ExecStopPost=/usr/bin/python3 -I '+str(SCRIPT)+' --child-cleanup','/usr/bin/python3','-I',str(SCRIPT),'--child'])
    m=module('supervisor');wait_until(lambda:m.STATE.exists(),30,'child admission');before=ready(m)
    injection={'at':time.time(),'pid':kill_exact(CHILD,'MainPID',SCRIPT,'--child'),'worker_uuid':before['uuid'],'pulse_count':before['pulse_count']};write(ROOT/'supervisor-injection.json',injection)
    props=wait_until(lambda:properties(CHILD) if quiescent(properties(CHILD)) else False,180,'child stop')
    receipt=read(ROOT/'child-cleanup.json')
    if props.get('Result')!='signal' or props.get('ExecMainCode')!='2' or props.get('ExecMainStatus')!='9' or receipt.get('complete') is not True or receipt.get('service_result')!='signal':raise RuntimeError('Supervisor death acceptance failed')
    result=completed(m,False);result['supervisor_properties']=props;return result


def reconcile(m):
    s=ownership(m)
    if not quiescent(properties(m.UNIT)):raise RuntimeError('Recovery refuses active controller')
    if absent(m,s):
        c=read(m.EVIDENCE/'cleanup.json')
        if c.get('complete') is not True or c.get('uuid')!=s['uuid']:raise RuntimeError('Missing complete receipt')
        return {'changed':False,'uuid':s['uuid']}
    # The one permitted stale state is explicit: VM gone, owned scratch retained.
    m.wait_domain_absent(s['uuid'],2)
    if m.owned_pids(s):raise RuntimeError('Recovery refuses live QEMU')
    checkpoint=read(m.EVIDENCE/'cleanup-checkpoint.json')
    if checkpoint.get('uuid')!=s['uuid'] or checkpoint.get('domain_absent') is not True:raise RuntimeError('Recovery checkpoint mismatch')
    if not m.SLICEFILE.is_file() or m.SLICEFILE.is_symlink() or digest(m.SLICEFILE)!=s.get('slice_file_sha256'):raise RuntimeError('Recovery slice identity mismatch')
    marker=m.ROOT/'interrupt-cleanup.json'
    if read(marker)!={'uuid':s['uuid']}:raise RuntimeError('Recovery marker mismatch')
    saved=m.EVIDENCE/'pre-recovery';saved.mkdir(mode=0o755);saved.chmod(0o755)
    for name in ['report.json','cleanup-checkpoint.json','cleanup.json']:
        if (m.EVIDENCE/name).exists():shutil.copyfile(m.EVIDENCE/name,saved/name)
    marker.unlink()
    if m.cleanup(preserve_failed_outcome=True) or not absent(m,s):raise RuntimeError('Reconciliation cleanup failed')
    r=read(m.EVIDENCE/'report.json')
    if r.get('ok') is not False or r.get('workload_ok') is not False or r.get('reconciled') is not True:raise RuntimeError('Recovery changed failed outcome')
    return {'changed':True,'uuid':s['uuid']}


def stale_case():
    m=admit('stale');before=ready(m);s=ownership(m);write(m.ROOT/'interrupt-cleanup.json',{'uuid':s['uuid']})
    run(['systemctl','stop','--no-block',m.UNIT])
    checkpoint=m.EVIDENCE/'cleanup-checkpoint.json';wait_until(lambda:checkpoint.exists(),45,'cleanup checkpoint')
    mark=read(checkpoint)
    if mark.get('uuid')!=s['uuid'] or mark.get('domain_absent') is not True:raise RuntimeError('Wrong cleanup checkpoint')
    pid=kill_exact(m.UNIT,'ControlPID',m.SCRIPT,'--cleanup',mark['pid'])
    if pid!=mark['pid']:raise RuntimeError('Cleanup checkpoint PID mismatch')
    props=wait_until(lambda:properties(m.UNIT) if quiescent(properties(m.UNIT)) else False,30,'interrupted cleanup')
    if (m.EVIDENCE/'cleanup.json').exists() or absent(m,s) or not m.DATA.exists():raise RuntimeError('Interruption did not leave expected stale state')
    lease=read(ROOT/'leases.json')['active']['stale'];refusals=[]
    for key,value in [('uuid',str(uuid.uuid4())),('name','unowned-domain'),('profile','libvirt-unowned'),('controller_sha256','0'*64)]:
        damaged=dict(s);damaged[key]=value
        try:validate_identity(damaged,lease,m.NAME,HASHES['stale-worker.py'],digest(m.SCRIPT))
        except RuntimeError:refusals.append(key)
        else:raise RuntimeError('Damaged ownership accepted')
    first=reconcile(m);hashes={n:digest(m.EVIDENCE/n) for n in ['report.json','cleanup.json']};second=reconcile(m)
    if not first['changed'] or second['changed'] or hashes!={n:digest(m.EVIDENCE/n) for n in hashes}:raise RuntimeError('Reconciliation is not idempotent')
    cleanup=read(m.EVIDENCE/'cleanup.json');attempt=read(m.EVIDENCE/'report.json')
    if cleanup.get('readonly_inputs_unchanged') is not True or cleanup['finished_at']-cleanup['started_at']>120 or attempt.get('error')!='Controller interrupted':raise RuntimeError('Stale evidence acceptance failed')
    result={'case':'stale','case_passed':True,'uuid':s['uuid'],'killed_cleanup_pid':pid,'unit_properties':props,'refused_damaged_copies':refusals,'first_recovery':first,'second_recovery':second,'receipt_hashes_unchanged':True,'pre_injection_pulses':before['pulse_count']}
    write(m.EVIDENCE/'case-result.json',result);release(m);return result


def io_case():
    m=admit('io');ready(m)
    wait_until(lambda:quiescent(properties(m.UNIT)),180,'I/O workload finish')
    if read(m.EVIDENCE/'report.json').get('io_verified') is not True:raise RuntimeError('I/O was not verified')
    return completed(m,True)


def pair_case():
    ledger=read(ROOT/'leases.json')
    if ledger['active']:raise RuntimeError('Unreleased prior reservations')
    ledger['phase']='pair';write(ROOT/'leases.json',ledger)
    left=admit('left');a=ready(left);right=admit('right');b=ready(right)
    # Require fresh observations from both while both exact domains are live.
    a=ready(left,a['pulse_count']+1);b=ready(right,b['pulse_count']+1)
    left.live(ownership(left));right.live(ownership(right));controller_budget()
    if a['uuid']==b['uuid'] or a['qemu']['pid']==b['qemu']['pid'] or a['observations'][-1]['identity']==b['observations'][-1]['identity']:raise RuntimeError('Workers are not distinct')
    third=module('third');before_ledger=digest(ROOT/'leases.json')
    try:admit('third')
    except RuntimeError as exc:
        if str(exc)!='Worker admission cap reached':raise
        rejection=str(exc)
    else:raise RuntimeError('Third admission unexpectedly succeeded')
    if before_ledger!=digest(ROOT/'leases.json') or third.ROOT.exists() or properties(third.UNIT).get('LoadState')!='not-found' or third.virsh('domuuid',third.NAME,check=False).returncode==0:raise RuntimeError('Third admission allocated resources')
    stop(left);left_result=completed(left,False);after_cleanup=time.time();at_cleanup=read(right.EVIDENCE/'report.json')
    later=ready(right,at_cleanup['pulse_count']+3)
    if later['uuid']!=b['uuid'] or later['qemu']['pid']!=b['qemu']['pid'] or any(o['at']<=after_cleanup for o in later['observations']) or len({o['nonce'] for o in later['observations']})!=3:raise RuntimeError('Survivor observations invalid')
    if later['observations'][-1]['counter']<=b['observations'][-1]['counter']:raise RuntimeError('Survivor database stopped')
    write(right.ROOT/'finish-request.json',{'uuid':b['uuid']});wait_until(lambda:quiescent(properties(right.UNIT)),100,'right ordinary finish');right_result=completed(right,True)
    result={'case':'pair','case_passed':True,'same_endpoint':'172.29.31.2:8080','same_database':'/opt/eqemu-proof/world.db','left':left_result,'right':right_result,'third_rejection':rejection,'third_allocated':False,'survivor_observations':later['observations'],'left_cleanup_finished_at':after_cleanup,'shared_controller_budget':controller_budget()}
    write(ROOT/'pair-result.json',result);return result


def supervise():
    report={'suite_passed':False,'started_at':time.time(),'cases':[]};write(ROOT/'suite-result.json',report)
    def interrupted(*_):raise RuntimeError('Suite interrupted')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    try:
        controller_budget()
        for operation in [supervisor_case,stale_case,io_case,pair_case]:
            report['cases'].append(operation());write(ROOT/'suite-result.json',report)
        if read(ROOT/'leases.json')['active']:raise RuntimeError('Reservations remain')
        report['cases_passed']=True
    except Exception as exc:report['error']=str(exc)
    finally:report['finished_at']=time.time();write(ROOT/'suite-result.json',report)
    return 0 if report.get('cases_passed') else 1


def cleanup():
    receipt={'complete':False,'rescued':[],'started_at':time.time()}
    try:
        if not quiescent(properties(CHILD)):run(['systemctl','stop',CHILD],timeout=180)
        for case in CASES:
            m=module(case)
            if not m.ROOT.exists():continue
            s=m.state()
            if not quiescent(properties(m.UNIT)):stop(m)
            if not absent(m,s):
                # Emergency cleanup cannot turn a failed case into a suite pass.
                ownership(m);saved=m.EVIDENCE/'before-suite-rescue';saved.mkdir(mode=0o755);saved.chmod(0o755)
                for name in ['report.json','cleanup.json','cleanup-checkpoint.json']:
                    if (m.EVIDENCE/name).exists():shutil.copyfile(m.EVIDENCE/name,saved/name)
                marker=m.ROOT/'interrupt-cleanup.json'
                if marker.exists() or marker.is_symlink():
                    if read(marker)!={'uuid':s['uuid']}:raise RuntimeError('Rescue refuses mismatched marker')
                    marker.unlink()
                receipt['rescued'].append(case)
                if m.cleanup(preserve_failed_outcome=True):raise RuntimeError('Rescue cleanup failed '+case)
            if not absent(m,s):raise RuntimeError('Resources remain '+case)
            if case in read(ROOT/'leases.json')['active']:release(m)
        if read(ROOT/'leases.json')['active']:raise RuntimeError('Unresolved reservation; inspect retained state')
        receipt['controller_budget']=controller_budget()
        if CTLFILE.is_symlink() or CTLFILE.read_text()!=CTLTEXT:raise RuntimeError('Shared controller slice ownership mismatch')
        CTLFILE.unlink() # No reload: keep the loaded cap until this last service exits.
        receipt['controller_slice_file_removed']=True;receipt['complete']=True
    except Exception as exc:receipt['error']=str(exc)
    receipt['finished_at']=time.time();write(ROOT/'suite-cleanup.json',receipt)
    report=read(ROOT/'suite-result.json') if (ROOT/'suite-result.json').exists() else {}
    report.update(cleanup=receipt,service_result=os.environ.get('SERVICE_RESULT','unknown'))
    report['suite_passed']=report.get('cases_passed') is True and receipt['complete'] and not receipt['rescued'] and report['service_result']=='success'
    write(ROOT/'suite-result.json',report);return 0 if receipt['complete'] else 1


def prerequisites():
    required={'lifetime-tests':'b2447d85dc6eb5c829acf7ea57eac84ea0b62cc04a25551ef2d2680a16db0ce4',
              'pressure-tests':'f87ea68f19a679953ef40fa3762e25990b678cf330ded8d3aebe3513aabf6506'}
    for name,sha in required.items():
        path=BASE/name/'suite-result.json';r=read(path)
        if digest(path)!=sha or r.get('suite_passed') is not True or r.get('cleanup',{}).get('complete') is not True or r['cleanup'].get('rescued'):raise RuntimeError('Prior proof identity or success changed')
    return required


def setup():
    prerequisites()
    if ROOT.exists() or ROOT.is_symlink():raise RuntimeError('Retained suite exists; inspect rather than overwrite')
    for unit in [UNIT,CHILD]:
        if properties(unit).get('LoadState')!='not-found':raise RuntimeError('Suite unit already exists')
    props=properties(CTL)
    if CTLFILE.exists() or CTLFILE.is_symlink() or props.get('ActiveState')!='inactive' or props.get('FragmentPath') or props.get('DropInPaths') or props.get('Transient')!='no':raise RuntimeError('Controller slice already configured or used')
    m=module('supervisor',local=True);m.safe_dir(BASE);m.admission()
    for case in CASES:module(case,local=True)
    ROOT.mkdir(mode=0o755);ROOT.chmod(0o755);SCRIPT.write_bytes(P(__file__).read_bytes());SCRIPT.chmod(0o600)
    for case in CASES:
        name=case+'-worker.py';target=ROOT/name;target.write_bytes((LOCAL/name).read_bytes());target.chmod(0o600)
        if digest(target)!=HASHES[name]:raise RuntimeError('Worker changed while copying')
    write(ROOT/'leases.json',{'phase':'single','active':{},'released':[]});(ROOT/'admission.lock').touch(mode=0o600,exist_ok=False)
    with CTLFILE.open('x') as f:f.write(CTLTEXT)
    CTLFILE.chmod(0o644);run(['systemctl','daemon-reload'])
    try:
        run(['systemd-run','--quiet','--unit='+UNIT,'--service-type=exec','-p','Slice='+CTL,'-p','RuntimeMaxSec=3600','-p','TimeoutStopSec=600','-p','KillMode=control-group','-p','MemoryMax=64M','-p','MemorySwapMax=0','-p','TasksMax=64','-p','StandardOutput=null','-p','StandardError=journal','-p','LogRateLimitIntervalSec=30s','-p','LogRateLimitBurst=20','-p','ExecStopPost=/usr/bin/python3 -I '+str(SCRIPT)+' --cleanup','/usr/bin/python3','-I',str(SCRIPT),'--supervise'])
    except Exception:
        # Do not remove a slice if a timed-out start may have created a controller.
        if quiescent(properties(UNIT)) and not read(ROOT/'leases.json')['active'] and CTLFILE.read_text()==CTLTEXT:CTLFILE.unlink();run(['systemctl','daemon-reload'])
        raise
    print(json.dumps({'started':True,'unit':UNIT,'report':str(ROOT/'suite-result.json'),'cancel_command':'sudo systemctl stop '+UNIT}))


def main():
    parser=argparse.ArgumentParser(description=__doc__);group=parser.add_mutually_exclusive_group()
    for mode in ['check','supervise','cleanup','child','child-cleanup']:group.add_argument('--'+mode,action='store_true')
    args=parser.parse_args()
    if args.check:
        prerequisites()
        for case in CASES:
            module(case,local=True);run(['/usr/bin/python3','-I',str(LOCAL/(case+'-worker.py')),'--check'],timeout=60)
        print(json.dumps({'fixed_workers':True,'all_domain_schemas':True,'all_policy_syntax':True,'all_input_hashes':True,'vm_started':False}));return 0
    if os.geteuid()!=0:raise RuntimeError('sudo required to start the VM suite')
    os.umask(0o077)
    internal=args.supervise or args.cleanup or args.child or args.child_cleanup
    if internal:
        if P(__file__).resolve()!=SCRIPT:raise RuntimeError('Internal modes require root-owned suite')
        module('supervisor').safe_dir(ROOT)
        if args.supervise:return supervise()
        if args.cleanup:return cleanup()
        return child_supervise() if args.child else child_cleanup()
    setup();return 0

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:print(json.dumps({'error':str(exc)}),file=sys.stderr);sys.exit(1)
