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
    expected='04da930ff096d4f3daa81543092e14432c646db8a6b3de4f67e36531d8f792f4'
    p=BASE/'recovery-tests/suite-result.json';r=read(p)
    if digest(p)!=expected or r.get('suite_passed') is not True or r.get('cleanup',{}).get('complete') is not True or r['cleanup'].get('rescued'):raise RuntimeError('Prior isolation proof identity/success changed')

def setup():
    prerequisites()
    prior=BASE/'build-proof-01/suite-result.json';r=read(prior)
    if digest(prior)!='8fd0bbe67f3b4c81d06eb795286b6aaf819b087566aa48e581bf891253b5cf6e' or r.get('suite_passed') is not False or r.get('cleanup',{}).get('complete') is not True or r['cleanup'].get('rescued') or read(BASE/'build-proof-01/leases.json')['active'] or (BASE/'build-proof-01/build/data').exists():raise RuntimeError('Prior failed attempt cleanup/provenance changed')
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
