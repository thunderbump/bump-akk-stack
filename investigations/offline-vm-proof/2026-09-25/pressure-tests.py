#!/usr/bin/python3
"""Fixed synthetic VM lifetime suite. --check is read-only; default needs sudo."""
import argparse, hashlib, importlib.util, json, os, pathlib, shutil, signal, stat, subprocess, sys, time
P=pathlib.Path
BASE=P('/var/lib/eqemu-vm-proof')
ROOT=BASE/'pressure-tests'
SCRIPT=ROOT/'suite.py'
LOCAL=P('/home/bump/.local/state/eqemu-vm-proof/pressure-inputs')
UNIT='eqemu-vm-pressure-suite.service'
CASES=('resources', 'oom', 'tasks', 'malformed', 'oversized', 'duplicate', 'forged', 'flood')
HASHES={
  "resources-worker.py": "e84768ff56690e83c59f1d42d9e51c9ba1e0d3e0cf271b042127c070bc754c84",
  "oom-worker.py": "0dfd5ed3c9a2da25204f7292c6832da9e2f99be9b409e823c7fcd94d24bec79c",
  "tasks-worker.py": "6da305112ee2bef74a9f2e96fb72305fb6cb38065c7584a6b7fd7a43f2f32b3c",
  "malformed-worker.py": "c0cfa79695a6c1fb4a2f14e6bb2bdd03d31f52c6a1759e4574b2441add446ef0",
  "oversized-worker.py": "1a78719c6399195116eb466d1a714fe9520e4883ec773976a6bf925ccf8efb47",
  "duplicate-worker.py": "7bdda47c7a60b3fbca9d50557879455d1597b284b333f18dcceba14628b70c56",
  "forged-worker.py": "2fb17daca47a762f7fbd959e10aeebea17ff4e31c9fbcb843020832bf584e5ee",
  "flood-worker.py": "e2b7b0ded26dd8cefe1b348e85141e2778daa0b8d2e3a71a907ef29bf34ea03a"
}
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}


def run(args,timeout=30,check=True):
    r=subprocess.run(args,text=True,capture_output=True,timeout=timeout,env=ENV,cwd='/')
    if check and r.returncode:raise RuntimeError(str(args[:3])+': '+r.stderr[-4000:]+r.stdout[-1000:])
    return r


def write(path,value):
    tmp=path.with_suffix('.new');tmp.write_text(json.dumps(value,indent=2)+'\n');tmp.chmod(0o644);os.replace(tmp,path)


def read(path):return json.loads(path.read_text())
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def properties(unit):
    r=run(['systemctl','show',unit,'-p','LoadState','-p','ActiveState','-p','SubState','-p','MainPID','-p','ControlPID','-p','Result','-p','ExecMainCode','-p','ExecMainStatus','-p','MemoryMax','-p','MemorySwapMax','-p','RuntimeMaxUSec'])
    return dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)


def module(case,local=False):
    if case not in CASES:raise RuntimeError('Unknown fixed case')
    path=(LOCAL if local else ROOT)/(case+'-worker.py')
    if path.is_symlink() or digest(path)!=HASHES[path.name]:raise RuntimeError('Worker identity mismatch')
    if not local:
        s=path.stat()
        if s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('Unsafe worker owner/mode')
    spec=importlib.util.spec_from_file_location('lifetime_'+case,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def absent(m,s):
    # Do not infer absence from a failed libvirt query or stale cleanup receipt.
    if s['uuid'] in m.virsh('list','--all','--uuid').stdout.split():return False
    return (not m.owned_pids(s) and not m.DATA.exists() and not m.DATA.is_symlink()
            and not m.SLICEFILE.exists() and not m.SLICEFILE.is_symlink()
            and not P('/sys/fs/cgroup',m.SLICE).exists()
            and s['profile'] not in P('/sys/kernel/security/apparmor/profiles').read_text())


EXPECTED={'resources':'Expected CPU and disk limits observed','oom':'Expected worker OOM observed','tasks':'Expected task limit observed','malformed':'Malformed result JSON','oversized':'Oversized result frame','duplicate':'Duplicate readiness frame','forged':'Invalid result schema','flood':'Serial output limit exceeded'}

def classify(case,attempt,cleanup,props,resources_absent,serial_bytes):
    checks={
      'host_pre_resume':attempt.get('checks',{}).get('host_pre_resume') is True,
      'live_vm_at_injection':attempt.get('live_vm_at_injection') is True and bool(attempt.get('ready_at')),
      'expected_failure':attempt.get('error')==EXPECTED[case],
      'failure_evidence':attempt.get('pressure_verified') is True if case in ['resources','oom','tasks'] else attempt.get('evidence_rejected')==EXPECTED[case],
      'attempt_failed':attempt.get('ok') is False and attempt.get('workload_ok') is False,
      'service_result':attempt.get('service_result')=='exit-code' and props.get('Result')=='exit-code' and props.get('ExecMainCode')=='1' and props.get('ExecMainStatus')=='1',
      'controller_quiescent':props.get('ActiveState') in ['failed','inactive'] and props.get('MainPID')==props.get('ControlPID')=='0',
      'cleanup_complete':cleanup.get('complete') is True and cleanup.get('uuid')==attempt.get('uuid'),
      'cleanup_bounded':0<=cleanup.get('finished_at',0)-cleanup.get('started_at',1)<=120,
      'inputs_unchanged':cleanup.get('readonly_inputs_unchanged') is True,
      'resources_absent':resources_absent is True,
      'serial_bounded':0<serial_bytes<=1024**2,
    }
    return {'case_passed':all(checks.values()),'checks':checks}


def execute_case(case):
    m=module(case);m.setup();s=m.state()
    result={'case':case,'case_passed':False,'uuid':s['uuid'],'started_at':time.time()}
    target=m.EVIDENCE/'case-result.json';write(target,result)
    try:
        props=properties(m.UNIT)
        if props.get('MemoryMax')!=str(960*1024**2) or props.get('MemorySwapMax')!='0' or props.get('RuntimeMaxUSec')!='10min':raise RuntimeError('Controller limits mismatch')
        until=time.monotonic()+750
        while time.monotonic()<until:
            props=properties(m.UNIT)
            if props.get('ActiveState') in ['failed','inactive'] and props.get('MainPID')==props.get('ControlPID')=='0':break
            time.sleep(1)
        else:raise RuntimeError('Controller or cleanup exceeded suite case deadline')
        attempt=read(m.EVIDENCE/'report.json');cleanup=read(m.EVIDENCE/'cleanup.json')
        if attempt.get('uuid')!=s['uuid']:raise RuntimeError('Attempt identity mismatch')
        result['unit_properties']=props
        result.update(classify(case,attempt,cleanup,props,absent(m,s),(m.EVIDENCE/'serial.log').stat().st_size))
    except Exception as exc:result['error']=str(exc)
    result['finished_at']=time.time();write(target,result)
    if not result['case_passed']:raise RuntimeError('Case failed: '+case+'; see '+str(target))
    return result


def supervise():
    report={'suite_passed':False,'started_at':time.time(),'cases':[]}
    write(ROOT/'suite-result.json',report)
    def interrupted(*_):raise RuntimeError('Suite interrupted')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    try:
        props=properties(UNIT)
        if props.get('MemoryMax')!=str(64*1024**2) or props.get('MemorySwapMax')!='0':raise RuntimeError('Supervisor budget mismatch')
        for case in CASES:
            report['cases'].append(execute_case(case));write(ROOT/'suite-result.json',report)
        report['cases_passed']=True
    except Exception as exc:report['error']=str(exc)
    finally:
        report['finished_at']=time.time();write(ROOT/'suite-result.json',report)
    return 0 if report.get('cases_passed') else 1


def cleanup():
    receipt={'complete':False,'rescued':[],'started_at':time.time()}
    try:
        for case in CASES:
            m=module(case)
            if not m.ROOT.exists():continue
            s=m.state();props=properties(m.UNIT)
            if props.get('MainPID')!='0' or props.get('ControlPID')!='0' or props.get('ActiveState') in ['active','activating','deactivating']:
                run(['systemctl','stop',m.UNIT],timeout=140)
            if not absent(m,s):
                # Preserve the original failed receipts before any supervisor rescue.
                saved=m.EVIDENCE/'before-suite-rescue';saved.mkdir(mode=0o755);saved.chmod(0o755)
                for name in ['report.json','cleanup.json']:
                    if (m.EVIDENCE/name).exists():shutil.copyfile(m.EVIDENCE/name,saved/name)
                receipt['rescued'].append(case)
                if m.cleanup(preserve_failed_outcome=True):raise RuntimeError('Rescue cleanup failed: '+case)
            if not absent(m,s):raise RuntimeError('Resources remain: '+case)
        receipt['complete']=True
    except Exception as exc:receipt['error']=str(exc)
    receipt['finished_at']=time.time();write(ROOT/'suite-cleanup.json',receipt)
    report=read(ROOT/'suite-result.json') if (ROOT/'suite-result.json').exists() else {}
    report['cleanup']=receipt;report['service_result']=os.environ.get('SERVICE_RESULT','unknown')
    report['suite_passed']=report.get('cases_passed') is True and receipt['complete'] and not receipt['rescued'] and report['service_result']=='success'
    write(ROOT/'suite-result.json',report)
    return 0 if receipt['complete'] else 1


def setup():
    if ROOT.exists() or ROOT.is_symlink():raise RuntimeError('Retained suite exists; inspect rather than overwrite')
    if properties(UNIT).get('LoadState')!='not-found':raise RuntimeError('Suite unit already exists')
    m=module('resources',local=True);m.safe_dir(BASE);m.admission()
    # Pin each local worker before root copies it. Guest media are verified by workers.
    for case in CASES:module(case,local=True)
    ROOT.mkdir(mode=0o755);ROOT.chmod(0o755)
    SCRIPT.write_bytes(P(__file__).read_bytes());SCRIPT.chmod(0o600)
    for case in CASES:
        name=case+'-worker.py';target=ROOT/name;target.write_bytes((LOCAL/name).read_bytes());target.chmod(0o600)
        if digest(target)!=HASHES[name]:raise RuntimeError('Worker changed while copying')
    run(['systemd-run','--quiet','--unit='+UNIT,'--service-type=exec',
         '-p','RuntimeMaxSec=3600','-p','TimeoutStopSec=300','-p','KillMode=control-group',
         '-p','MemoryMax=64M','-p','MemorySwapMax=0','-p','TasksMax=64',
         '-p','StandardOutput=null','-p','StandardError=journal','-p','LogRateLimitIntervalSec=30s','-p','LogRateLimitBurst=20',
         '-p','ExecStopPost=/usr/bin/python3 -I '+str(SCRIPT)+' --cleanup',
         '/usr/bin/python3','-I',str(SCRIPT),'--supervise'])
    print(json.dumps({'started':True,'unit':UNIT,'report':str(ROOT/'suite-result.json'),'cancel_command':'sudo systemctl stop '+UNIT}))


def main():
    parser=argparse.ArgumentParser(description=__doc__);group=parser.add_mutually_exclusive_group()
    for mode in ['check','supervise','cleanup']:group.add_argument('--'+mode,action='store_true')
    args=parser.parse_args()
    if args.check:
        for case in CASES:
            module(case,local=True)
            run(['/usr/bin/python3','-I',str(LOCAL/(case+'-worker.py')),'--check'],timeout=60)
        print(json.dumps({'fixed_workers':True,'all_domain_schemas':True,'all_policy_syntax':True,'all_input_hashes':True,'vm_started':False}));return 0
    if os.geteuid()!=0:raise RuntimeError('sudo required to start the VM suite')
    os.umask(0o077)
    if args.supervise or args.cleanup:
        if P(__file__).resolve()!=SCRIPT:raise RuntimeError('Internal modes require root-owned suite')
        module('resources').safe_dir(ROOT)
        return supervise() if args.supervise else cleanup()
    setup();return 0


if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:print(json.dumps({'error':str(exc)}),file=sys.stderr);sys.exit(1)
