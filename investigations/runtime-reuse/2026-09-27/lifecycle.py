"""Fixed foreground cancellation/repeat driver. Child suites retain their real outcomes."""
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import sys
import time
import types

ROOT=Path('/var/lib/eqemu-vm-proof/runtime-lifecycle-01')
LOCAL=Path('/home/bump/.local/state/eqemu-vm-proof')
LAUNCHERS={}  # Bound to the two prepared launcher digests during preparation.


def load_verified(path, expected):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        facts=os.fstat(fd)
        if not stat.S_ISREG(facts.st_mode) or facts.st_size>256*1024:raise RuntimeError('Unsafe launcher')
        data=b''
        while len(data)<=256*1024:
            chunk=os.read(fd,min(65536,256*1024+1-len(data)))
            if not chunk:break
            data+=chunk
        if len(data)>256*1024:raise RuntimeError('Launcher size changed')
    finally:os.close(fd)
    if hashlib.sha256(data).hexdigest()!=expected:raise RuntimeError('Launcher identity changed')
    module=types.ModuleType('lifecycle_child');module.__file__=str(path)
    exec(compile(data,str(path),'exec'),module.__dict__)
    module._verified_bytes=data
    return module


def write_result(value):
    temporary=ROOT/'result.new'
    temporary.write_text(json.dumps(value,indent=2)+'\n');temporary.chmod(0o644)
    temporary.replace(ROOT/'result.json')


def check_outcome(kind, report, suite, cleanup, ledger, request=None):
    """Reject unrelated failures; this verifies the experiment, not candidate acceptance."""
    if (report.get('ok') is not False or report.get('workload_ok') is not False
            or suite.get('suite_passed') is not False or cleanup.get('complete') is not True
            or cleanup.get('rescued')!=[] or 'controller_budget_error' in cleanup
            or ledger.get('active')!={}):raise RuntimeError('Incomplete or promoted lifecycle outcome')
    guest=report.get('guest_report_untrusted',{})
    if kind=='cancel':
        ready=(request or {}).get('ready',{})
        if (not request or request.get('uuid')!=report.get('uuid')
                or ready.get('name')!='ready' or ready.get('value',{}).get('zone_connection') is not True
                or request.get('requested_at')!=suite.get('cancel_requested_at')
                or suite.get('error')!='Supervisor interrupted' or report.get('error')!='Controller interrupted'
                or guest or report.get('diagnostic_complete') is True):raise RuntimeError('Expected ready-then-cancel evidence missing')
    elif kind=='repeat':
        if (report.get('diagnostic_complete') is not True or guest.get('ok') is not True
                or guest.get('accepted') is not False or guest.get('first_failure') is not None
                or guest.get('later_errors')!=[] or guest.get('evidence_complete') is not True
                or guest.get('scenario',{}).get('checks_completed') is not True):raise RuntimeError('Positive diagnostic repeat incomplete')
    else:raise RuntimeError('Unknown lifecycle case')


def inspect_finished(kind, suite):
    worker=suite.module('consumer');state=worker.state()
    report=suite.read(worker.EVIDENCE/'report.json');receipt=suite.read(worker.EVIDENCE/'cleanup.json')
    summary=suite.read(suite.ROOT/'suite-result.json');cleanup=suite.read(suite.ROOT/'suite-cleanup.json');ledger=suite.read(suite.ROOT/'leases.json')
    released=ledger.get('released',[])
    if len(released)!=1:raise RuntimeError('Expected one released worker')
    suite.validate_identity(state,released[0],worker.NAME,suite.HASHES['consumer-worker.py'],suite.digest(worker.SCRIPT))
    checks=suite.acceptance(report,receipt,suite.properties(worker.UNIT),state,suite.absent(worker,state))['checks']
    if not all(value for name,value in checks.items() if name not in ['workload','service']):raise RuntimeError('Worker cleanup/identity checks failed')
    if suite.CTLFILE.exists() or suite.CTLFILE.is_symlink():raise RuntimeError('Suite slice file remains')
    request=suite.read(suite.ROOT/'cancel-request.json') if kind=='cancel' else None
    check_outcome(kind,report,summary,cleanup,ledger,request)
    return {'verified':True,'suite_result_sha256':suite.digest(suite.ROOT/'suite-result.json'),
            'worker_report_sha256':suite.digest(worker.EVIDENCE/'report.json'),
            'worker_cleanup_sha256':suite.digest(worker.EVIDENCE/'cleanup.json')}


def main():
    if os.geteuid()!=0:raise RuntimeError('sudo required')
    # This small foreground coordinator does no disk copying or guest execution.
    resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2))
    resource.setrlimit(resource.RLIMIT_CPU,(60,60))
    os.umask(0o077)
    if ROOT.exists() or ROOT.is_symlink():raise RuntimeError('Preserve existing lifecycle attempt')
    children=[]
    for kind,number in [('cancel','05'),('repeat','06')]:
        path=LOCAL/('offline-runtime-reuse-'+number+'.py')
        child=load_verified(path,LAUNCHERS[number])
        if child.ROOT.exists() or child.ROOT.is_symlink():raise RuntimeError('Preserve existing child attempt')
        child.prerequisites();child.module('consumer',local=True)
        children.append((kind,number,child,path))
    ROOT.mkdir(mode=0o755)
    for _,number,child,path in children:
        target=ROOT/(number+'-launcher.py');target.write_bytes(child._verified_bytes);target.chmod(0o600)
        load_verified(target,LAUNCHERS[number])
    result={'lifecycle_checks_passed':False,'accepted':False,'cases':{},'started_at':time.time()};active=None
    def interrupted(*_):raise RuntimeError('Lifecycle driver interrupted')
    for signum in [signal.SIGTERM,signal.SIGINT,signal.SIGHUP]:signal.signal(signum,interrupted)
    try:
        write_result(result)
        for kind,number,_,_ in children:
            active=load_verified(ROOT/(number+'-launcher.py'),LAUNCHERS[number])
            result['active_case']=kind;write_result(result)
            active.setup()
            deadline=time.monotonic()+3300
            while time.monotonic()<deadline:
                if active.quiescent(active.properties(active.UNIT)):break
                time.sleep(1)
            else:raise RuntimeError('Child suite deadline')
            result['cases'][kind]=inspect_finished(kind,active)
            active=None;result.pop('active_case',None);write_result(result)
        result['lifecycle_checks_passed']=True
    except Exception as error:result['error']=str(error)
    finally:
        for signum in [signal.SIGTERM,signal.SIGINT,signal.SIGHUP]:signal.signal(signum,signal.SIG_IGN)
        if active is not None and active.ROOT.exists():
            try:
                active.run(['systemctl','stop',active.UNIT],timeout=330)
            except Exception as error:result['stop_error']=str(error)
        result['finished_at']=time.time();write_result(result)
    print(json.dumps(result),flush=True)
    return 0 if result['lifecycle_checks_passed'] else 1


if __name__=='__main__':
    try:sys.exit(main())
    except Exception as error:print(json.dumps({'error':str(error)}),file=sys.stderr);sys.exit(1)
