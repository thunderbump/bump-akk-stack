#!/usr/bin/python3
"""Regression for trusted input copy/conversion under the controller memory cap."""
import importlib.util,json,os,pathlib,shutil,time
P=pathlib.Path
home=P('/home/bump/.local/state/eqemu-vm-proof')
spec=importlib.util.spec_from_file_location('trial',home/'first-vm-trial.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
root=home/'disk-preparation-regression';root.mkdir(mode=0o700)
report={'ok':False,'started_at':time.time()}
try:
    m.admission()
    for name,(rel,length,sha) in m.FILES.items():
        source=m.INPUTS/rel;dest=root/name
        with source.open('rb') as src,dest.open('xb') as dst:
            remain=length
            while remain:
                chunk=src.read(min(remain,1024**2))
                if not chunk:raise RuntimeError('Short input')
                dst.write(chunk);remain-=len(chunk)
            if src.read(1):raise RuntimeError('Input grew')
        assert dest.stat().st_size==length and m.digest(dest)==sha
        dest.chmod(0o444)
    raw=root/'root.raw';m.prepare_disk(root/'base.qcow2',raw)
    report['logical_bytes']=raw.stat().st_size;report['allocated_bytes']=raw.stat().st_blocks*512
    cg=P('/sys/fs/cgroup')/P('/proc/self/cgroup').read_text().strip().split('::',1)[1].lstrip('/')
    report['cgroup']={name:(cg/name).read_text().strip() for name in ['memory.max','memory.swap.max','memory.peak','memory.events','memory.stat']}
    assert report['cgroup']['memory.max']==str(1024**3) and report['cgroup']['memory.swap.max']=='0'
    result=m.run(['/usr/bin/qemu-img','compare','-f','qcow2','-F','raw',str(root/'base.qcow2'),str(raw)],timeout=180)
    report['content_comparison']=result.stdout.strip()
    report['after_compare']={name:(cg/name).read_text().strip() for name in ['memory.peak','memory.events']}
    if any(line in report['after_compare']['memory.events'].splitlines() for line in ['oom 1','oom_kill 1']):raise RuntimeError('Unexpected OOM event')
    report['ok']=True
except Exception as exc:report['error']=str(exc)
finally:
    shutil.rmtree(root);report['scratch_absent']=not root.exists();report['finished_at']=time.time()
    (home/'disk-preparation-regression.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:v for k,v in report.items() if k!='cgroup'}))
raise SystemExit(0 if report['ok'] else 1)
