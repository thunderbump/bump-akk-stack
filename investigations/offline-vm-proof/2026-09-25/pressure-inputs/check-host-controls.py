"""Small trusted user-service probes; no VM or privileged data access."""
import json,pathlib,subprocess,sys,time
P=pathlib.Path;D=P(__file__).parent
if len(sys.argv)>1:
 cg=P('/sys/fs/cgroup')/P('/proc/self/cgroup').read_text().strip().split('::',1)[1].lstrip('/')
 if sys.argv[1]=='memory':
  blocks=[]
  for _ in range(32):blocks.append(bytearray(4*1024**2))
  raise RuntimeError('Memory limit did not stop the probe')
 if sys.argv[1]=='post':
  report={n:(cg/n).read_text().strip() for n in ['memory.events','memory.max','memory.swap.max','memory.peak','pids.events']}
  (D/(sys.argv[2]+'-control.json')).write_text(json.dumps(report,indent=2)+'\n');sys.exit(0)
 if sys.argv[1]=='cpu':
  def counters():return {k:int(v) for k,v in (x.split() for x in (cg/'cpu.stat').read_text().splitlines())}
  before=counters();start=time.monotonic()
  jobs=[subprocess.Popen(['/usr/bin/python3','-I','-c','import time\ne=time.monotonic()+22\nwhile time.monotonic()<e: pass\n']) for _ in range(2)]
  for p in jobs:assert p.wait(timeout=40)==0
  elapsed=time.monotonic()-start;after=counters();used=after['usage_usec']-before['usage_usec'];throttled=after['nr_throttled']-before['nr_throttled']
  report={'elapsed_seconds':elapsed,'usage_usec':used,'throttled_periods':throttled,'cpu_max':(cg/'cpu.max').read_text().strip()}
  assert report['cpu_max']=='25000 100000' and elapsed>=20 and 2e6<=used<=(.4*elapsed+.5)*1e6 and throttled>=10,report
  (D/'cpu-control.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report));sys.exit(0)

def run(args,check=True):return subprocess.run(args,check=check,capture_output=True,text=True)
for case in ['cpu','memory']:
 unit='eqemu-pressure-'+case+'-regression.service'
 args=['systemd-run','--user','--quiet','--wait','--pipe','--unit='+unit,'-p','RuntimeMaxSec=45','-p','TimeoutStopSec=5','-p','MemorySwapMax=0','-p','TasksMax=16','-p','MemoryMax='+('64M' if case=='cpu' else '32M')]
 if case=='cpu':args+=['-p','CPUQuota=25%']
 else:args+=['-p','ExecStopPost=/usr/bin/python3 -I '+str(P(__file__).resolve())+' post memory']
 result=run(args+['/usr/bin/python3','-I',str(P(__file__).resolve()),case],check=False)
 if case=='cpu':assert result.returncode==0,result.stderr
 else:
  report=json.loads((D/'memory-control.json').read_text());events=dict(x.split() for x in report['memory.events'].splitlines())
  assert int(events['oom_kill'])>=1 and report['memory.max']==str(32*1024**2) and report['memory.swap.max']=='0',report
  props=run(['systemctl','--user','show',unit,'-p','Result','--value']).stdout.strip();assert props=='oom-kill',props
  run(['systemctl','--user','reset-failed',unit])
 print(case,'passed',flush=True)
