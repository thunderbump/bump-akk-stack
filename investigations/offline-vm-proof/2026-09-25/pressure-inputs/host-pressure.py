# Appended to each fixed controller during preparation.

def counters(cg,name):return {k:int(v) for k,v in (line.split() for line in (cg/name).read_text().splitlines())}

def task_cleanup():
    if CASE!='tasks':return
    props=run(['systemctl','show',PROBEUNIT,'-p','LoadState','-p','ActiveState','-p','MainPID','-p','ControlPID','-p','Slice','-p','ExecStart']).stdout
    props=dict(x.split('=',1) for x in props.splitlines())
    if props.get('LoadState')=='not-found':return
    if props.get('Slice')!=SLICE or str(ROOT/'task-probe.py') not in props.get('ExecStart','') or digest(ROOT/'task-probe.py')!=hashlib.sha256(TASK_SOURCE.encode()).hexdigest():raise RuntimeError('Task probe ownership mismatch')
    run(['systemctl','stop',PROBEUNIT],timeout=35)
    props=run(['systemctl','show',PROBEUNIT,'-p','MainPID','-p','ControlPID']).stdout
    if any(x!='0' for x in (line.split('=',1)[1] for line in props.splitlines())):raise RuntimeError('Task probe remains active')
    run(['systemctl','reset-failed',PROBEUNIT],check=False)


def host_ready(s,report,cg):
    if len(owned_pids(s))!=1 or virsh('domstate',s['uuid']).stdout.strip()!='running':raise RuntimeError('VM not running at pressure injection')
    report['live_vm_at_injection']=True
    report['before_pressure']={n:(cg/n).read_text().strip() for n in ['memory.current','memory.events','cpu.stat','pids.current','pids.events']}
    report['injected_at']=time.time();write_json(EVIDENCE/'report.json',report)
    if CASE=='resources':
        (cg/'cpu.max').write_text('25000 100000')
        if (cg/'cpu.max').read_text().strip()!='25000 100000':raise RuntimeError('Reduced CPU quota not applied')
        report['cpu_start']=counters(cg,'cpu.stat');report['cpu_started_monotonic']=time.monotonic()
    elif CASE=='oom':
        pid=owned_pids(s)[0]
        report['qemu_oom_score_adj']=int(P('/proc',str(pid),'oom_score_adj').read_text())
        if report['qemu_oom_score_adj']==-1000 or int((cg/'memory.current').read_text())<=256*1024**2:raise RuntimeError('QEMU cannot exercise the selected memory limit')
        report['reduced_memory_max']=256*1024**2
        report['oom_before']=counters(cg,'memory.events')
        write_json(EVIDENCE/'report.json',report)
        (cg/'memory.max').write_text(str(256*1024**2))
        if (cg/'memory.max').read_text().strip()!=str(256*1024**2):raise RuntimeError('Reduced memory maximum not applied')
    elif CASE=='tasks':
        before=counters(cg,'pids.events');limit=int((cg/'pids.current').read_text())+16
        if limit>256:raise RuntimeError('No room for bounded task pressure')
        (cg/'pids.max').write_text(str(limit));report['task_limit']=limit
        script=ROOT/'task-probe.py';script.write_text(TASK_SOURCE);script.chmod(0o644)
        response=run(['systemd-run','--quiet','--wait','--pipe','--unit='+PROBEUNIT,'--slice='+SLICE,'--service-type=exec',
                      '-p','RuntimeMaxSec=30','-p','TimeoutStopSec=5','-p','KillMode=control-group','-p','User=libvirt-qemu',
                      '-p','MemoryMax=64M','-p','MemorySwapMax=0','-p','TasksMax=infinity','-p','NoNewPrivileges=yes',
                      '-p','ProtectSystem=strict','-p','ProtectHome=yes','-p','PrivateTmp=yes',
                      '/usr/bin/python3','-I',str(script)],timeout=40)
        if len(response.stdout)>4096:raise RuntimeError('Unexpected task probe output size')
        probe=json.loads(response.stdout);after=counters(cg,'pids.events')
        report['task_probe']=probe;report['task_events_after']=after
        if probe.get('eagain') is not True or not 1<=probe.get('children',0)<=64 or '/'+SLICE+'/' not in probe.get('cgroup','') or after['max']<=before['max']:raise RuntimeError('Task limit enforcement not observed')
        (cg/'pids.max').write_text('256');task_cleanup()
        report['pressure_verified']=True
        raise RuntimeError('Expected task limit observed')
    write_json(EVIDENCE/'report.json',report)


def resource_result(obj,report,cg):
    if CASE!='resources':raise RuntimeError('Unexpected valid resource result')
    after=counters(cg,'cpu.stat');elapsed=time.monotonic()-report['cpu_started_monotonic'];before=report['cpu_start']
    usage=after['usage_usec']-before['usage_usec'];throttled=after['nr_throttled']-before['nr_throttled']
    report['cpu_observation']={'elapsed_seconds':elapsed,'usage_usec':usage,'throttled_periods':throttled,'cpu_max':(cg/'cpu.max').read_text().strip()}
    if elapsed<20 or usage<2_000_000 or usage>(0.4*elapsed+0.5)*1_000_000 or throttled<10:raise RuntimeError('CPU enforcement observations outside expected bounds')
    raw=DATA/'pressure.raw'
    if raw.stat().st_size!=32*1024**2 or raw.stat().st_blocks*512>33*1024**2:raise RuntimeError('Synthetic disk grew outside allocation')
    if type(obj.get('written_bytes')) is not int or not 16*1024**2<=obj['written_bytes']<=32*1024**2:raise RuntimeError('Unexpected disk-full observation')
    report['guest_resource_report_untrusted']=obj;report['pressure_verified']=True
    raise RuntimeError('Expected CPU and disk limits observed')


def collect_pressure(sock,s,report,cg):
    reader=SerialReader();deadline=time.monotonic()+360;last_check=0
    try:
        with sock,(EVIDENCE/'serial.log').open('xb') as log:
            while time.monotonic()<deadline:
                try:data=sock.recv(65536)
                except socket.timeout:data=None
                if data==b'':
                    if CASE=='oom' and report.get('ready_at'):
                        after=counters(cg,'memory.events');report['oom_after']=after
                        for _ in range(20):
                            if not owned_pids(s):break
                            time.sleep(.25)
                        if after['oom_kill']>report['oom_before']['oom_kill'] and not owned_pids(s):
                            report['pressure_verified']=True
                            raise RuntimeError('Expected worker OOM observed')
                    raise RuntimeError('Unexpected serial closure')
                if data:
                    # The total cap applies to stored bytes as well as parser memory.
                    log.write(data[:max(0,SERIAL_LIMIT-reader.total)])
                    for kind,obj in reader.feed(data):
                        if kind=='ready':
                            report['guest_report_untrusted']=obj;report['ready_at']=time.time()
                            write_json(EVIDENCE/'report.json',report)
                            host_ready(s,report,cg)
                        else:resource_result(obj,report,cg)
                if not report.get('ready_at') and time.time()-report['started_at']>240:raise RuntimeError('Guest readiness deadline reached')
                if time.monotonic()-last_check>2:
                    last_check=time.monotonic()
                    if shutil.disk_usage('/var/lib').free<100*GIB:raise RuntimeError('Disk reserve threatened')
                    available=int(next(x.split()[1] for x in P('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))*1024
                    if available<8*GIB:raise RuntimeError('Host memory reserve threatened')
            raise RuntimeError('Pressure guest deadline reached')
    except EvidenceError as exc:
        report['evidence_rejected']=str(exc)
        raise
    finally:report['serial_bytes']=(EVIDENCE/'serial.log').stat().st_size
