# Fixed host protocol. Guest frames remain untrusted and cannot select host paths.
def regular_root_json(path):
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022 or st.st_size>65536:raise RuntimeError('Unsafe control file')
    return strict_json(path.read_bytes())


def cleanup_barrier(s):
    marker=ROOT/'interrupt-cleanup.json'
    if not marker.exists() and not marker.is_symlink():return
    if CASE!='stale' or regular_root_json(marker)!={'uuid':s['uuid']}:raise RuntimeError('Invalid cleanup barrier ownership')
    write_json(EVIDENCE/'cleanup-checkpoint.json',{'uuid':s['uuid'],'domain_absent':True,'pid':os.getpid(),'at':time.time()})
    deadline=time.monotonic()+60
    while time.monotonic()<deadline:time.sleep(0.25)
    raise RuntimeError('Cleanup interruption barrier expired')


class RecoverySerial:
    def __init__(self,sock,log):
        self.sock=sock;self.log=log;self.total=0;self.tail=b'';self.frames=[]
    def poll(self):
        try:data=self.sock.recv(4096)
        except socket.timeout:return True
        if not data:return False
        if self.total+len(data)>1024**2:
            self.log.write(data[:1024**2-self.total]);self.log.flush()
            raise RuntimeError('Serial output limit exceeded')
        self.total+=len(data);self.log.write(data);self.log.flush();self.tail+=data
        while b'\n' in self.tail:
            line,self.tail=self.tail.split(b'\n',1);line=line.rstrip(b'\r')
            if len(line)>65536:raise RuntimeError('Oversized serial line')
            if line.startswith(b'EQEMU_RECOVERY '):
                raw=line[len(b'EQEMU_RECOVERY '):]
                if len(raw)>16384:raise RuntimeError('Oversized result frame')
                value=strict_json(raw)
                if not isinstance(value,dict):raise RuntimeError('Invalid result schema')
                self.frames.append(value)
                if len(self.frames)>8:raise RuntimeError('Too many queued frames')
        if len(self.tail)>65536:raise RuntimeError('Oversized serial line')
        return True
    def next(self,deadline):
        while time.monotonic()<deadline:
            if self.frames:return self.frames.pop(0)
            host_headroom()
            if not self.poll():raise RuntimeError('Guest serial closed early')
        raise RuntimeError('Guest response deadline')


def host_headroom():
    if shutil.disk_usage('/var/lib').free<100*GIB:raise RuntimeError('Disk reserve threatened')
    available=int(next(x.split()[1] for x in P('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))*1024
    if available<8*GIB:raise RuntimeError('Host memory reserve threatened')


def live(s):
    if virsh('domstate',s['uuid']).stdout.strip()!='running' or len(owned_pids(s))!=1:raise RuntimeError('Expected live owned VM')


def validate_ready(value):
    required={'guest_root','no_virtual_nic','no_nested_virtualization','approved_input','no_host_mounts','no_host_control_socket','no_external_route','container_exchange','intentional_failure_distinct','containers_removed'}
    if set(value)!={'kind','identity','baseline'} or value['kind']!='ready' or value['identity']!='eqemu-recovery-'+CASE+'-v1':raise RuntimeError('Invalid ready frame')
    b=value['baseline']
    if not isinstance(b,dict) or type(b.get('schema')) is not int or b.get('schema')!=1 or b.get('kind')!='offline-container-trial' or b.get('ok') is not True or not isinstance(b.get('checks'),dict) or set(b['checks'])!=required or any(v is not True for v in b['checks'].values()):raise RuntimeError('Guest baseline failed')


def validate_reply(value,op,nonce,previous):
    fields={'kind','nonce','identity'}|({'http','counter','database','endpoint'} if op=='probe' else {'counter','clean'} if op=='finish' else {'bytes'})
    if set(value)!=fields or value.get('kind')!=op or value.get('nonce')!=nonce or value.get('identity')!='eqemu-recovery-'+CASE+'-v1':raise RuntimeError('Invalid response identity or schema')
    if op=='probe':
        if type(value['counter']) is not int or value['counter']!=previous+1 or value['http']!=value['identity'] or value['database']!='/opt/eqemu-proof/world.db' or value['endpoint']!='172.29.31.2:8080':raise RuntimeError('Invalid probe evidence')
    elif op=='finish':
        if value['clean'] is not True or type(value['counter']) is not int or value['counter']!=previous:raise RuntimeError('Invalid final evidence')
    elif value['bytes']!=64*1024**2 or type(value['bytes']) is not int:raise RuntimeError('Invalid I/O evidence')
    return value


def io_count(cg,dev,key):
    for line in (cg/'io.stat').read_text().splitlines():
        fields=line.split()
        if fields[0]==dev:return int(dict(x.split('=',1) for x in fields[1:])[key])
    return 0


def collect_recovery(sock,s,report,cg):
    deadline=time.monotonic()+1100;counter=0
    with sock,(EVIDENCE/'serial.log').open('xb') as log:
        reader=RecoverySerial(sock,log)
        ready=reader.next(min(deadline,time.monotonic()+420));validate_ready(ready);live(s)
        report.update(ready_at=time.time(),guest_report_untrusted=ready,pulse_count=0,observations=[])
        write_json(EVIDENCE/'report.json',report)
        def request(op,timeout=25):
            nonce=uuid.uuid4().hex;sock.sendall((json.dumps({'op':op,'nonce':nonce})+'\n').encode())
            value=reader.next(min(deadline,time.monotonic()+timeout));return validate_reply(value,op,nonce,counter)
        while time.monotonic()<deadline:
            value=request('probe');counter=value['counter'];live(s)
            report['pulse_count']+=1;report['observations']=(report['observations']+[dict(value,at=time.time())])[-3:]
            report['serial_bytes']=reader.total;write_json(EVIDENCE/'report.json',report)
            finish=ROOT/'finish-request.json'
            if CASE=='io':
                dev=report['io_device']['backing_disk'];(cg/'io.max').write_text(dev+' rbps=8388608 wbps=4194304\n')
                if dev+' ' not in (cg/'io.max').read_text():raise RuntimeError('I/O limit device mismatch')
                limits=dict(x.split('=',1) for x in next(l for l in (cg/'io.max').read_text().splitlines() if l.startswith(dev+' ')).split()[1:])
                if limits.get('rbps')!='8388608' or limits.get('wbps')!='4194304':raise RuntimeError('I/O pressure limits mismatch')
                report['io_phases']=[]
                for op,key,rate,min_seconds in [('io-write','wbytes',4*1024**2,8),('io-read','rbytes',8*1024**2,4)]:
                    before=io_count(cg,dev,key);start=time.monotonic();response=request(op,90);duration=time.monotonic()-start;delta=io_count(cg,dev,key)-before
                    phase={'op':op,'bytes':delta,'seconds':duration,'limit':rate,'response_untrusted':response}
                    phase['passed']=delta>=64*1024**2 and duration>=min_seconds and delta<=rate*1.5*duration+8*1024**2
                    report['io_phases'].append(phase);write_json(EVIDENCE/'report.json',report)
                    if not phase['passed']:raise RuntimeError('Sustained I/O limit proof failed')
                report['io_verified']=True
            if CASE=='io' or finish.exists() or finish.is_symlink():
                if CASE!='io' and regular_root_json(finish)!={'uuid':s['uuid']}:raise RuntimeError('Invalid finish ownership')
                report['finish_untrusted']=request('finish');write_json(EVIDENCE/'report.json',report)
                end=min(deadline,time.monotonic()+60)
                while time.monotonic()<end:
                    if reader.frames:raise RuntimeError('Unexpected frame after finish')
                    connected=reader.poll()
                    if reader.frames:raise RuntimeError('Unexpected frame after finish')
                    if not connected and not owned_pids(s):break
                    time.sleep(0.1)
                else:raise RuntimeError('Guest did not power off')
                wait_domain_absent(s['uuid']);report['serial_bytes']=reader.total;report['workload_ok']=True;return
            time.sleep(5)
        raise RuntimeError('Worker deadline')
