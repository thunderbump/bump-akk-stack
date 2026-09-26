# Host accepts only bounded protocol data; guest reports cannot select host paths/actions.
MANIFEST_SHA='95eb1cf160fdc3704d17d9d18be0919ed393f6951a98f6143a144b2c91b8f7e4'
class BuildSerial:
    def __init__(self):self.tail=b'';self.total=0
    def feed(self,data):
        if self.total+len(data)>1024**2:raise RuntimeError('Serial output limit exceeded')
        self.total+=len(data);self.tail+=data;values=[]
        while b'\n' in self.tail:
            line,self.tail=self.tail.split(b'\n',1);line=line.rstrip(b'\r')
            if len(line)>65536:raise RuntimeError('Oversized serial line')
            if line.startswith(b'EQEMU_BUILD '):
                raw=line[len(b'EQEMU_BUILD '):]
                if len(raw)>16384:raise RuntimeError('Oversized result frame')
                obj=strict_json(raw)
                if not isinstance(obj,dict):raise RuntimeError('Invalid protocol object')
                values.append(obj)
        if len(self.tail)>65536:raise RuntimeError('Oversized serial line')
        return values

class BuildProtocol:
    def __init__(self,nonce):self.nonce=nonce;self.ready=False;self.preflight=False;self.result=None;self.frames=0
    def accept(self,v):
        self.frames+=1
        if self.frames>1500:raise RuntimeError('Frame count limit')
        if self.result is not None:raise RuntimeError('Frame after final result')
        kind=v.get('kind')
        if kind=='ready':
            if self.ready or set(v)!={'kind','nonce','manifest_sha256'} or v['nonce'] is not None or v['manifest_sha256']!=MANIFEST_SHA:raise RuntimeError('Invalid/duplicate ready')
            self.ready=True;return kind
        if not self.ready or v.get('nonce')!=self.nonce:raise RuntimeError('Wrong run identity or frame ordering')
        if kind=='stage':
            if set(v)!={'kind','nonce','name','state'} or not isinstance(v['name'],str) or not re.fullmatch('[a-z0-9-]{1,80}',v['name']) or v['state'] not in ['started','running','passed']:raise RuntimeError('Invalid stage')
        elif kind=='preflight':
            if self.preflight or set(v)!={'kind','nonce','before_status','after_status','solver_sha256','ports','negative_control','tools'} or v['negative_control'] is not True or type(v['ports']) is not int or v['ports']!=51:raise RuntimeError('Invalid preflight')
            if any(not isinstance(v[k],str) or not re.fullmatch('[a-f0-9]{64}',v[k]) for k in ['before_status','after_status','solver_sha256']):raise RuntimeError('Invalid preflight hash')
            if not isinstance(v['tools'],dict) or not v['tools'].get('system-zlib') or len(v['tools'])>10 or any(not isinstance(x,str) or len(x)>600 for x in v['tools'].values()):raise RuntimeError('Invalid tool facts')
            self.preflight=True
        elif kind=='result':
            if v.get('ok') is not True:
                if set(v)!={'kind','nonce','ok','error'} or v['ok'] is not False or not isinstance(v['error'],str) or len(v['error'])>4500:raise RuntimeError('Invalid failure result')
            else:
                keys={'kind','nonce','ok','checks','binaries','cache_sha256','guest_disk_used_bytes','effective_cmake'}
                checks={'inputs','packages','solver','negative_control','perl','system_zlib','build','tests'}
                if not self.preflight or set(v)!=keys or not isinstance(v['checks'],dict) or set(v['checks'])!=checks or any(x is not True for x in v['checks'].values()):raise RuntimeError('Invalid success result')
                if not isinstance(v['binaries'],dict) or set(v['binaries'])!={'world','zone','shared_memory','loginserver','ucs','queryserv','eqlaunch','tests'}:raise RuntimeError('Missing binary identity')
                if any(not isinstance(x,str) or not re.fullmatch('[a-f0-9]{64}',x) for x in [v['cache_sha256'],*v['binaries'].values()]):raise RuntimeError('Invalid binary hash')
                if type(v['guest_disk_used_bytes']) is not int or not 0<v['guest_disk_used_bytes']<=32*GIB:raise RuntimeError('Invalid disk observation')
                if not isinstance(v['effective_cmake'],dict) or len(v['effective_cmake'])>20 or any(not isinstance(x,str) or len(x)>500 for x in v['effective_cmake'].values()):raise RuntimeError('Invalid effective configuration')
            self.result=v
        else:raise RuntimeError('Unknown frame kind')
        return kind

def collect_build(sock,s,report,cg):
    start=time.monotonic();deadline=start+600;nonce=uuid.uuid4().hex
    parser=BuildSerial();protocol=BuildProtocol(nonce);report['stages']={}
    with sock,(EVIDENCE/'serial.log').open('xb') as log:
        while time.monotonic()<deadline:
            if shutil.disk_usage('/var/lib').free<100*GIB:raise RuntimeError('Disk reserve threatened')
            available=int(next(x.split()[1] for x in P('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))*1024
            if available<8*GIB:raise RuntimeError('Host memory reserve threatened')
            try:data=sock.recv(4096)
            except socket.timeout:continue
            if not data:break
            if parser.total+len(data)>1024**2:raise RuntimeError('Serial output limit exceeded')
            log.write(data);log.flush()
            for v in parser.feed(data):
                kind=protocol.accept(v)
                if kind=='ready':
                    report['ready_at']=time.time();deadline=time.monotonic()+1800
                    sock.sendall((json.dumps({'op':'build','nonce':nonce})+'\n').encode())
                elif kind=='stage':
                    if v['name'] not in report['stages'] and len(report['stages'])>=50:raise RuntimeError('Too many stages')
                    report['stages'][v['name']]={'state':v['state'],'at':time.time()}
                elif kind=='preflight':report['preflight_untrusted']=v;deadline=time.monotonic()+14400
                elif kind=='result':report['guest_report_untrusted']=v;deadline=min(deadline,time.monotonic()+60)
                report['serial_bytes']=parser.total;write_json(EVIDENCE/'report.json',report)
        else:raise RuntimeError('Guest execution deadline reached')
    if protocol.result is None:raise RuntimeError('Missing guest result')
    end=time.monotonic()+30
    while owned_pids(s) and time.monotonic()<end:time.sleep(.25)
    if owned_pids(s):raise RuntimeError('Guest did not shut down')
    wait_domain_absent(s['uuid'])
    if protocol.result['ok'] is not True:raise RuntimeError('Guest build failed: '+protocol.result['error'])
    report['workload_ok']=True
