# Guest adapter appended to selected archived fixture helpers. No legacy scenario/checksum gate.
START=time.monotonic(); FIRST_FAILURE=None; LATER_ERRORS=[]; EVENTS=[]; DIAGNOSTIC_BYTES=0
READINESS={'registration','zone_boot','instance','world_time'}


def event(name,value):
    value=dict(value,elapsed=round(time.monotonic()-START,3))
    EVENTS.append((name,value))
    if len(EVENTS)>100:raise RuntimeError('Scenario event budget')
    B.emit({'kind':'scenario-event','name':name,'value':value})


def observe(service,line):
    line=ANSI.sub('',line)
    if service.name=='world' and 'Setting zone process to Zone [The Plane of Knowledge] [poknowledge] zone_id [202]' in line and '(Static)' in line and 'Instance ID' not in line:service.flags.add('registration')
    if service.name=='zone':
        if 'Zone booted successfully zone_id [202]' in line:service.flags.add('zone_boot')
        if 'Zone bootup type [Static] short_name [poknowledge] zone_id [202] instance_id [0]' in line:service.flags.add('instance')
        if 'Received Message SyncWorldTime' in line:service.flags.add('world_time')
        if 'Zone->Init failed' in line:service.flags.add('init_failed')


CapturedService=Service

def Service(name,args,cwd,log):
    service=CapturedService(name,args,cwd,log,B.ENV,SECRET_VALUES,observe,event)
    SERVICES.append(service)
    event('service-start',{'service':name,'pid':service.pid})
    return service


def protected_state(db,label,inventory):
    tables=sorted({t for group in inventory['groups'].values() for t in group['tables']})
    if set(db.query(label+'-tables','SHOW TABLES;').splitlines())!=set(tables):raise RuntimeError('Fixture table set changed')
    version=db.query(label+'-version','SELECT version,bots_version,custom_version FROM db_version;').strip()
    if version!='9328\t0\t0':raise RuntimeError('Unexpected fixture version')
    if db.query(label+'-bots',"SELECT rule_value FROM rule_values WHERE ruleset_id=1 AND rule_name='Bots:Enabled';").strip()!='false':raise RuntimeError('Bots enabled')
    empty=sorted(set(inventory['groups']['player']['tables']+inventory['groups']['login']['tables']))
    counts=db.query(label+'-players',' UNION ALL '.join("SELECT '"+t+"',COUNT(*) FROM `"+t+'`' for t in empty)+';')
    if len(counts.splitlines())!=len(empty) or any(line.split('\t')[1]!='0' for line in counts.splitlines()):raise RuntimeError('Player/account state changed')
    schema=db.query(label+'-schema',"SELECT TABLE_NAME,COLUMN_NAME,ORDINAL_POSITION,COLUMN_TYPE,IS_NULLABLE,IFNULL(COLUMN_DEFAULT,'<NULL>'),EXTRA FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='eqemu_proof' ORDER BY TABLE_NAME,ORDINAL_POSITION; SELECT TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX,COLUMN_NAME,NON_UNIQUE,IFNULL(SUB_PART,0) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA='eqemu_proof' ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX;")
    return {'schema_sha256':hashlib.sha256(schema.encode()).hexdigest(),'player_state_sha256':hashlib.sha256(counts.encode()).hexdigest(),'version':version}


def database_observation(db,label):
    output=db.query('connections-'+label,"SHOW GLOBAL STATUS WHERE Variable_name IN ('Aborted_clients','Aborted_connects','Threads_connected'); SELECT ID,USER,HOST,COMMAND,IFNULL(STATE,'') FROM information_schema.PROCESSLIST WHERE USER='eqemu' ORDER BY ID;")
    if len(output)>6000:raise RuntimeError('DB observation budget')
    event('database-connections',{'phase':label,'observation':output})


def check_health(db,world,zone):
    guard()
    for service in [db.service,world,zone]:service.live()
    if 'init_failed' in zone.flags:raise RuntimeError('Zone initialization explicitly failed')
    if not connection(zone.pid):raise RuntimeError('Zone-owned world connection absent')


def world_listener_ready(tcp_table):
    # EQEmu binds its IPv4 server listener to all interfaces in this offline VM.
    for line in tcp_table.splitlines()[1:]:
        fields=line.split()
        if fields[1] in {'00000000:2328','0100007F:2328'} and fields[3]=='0A':
            return True
    return False


def scenario():
    root=ROOT/'startup';root.mkdir();db=Database('startup',root)
    event('setup',{'fixture':RUNTIME_SHA})
    db.initialize();inventory=db.import_fixture();server=configure('startup',root,db)
    content=db.query('content',"SELECT zoneidnumber,version,short_name FROM zone WHERE zoneidnumber=202 AND version=0; SELECT COUNT(*)>0 FROM items; SELECT COUNT(*)>0 FROM spells_new;").strip()
    if content!='202\t0\tpoknowledge\n1\n1':raise RuntimeError('Required public content missing')
    database_observation(db,'before-shared')
    B.command('startup-shared-memory',[str(B.WORK/'build/bin/shared_memory')],cwd=server,timeout=180)
    shared=shared_evidence(server/'shared');database_observation(db,'after-shared')
    before=protected_state(db,'before',inventory)
    world=Service('world',[str(B.WORK/'build/bin/world')],server,root/'world-console.log')
    deadline=min(B.DEADLINE,time.monotonic()+120)
    while time.monotonic()<deadline:
        guard();world.live();db.service.live()
        if world_listener_ready(P('/proc/net/tcp').read_text()):break
        time.sleep(.25)
    else:raise RuntimeError('World listener deadline')
    zone=Service('zone',[str(B.WORK/'build/bin/zone'),'poknowledge:7000'],server,root/'zone-console.log')
    deadline=min(B.DEADLINE,time.monotonic()+180)
    while time.monotonic()<deadline:
        guard()
        for service in [db.service,world,zone]:service.live()
        if 'init_failed' in zone.flags:raise RuntimeError('Zone initialization failed')
        flags=world.flags|zone.flags
        if READINESS<=flags and connection(zone.pid):break
        time.sleep(.5)
    else:raise RuntimeError('Startup interaction deadline; missing '+str(sorted(READINESS-flags)))
    event('ready',{'observed':sorted(flags),'zone_connection':True})
    database_observation(db,'ready')
    start=time.monotonic();samples=0
    while time.monotonic()-start<60:
        check_health(db,world,zone)
        if db.query('health-'+str(samples),'SELECT 1;').strip()!='1':raise RuntimeError('DB health probe failed')
        samples+=1;time.sleep(5)
    check_health(db,world,zone);event('health',{'duration':round(time.monotonic()-start,3),'samples':samples})
    database_observation(db,'before-shutdown')
    for service in [zone,world]:
        result=service.stop()
        if result['return_code']!=0 or result['early_exit'] or result['forced'] or not result['capture_complete'] or result['capture_error']:raise RuntimeError('Unclean '+service.name+' shutdown')
    after=protected_state(db,'after',inventory)
    if before!=after:raise RuntimeError('Protected schema/player state changed')
    database_observation(db,'after-shutdown')
    event('checks-complete',{'schema_unchanged':True,'player_state_empty':True,'shared':shared})
    return {'checks_completed':True,'health_samples':samples,'schema_sha256':before['schema_sha256']}


def diagnostic(name,tail):
    global DIAGNOSTIC_BYTES
    tail.secrets=[secret.encode() for secret in SECRET_VALUES if secret]
    value=tail.export();text=value.pop('text');chunks=[text[i:i+1024] for i in range(0,len(text),1024)] or ['']
    for index,chunk in enumerate(chunks):
        frame={'kind':'diagnostic','stream':name,'index':index,'chunks':len(chunks),'text':chunk,'meta':value}
        size=len(json.dumps(frame).encode())+100
        if DIAGNOSTIC_BYTES+size>512*1024:raise RuntimeError('Diagnostic export budget')
        DIAGNOSTIC_BYTES+=size;B.emit(frame)


def failure(error):
    global FIRST_FAILURE
    context=DiagnosticTail(SECRET_VALUES,limit=4000);context.feed(str(error).encode())
    message=context.export()['text']
    if FIRST_FAILURE is None:
        FIRST_FAILURE={'reason':message,'elapsed':round(time.monotonic()-START,3)}
        try:event('first-failure',FIRST_FAILURE)
        except Exception as later:LATER_ERRORS.append(str(later)[:500])
    else:LATER_ERRORS.append(message[:500])


def begin_diagnostic_export():
    # Workload expiry must leave a bounded opportunity to export its failure.
    terminal_deadline=time.monotonic()+15
    B.SEND_DEADLINE=terminal_deadline-2
    return terminal_deadline


def main():
    global BUILD_USED
    check_guest();resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    B.WORK.mkdir();B.LOGS.mkdir();ROOT.mkdir();os.chmod(ROOT,0o755)
    subprocess.run(['systemctl','stop','serial-getty@ttyS0.service'],check=True,timeout=30)
    B.FD=os.open('/dev/ttyS0',os.O_RDWR|os.O_NOCTTY|os.O_NONBLOCK);tty.setraw(B.FD);B.EMIT=B.emit
    result={};evidence_complete=False;reuse=None;oom_before=oom_kills()
    try:
        B.emit({'kind':'ready','manifest_sha256':B.MANIFEST_SHA,'experiment_sha256':'@RECIPE@'})
        pending=b'';end=time.monotonic()+60
        while b'\n' not in pending and time.monotonic()<end:
            if select.select([B.FD],[],[],.2)[0]:pending+=os.read(B.FD,1024)
            if len(pending)>2048:raise RuntimeError('Command size')
        command=json.loads(pending)
        if set(command)!={'op','nonce','artifact_manifest_sha256'} or command['op']!='build' or not re.fullmatch('[a-f0-9]{32}',command['nonce']):raise RuntimeError('Command identity')
        B.NONCE=command['nonce'];B.EXPECTED_ARTIFACT=command['artifact_manifest_sha256'];B.DEADLINE=time.monotonic()+1800
        B.MEDIA.mkdir();RM.mkdir()
        B.command('mount-input',['mount','-o','ro,nosuid,nodev,noexec','/dev/disk/by-label/EQEMUBUILD',str(B.MEDIA)])
        B.command('mount-runtime',['mount','-o','ro,nosuid,nodev,noexec','/dev/disk/by-label/EQEMURUNTIME',str(RM)])
        B.verify_inputs();verify_runtime();reuse=B.build()['consumer']
        B.emit({'kind':'reuse','ok':True,'consumer':reuse})
        BUILD_USED=shutil.disk_usage(ROOT).used;B.GUARD=guard
        install_runtime();verify_binaries(reuse['binaries'])
        for path,expected in reuse['libraries'].items():
            if B.sha(P(path))!=expected:raise RuntimeError('Runtime packages changed a build library')
        result=scenario();verify_binaries(reuse['binaries']);verify_runtime()
    except Exception as error:failure(error)
    finally:
        for service in reversed(SERVICES):
            if service.stop_complete:continue
            try:
                observed=service.stop('failure cleanup' if FIRST_FAILURE else 'requested shutdown')
                if observed['early_exit'] or observed['forced'] or observed['return_code']!=0 or observed['capture_error'] or not observed['capture_complete']:failure(RuntimeError('Unclean service shutdown '+json.dumps(observed)))
            except Exception as error:failure(error)
        terminal_deadline=begin_diagnostic_export()
        try:
            if oom_kills()!=oom_before:failure(RuntimeError('Guest OOM observed'))
            export_end=B.SEND_DEADLINE
            for service in SERVICES:
                if time.monotonic()>=export_end:raise RuntimeError('Diagnostic export deadline')
                diagnostic(service.name,service.tail)
            path=B.LAST_COMMAND
            if path is not None and path.exists():
                tail=DiagnosticTail(SECRET_VALUES)
                with path.open('rb') as stream:
                    stream.seek(max(0,path.stat().st_size-33792));tail.feed(stream.read(33792))
                tail.total=path.stat().st_size
                diagnostic('last-command',tail)
            evidence_complete=True
        except Exception as error:failure(error)
        B.SEND_DEADLINE=terminal_deadline
        try:
            B.emit({'kind':'result','version':1,'ok':FIRST_FAILURE is None,'diagnostic_only':True,'accepted':False,
                'scenario':result,'first_failure':FIRST_FAILURE,'later_errors':LATER_ERRORS[:8],
                'evidence_complete':evidence_complete})
        finally:subprocess.run(['systemctl','poweroff'],timeout=15,check=False)


if __name__=='__main__':main()
