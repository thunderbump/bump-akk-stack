    # CASE is fixed in each seed; there are no host paths or command arguments.
    import errno
    def emit(value):
        with open('/dev/ttyS0','wb',buffering=0) as out:out.write(value)
    line=b'EQEMU_PRESSURE_READY '+json.dumps(report,separators=(',',':')).encode()+b'\n'
    emit(line)
    if report['ok']:
        time.sleep(2)
        if CASE=='resources':
            result={'schema':1,'kind':'pressure-resource-result','ok':False,'checks':{}}
            try:
                code='import time\nend=time.monotonic()+30\nwhile time.monotonic()<end: pass\n'
                jobs=[subprocess.Popen(['/usr/bin/python3','-I','-c',code]) for _ in range(2)]
                result['checks']['cpu_done']=all(p.wait(timeout=60)==0 for p in jobs)
                size=int(run(['blockdev','--getsize64','/dev/vdb']).stdout)
                if size!=32*1024**2:raise RuntimeError('Unexpected synthetic disk capacity')
                run(['mkfs.ext4','-q','-F','-m','0','/dev/vdb'])
                P('/opt/pressure-disk').mkdir(exist_ok=True)
                run(['mount','-o','nosuid,nodev,noexec','/dev/vdb','/opt/pressure-disk'])
                written=0;full=False
                with open('/opt/pressure-disk/fill','wb',buffering=0) as f:
                    try:
                        for _ in range(600):written+=f.write(b'x'*65536)
                        os.fsync(f.fileno())
                    except OSError as exc:
                        if exc.errno!=errno.ENOSPC:raise
                        full=True
                result['written_bytes']=written
                result['checks']['disk_full']=full and 16*1024**2<=written<=32*1024**2
                result['ok']=all(result['checks'].values())
            except Exception as exc:result['error']=str(exc)[:1000]
            emit(b'EQEMU_PRESSURE_RESULT '+json.dumps(result,separators=(',',':')).encode()+b'\n')
        elif CASE=='malformed':emit(b'EQEMU_PRESSURE_RESULT {broken-json}\n')
        elif CASE=='oversized':emit(b'EQEMU_PRESSURE_RESULT '+b'x'*20000+b'\n')
        elif CASE=='duplicate':emit(line)
        elif CASE=='forged':emit(b'EQEMU_PRESSURE_RESULT {"schema":1,"kind":"suite-result","ok":true,"suite_passed":true,"cleanup":{"complete":true}}\n')
        elif CASE=='flood':
            for _ in range(320):emit(b'x'*4095+b'\n')
    while True:time.sleep(1)
