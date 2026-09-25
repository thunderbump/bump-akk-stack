    import select, sqlite3, tty, re
    fd=None
    def emit(value):
        data=('\nEQEMU_RECOVERY '+json.dumps(value,separators=(',',':'))+'\n').encode()
        while data:
            n=os.write(fd,data);data=data[n:]
    try:
        if not report['ok']:raise RuntimeError('Baseline fixture failed')
        identity='eqemu-recovery-'+CASE+'-v1'
        with tarfile.open('/opt/eqemu-proof/live.tar','w') as t:
            t.add('/bin/busybox',arcname='bin/busybox',recursive=False)
            payload=(identity+'\n').encode();entry=tarfile.TarInfo('www/index.html');entry.size=len(payload);entry.mode=0o444;t.addfile(entry,io.BytesIO(payload))
        run(['docker','import','/opt/eqemu-proof/live.tar','eqemu-live:v1'])
        run(['docker','network','create','--internal','--subnet','172.29.31.0/24','eqemu-proof'])
        run(['docker','run','-d','--pull=never','--name','fixture-server','--network','eqemu-proof','--ip','172.29.31.2','--read-only','--cap-drop=ALL','eqemu-live:v1','/bin/busybox','httpd','-f','-p','8080','-h','/www'])
        db=sqlite3.connect('/opt/eqemu-proof/world.db')
        db.execute('CREATE TABLE actor (identity TEXT PRIMARY KEY, ticks INTEGER NOT NULL)')
        db.execute('INSERT INTO actor VALUES (?,0)',(identity,));db.commit()
        # Stop the login reader and terminal echo before the host sends commands.
        run(['systemctl','stop','serial-getty@ttyS0.service'])
        fd=os.open('/dev/ttyS0',os.O_RDWR|os.O_NOCTTY);tty.setraw(fd)
        emit({'kind':'ready','identity':identity,'baseline':report})
        deadline=time.monotonic()+1200;pending=b''
        while time.monotonic()<deadline:
            if not select.select([fd],[],[],1)[0]:continue
            pending+=os.read(fd,1024)
            if len(pending)>2048:raise RuntimeError('Command too large')
            while b'\n' in pending:
                line,pending=pending.split(b'\n',1)
                if not line:continue
                command=json.loads(line)
                if set(command)!={'op','nonce'} or not re.fullmatch('[0-9a-f]{32}',command['nonce']):raise RuntimeError('Invalid command')
                op=command['op'];answer={'kind':op,'nonce':command['nonce'],'identity':identity}
                if op=='probe':
                    body=run(['docker','exec','fixture-server','/bin/busybox','wget','-T','3','-qO-','http://172.29.31.2:8080/'],timeout=10).stdout
                    if body!=identity+'\n':raise RuntimeError('HTTP identity mismatch')
                    db.execute('UPDATE actor SET ticks=ticks+1 WHERE identity=?',(identity,));db.commit()
                    rows=db.execute('SELECT identity,ticks FROM actor').fetchall()
                    if len(rows)!=1 or rows[0][0]!=identity:raise RuntimeError('Database identity mismatch')
                    answer.update(http=body.strip(),counter=rows[0][1],database='/opt/eqemu-proof/world.db',endpoint='172.29.31.2:8080')
                elif op in ['io-write','io-read'] and CASE=='io':
                    if run(['blockdev','--getsize64','/dev/vdb']).stdout.strip()!=str(128*1024**2):raise RuntimeError('Wrong I/O disk')
                    args=['dd','bs=1M','count=64','status=none']
                    args+=['if=/dev/zero','of=/dev/vdb','oflag=direct','conv=fdatasync'] if op=='io-write' else ['if=/dev/vdb','of=/dev/null','iflag=direct']
                    run(args,timeout=90);answer['bytes']=64*1024**2
                elif op=='finish':
                    rows=db.execute('SELECT identity,ticks FROM actor').fetchall()
                    if len(rows)!=1 or rows[0][0]!=identity or rows[0][1]<1:raise RuntimeError('Final database mismatch')
                    run(['docker','rm','-f','fixture-server']);run(['docker','network','rm','eqemu-proof'])
                    if run(['docker','ps','-aq']).stdout.strip():raise RuntimeError('Containers remain')
                    answer['counter']=rows[0][1];answer['clean']=True;db.close();emit(answer)
                    subprocess.run(['systemctl','poweroff'],timeout=15,check=False);time.sleep(30)
                    raise RuntimeError('Poweroff did not finish')
                else:raise RuntimeError('Unsupported command')
                emit(answer)
        raise RuntimeError('Guest deadline')
    except Exception as exc:
        if fd is None:fd=os.open('/dev/ttyS0',os.O_WRONLY|os.O_NOCTTY)
        emit({'kind':'error','error':str(exc)[:2000],'baseline':report})
        subprocess.run(['systemctl','poweroff'],timeout=15,check=False)
