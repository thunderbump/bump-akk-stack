"""Run the actual guest command loop on a PTY/SQLite; stub Docker and poweroff.
This checks transport/database logic, not guest Docker or VM isolation.
"""
import io,json,os,pathlib,pty,select,subprocess,sys,tarfile,tempfile,textwrap,time,uuid
P=pathlib.Path;D=P(__file__).parent
with tempfile.TemporaryDirectory(prefix='eqemu-guest-protocol-') as temp:
    root=P(temp);master,slave=pty.openpty();tty_path=os.ttyname(slave)
    source=textwrap.dedent((D/'guest-suffix.py').read_text())
    source=source.replace('/opt/eqemu-proof',str(root)).replace('/dev/ttyS0',tty_path)
    # No real subprocess calls are reachable from the test child.
    prelude='''import io,json,os,pathlib,tarfile,time,types
P=pathlib.Path
CASE='left'
report={'ok':True,'checks':{}}
def run(args,**kw):
    if args[:3]==['docker','exec','fixture-server']:return types.SimpleNamespace(stdout='eqemu-recovery-left-v1\\n',returncode=0)
    return types.SimpleNamespace(stdout='',returncode=0)
def fake_poweroff(*args,**kw):raise SystemExit(0)
subprocess=types.SimpleNamespace(run=fake_poweroff)
'''
    child=root/'guest-test.py';child.write_text(prelude+source)
    process=subprocess.Popen([sys.executable,'-I',str(child)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    buffer=b''
    def receive():
        global buffer
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            while b'\n' in buffer:
                line,buffer=buffer.split(b'\n',1)
                if line.startswith(b'EQEMU_RECOVERY '):return json.loads(line[15:])
            if select.select([master],[],[],.2)[0]:buffer+=os.read(master,4096)
        raise RuntimeError('Guest test response deadline')
    try:
        ready=receive();assert ready['kind']=='ready',ready
        answers=[]
        for op in ['probe','probe','probe','finish']:
            nonce=uuid.uuid4().hex;raw=(json.dumps({'op':op,'nonce':nonce})+'\n').encode()
            # Fragmented writes exercise the guest's command buffer.
            os.write(master,raw[:11]);os.write(master,raw[11:]);value=receive()
            assert value['kind']==op and value['nonce']==nonce and value['identity']=='eqemu-recovery-left-v1',value
            answers.append(value)
        assert [a['counter'] for a in answers]==[1,2,3,3]
        assert answers[-1]['clean'] is True
        stdout,stderr=process.communicate(timeout=5);assert process.returncode==0,stderr
        result={'passed':True,'counter_sequence':[1,2,3,3],'fresh_nonces':True,'raw_pty':True,'actual_sqlite':True,'docker_stubbed':True,'poweroff_stubbed':True,'at':time.time()}
        (D/'guest-protocol-proof.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
    finally:
        if process.poll() is None:process.kill();process.wait()
        os.close(master);os.close(slave)
