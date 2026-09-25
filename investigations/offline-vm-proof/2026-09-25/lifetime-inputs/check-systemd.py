import json,os,pathlib,signal,subprocess,time,uuid
P=pathlib.Path
out=P(__file__).parent
if len(__import__('sys').argv)>1:
    if __import__('sys').argv[1]=='worker':
        def interrupted(*_):raise SystemExit(1)
        signal.signal(signal.SIGTERM,interrupted)
        while True:time.sleep(1)
    else:
        P(__import__('sys').argv[2]).write_text(json.dumps({k:os.environ.get(k) for k in ['SERVICE_RESULT','EXIT_CODE','EXIT_STATUS']}));raise SystemExit(0)
report={}
for case in ['timeout','cancel','death']:
    unit='eqemu-lifetime-semantics-'+uuid.uuid4().hex+'.service';receipt=out/(case+'-systemd.json')
    def run(*args):return subprocess.run(args,text=True,capture_output=True,check=True)
    run('systemd-run','--user','--quiet','--unit='+unit,'--service-type=exec','-p','RuntimeMaxSec=3','-p','TimeoutStopSec=5','-p','MemoryMax=64M','-p','MemorySwapMax=0','-p','ExecStopPost=/usr/bin/python3 -I '+str(P(__file__).resolve())+' cleanup '+str(receipt),'/usr/bin/python3','-I',str(P(__file__).resolve()),'worker')
    time.sleep(0.5)
    if case=='cancel':run('systemctl','--user','stop',unit)
    if case=='death':run('systemctl','--user','kill','--kill-whom=main','--signal=KILL',unit)
    for _ in range(100):
        props=dict(x.split('=',1) for x in run('systemctl','--user','show',unit,'-p','ActiveState','-p','MainPID','-p','ControlPID','-p','Result','-p','ExecMainCode','-p','ExecMainStatus').stdout.splitlines())
        if props['ActiveState'] in ['failed','inactive'] and props['ControlPID']=='0':break
        time.sleep(0.1)
    else:raise RuntimeError('Synthetic service did not stop')
    report[case]={'properties':props,'cleanup_environment':json.loads(receipt.read_text())}
    expected={'timeout':('timeout','1','1'),'cancel':('exit-code','1','1'),'death':('signal','2','9')}[case]
    assert (props['Result'],props['ExecMainCode'],props['ExecMainStatus'])==expected,report
    assert report[case]['cleanup_environment']['SERVICE_RESULT']==expected[0]
    run('systemctl','--user','reset-failed',unit)
(out/'systemd-regression.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
