
EXPECTED={'resources':'Expected CPU and disk limits observed','oom':'Expected worker OOM observed','tasks':'Expected task limit observed','malformed':'Malformed result JSON','oversized':'Oversized result frame','duplicate':'Duplicate readiness frame','forged':'Invalid result schema','flood':'Serial output limit exceeded'}

def classify(case,attempt,cleanup,props,resources_absent,serial_bytes):
    checks={
      'host_pre_resume':attempt.get('checks',{}).get('host_pre_resume') is True,
      'live_vm_at_injection':attempt.get('live_vm_at_injection') is True and bool(attempt.get('ready_at')),
      'expected_failure':attempt.get('error')==EXPECTED[case],
      'failure_evidence':attempt.get('pressure_verified') is True if case in ['resources','oom','tasks'] else attempt.get('evidence_rejected')==EXPECTED[case],
      'attempt_failed':attempt.get('ok') is False and attempt.get('workload_ok') is False,
      'service_result':attempt.get('service_result')=='exit-code' and props.get('Result')=='exit-code' and props.get('ExecMainCode')=='1' and props.get('ExecMainStatus')=='1',
      'controller_quiescent':props.get('ActiveState') in ['failed','inactive'] and props.get('MainPID')==props.get('ControlPID')=='0',
      'cleanup_complete':cleanup.get('complete') is True and cleanup.get('uuid')==attempt.get('uuid'),
      'cleanup_bounded':0<=cleanup.get('finished_at',0)-cleanup.get('started_at',1)<=120,
      'inputs_unchanged':cleanup.get('readonly_inputs_unchanged') is True,
      'resources_absent':resources_absent is True,
      'serial_bounded':0<serial_bytes<=1024**2,
    }
    return {'case_passed':all(checks.values()),'checks':checks}


def execute_case(case):
    m=module(case);m.setup();s=m.state()
    result={'case':case,'case_passed':False,'uuid':s['uuid'],'started_at':time.time()}
    target=m.EVIDENCE/'case-result.json';write(target,result)
    try:
        props=properties(m.UNIT)
        if props.get('MemoryMax')!=str(960*1024**2) or props.get('MemorySwapMax')!='0' or props.get('RuntimeMaxUSec')!='10min':raise RuntimeError('Controller limits mismatch')
        until=time.monotonic()+750
        while time.monotonic()<until:
            props=properties(m.UNIT)
            if props.get('ActiveState') in ['failed','inactive'] and props.get('MainPID')==props.get('ControlPID')=='0':break
            time.sleep(1)
        else:raise RuntimeError('Controller or cleanup exceeded suite case deadline')
        attempt=read(m.EVIDENCE/'report.json');cleanup=read(m.EVIDENCE/'cleanup.json')
        if attempt.get('uuid')!=s['uuid']:raise RuntimeError('Attempt identity mismatch')
        result['unit_properties']=props
        result.update(classify(case,attempt,cleanup,props,absent(m,s),(m.EVIDENCE/'serial.log').stat().st_size))
    except Exception as exc:result['error']=str(exc)
    result['finished_at']=time.time();write(target,result)
    if not result['case_passed']:raise RuntimeError('Case failed: '+case+'; see '+str(target))
    return result

