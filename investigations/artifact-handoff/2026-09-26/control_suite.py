# Fixed cancellation and publication controls. Workload failure is required.


def control_acceptance(case, report, cleanup_receipt, props, identity, resources_absent,
                       pending, fault, cancel_requested):
    checks = {
        'identity': report.get('uuid') == cleanup_receipt.get('uuid') == identity['uuid'],
        'host_pre_resume': report.get('checks', {}).get('host_pre_resume') is True,
        'workload_not_accepted': report.get('ok') is False,
        'cleanup': cleanup_receipt.get('complete') is True and cleanup_receipt.get('readonly_inputs_unchanged') is True,
        'cleanup_time': 0 <= cleanup_receipt.get('finished_at', 0)-cleanup_receipt.get('started_at', 1) <= 120,
        'resources_absent': resources_absent is True,
        'quiescent': quiescent(props),
        'no_promotion': pending is None or pending.get('eligible') is False,
    }
    if case == 'cancel':
        checks.update(cancel_requested=cancel_requested is True,
                      export_started=report.get('export_started') is True,
                      interrupted=report.get('error') == 'Controller interrupted',
                      no_completion=report.get('workload_ok') is False,
                      no_custody=pending is None)
    else:
        checks.update(producer_completed=report.get('workload_ok') is True,
                      injected_failure=fault == {'injected': True, 'operation': 'finalize-custody'},
                      publication_failed=report.get('publication_error') == 'Intentional custody finalization failure',
                      pending_custody=isinstance(pending, dict) and pending.get('eligible') is False,
                      service_failed=props.get('Result') == 'exit-code')
    return {'case_passed': all(checks.values()), 'checks': checks}


def supervise():
    report = {'suite_passed': False, 'cases_passed': False, 'cases': {}, 'started_at': time.time()}
    write(ROOT / 'suite-result.json', report)
    def interrupted(*_): raise RuntimeError('Supervisor interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        controller_budget()
        for case in CASES:
            m = admit(case)
            cancel_requested = False
            deadline = time.monotonic() + 1200
            while time.monotonic() < deadline:
                props = properties(m.UNIT)
                if quiescent(props): break
                if props.get('Slice') != CTL or props.get('MemoryMax') != str(960*1024**2) or props.get('MemorySwapMax') != '0':
                    raise RuntimeError('Controller budget mismatch')
                controller_budget()
                evidence = m.EVIDENCE / 'report.json'
                if case == 'cancel' and not cancel_requested and evidence.exists() and read(evidence).get('export_started') is True:
                    ownership(m)
                    report['cancel_requested_at'] = time.time()
                    write(ROOT / 'suite-result.json', report)
                    cancel_requested = True
                    stop(m)
                time.sleep(.5)
            else: raise RuntimeError('Worker deadline')
            s = ownership(m)
            r = read(m.EVIDENCE / 'report.json')
            c = read(m.EVIDENCE / 'cleanup.json')
            pending = read(ROOT/'custody.json') if (ROOT/'custody.json').exists() else None
            fault_path = m.EVIDENCE/'publication-fault.json'
            fault = read(fault_path) if fault_path.exists() else None
            refused = False
            try:
                m.custody()
            except FileNotFoundError:
                refused = case == 'cancel' and not (ROOT/'custody.json').exists()
            except RuntimeError as error:
                refused = case == 'publish' and str(error) == 'Artifact is not eligible'
            result = control_acceptance(case, r, c, props, s, absent(m, s), pending, fault, cancel_requested)
            result['checks']['consumer_refused'] = refused
            result['case_passed'] = all(result['checks'].values())
            result.update(report_sha256=digest(m.EVIDENCE/'report.json'), cleanup_sha256=digest(m.EVIDENCE/'cleanup.json'))
            report['cases'][case] = result
            write(ROOT / 'suite-result.json', report)
            if not result['case_passed']: raise RuntimeError('Control failed: ' + case)
            release(m)
        report['cases_passed'] = True
    except Exception as error: report['error'] = str(error)
    finally:
        report['finished_at'] = time.time()
        write(ROOT / 'suite-result.json', report)
    return 0 if report['cases_passed'] else 1
