# Replaces only suite case sequencing and final retained-file cleanup.

def admit(case):
    m = module(case)
    with (ROOT / 'admission.lock').open('r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ledger = read(ROOT / 'leases.json')
        if ledger['active']:
            raise RuntimeError('A worker remains reserved')
        if any(name.startswith('eqemu-') for name in m.virsh('list', '--all', '--name').stdout.splitlines()):
            raise RuntimeError('Another proof domain exists')
        facts = m.admission()
        ledger['active'][case] = {'state': 'starting', 'name': m.NAME, 'worker_sha256': HASHES[case+'-worker.py'], 'admission': facts}
        write(ROOT / 'leases.json', ledger)
        m.setup()
        s = m.state()
        ledger['active'][case].update(state='active', uuid=s['uuid'])
        write(ROOT / 'leases.json', ledger)
    return m


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
            deadline = time.monotonic() + 1200
            while time.monotonic() < deadline:
                props = properties(m.UNIT)
                if quiescent(props): break
                if props.get('Slice') != CTL or props.get('MemoryMax') != str(960*1024**2) or props.get('MemorySwapMax') != '0':
                    raise RuntimeError('Controller budget mismatch')
                controller_budget()
                time.sleep(2)
            else: raise RuntimeError('Worker deadline')
            s = ownership(m)
            r = read(m.EVIDENCE / 'report.json')
            c = read(m.EVIDENCE / 'cleanup.json')
            result = acceptance(r, c, props, s, absent(m, s))
            if case == 'producer':
                result['checks']['artifact_eligible'] = read(ROOT / 'custody.json').get('eligible') is True
            else:
                result['checks']['artifact_input_unchanged'] = c.get('artifact_input_unchanged') is True
            result['case_passed'] = all(result['checks'].values())
            result.update(report_sha256=digest(m.EVIDENCE/'report.json'), cleanup_sha256=digest(m.EVIDENCE/'cleanup.json'))
            report['cases'][case] = result
            write(ROOT / 'suite-result.json', report)
            if not result['case_passed']: raise RuntimeError('Handoff case failed: ' + case)
            release(m)
        report['cases_passed'] = True
    except Exception as error: report['error'] = str(error)
    finally:
        report['finished_at'] = time.time()
        write(ROOT / 'suite-result.json', report)
    return 0 if report['cases_passed'] else 1


def cleanup():
    receipt = {'complete': False, 'rescued': [], 'started_at': time.time()}
    try:
        for case in CASES:
            m = module(case)
            if m.ROOT.exists():
                if not quiescent(properties(m.UNIT)): stop(m)
                s = m.state()
                if not absent(m, s):
                    ownership(m)
                    receipt['rescued'].append(case)
                    if m.cleanup(preserve_failed_outcome=True): raise RuntimeError('Rescue failed')
                if not absent(m, s): raise RuntimeError('Owned resources remain')
                if case in read(ROOT / 'leases.json')['active']: release(m)
        if read(ROOT / 'leases.json')['active']: raise RuntimeError('Reservation remains')
        store = ROOT / 'retained'
        if store.exists():
            module('producer').safe_dir(store)
            if any(p.name != 'artifact.raw' for p in store.iterdir()):
                raise RuntimeError('Unknown retained file')
            artifact = store / 'artifact.raw'
            if artifact.exists() or artifact.is_symlink():
                info = artifact.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size != 4*GIB:
                    raise RuntimeError('Retained file identity changed')
                artifact.unlink()
            store.rmdir()
        receipt['retained_artifact_absent'] = not store.exists()
        receipt['controller_budget'] = controller_budget()
        if CTLFILE.is_symlink() or CTLFILE.read_text() != CTLTEXT: raise RuntimeError('Controller slice identity changed')
        CTLFILE.unlink()
        receipt['complete'] = True
    except Exception as error: receipt['error'] = str(error)
    receipt['finished_at'] = time.time()
    write(ROOT / 'suite-cleanup.json', receipt)
    report = read(ROOT / 'suite-result.json') if (ROOT / 'suite-result.json').exists() else {}
    report.update(cleanup=receipt, service_result=os.environ.get('SERVICE_RESULT', 'unknown'))
    report['suite_passed'] = (report.get('cases_passed') is True and receipt['complete']
                            and not receipt['rescued'] and report['service_result'] == 'success')
    write(ROOT / 'suite-result.json', report)
    return 0 if receipt['complete'] else 1
