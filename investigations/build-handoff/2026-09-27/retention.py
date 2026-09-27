# Appended to the suite. Retain one qualified artifact; discard uses this fixed owner only.

def retained_file(m):
    m.safe_dir(m.STORE)
    path = m.STORE/'artifact.raw'
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077
            or info.st_size != 4*GIB or set(p.name for p in m.STORE.iterdir()) != {'artifact.raw'}):
        raise RuntimeError('Retained artifact ownership/type changed')
    return path


def retain_or_discard(receipt):
    m = module('producer')
    result = read(ROOT/'suite-result.json')
    keep = (result.get('cases_passed') is True and not receipt['rescued']
            and os.environ.get('SERVICE_RESULT') == 'success'
            and 'controller_budget_error' not in receipt)
    if not m.STORE.exists() and not m.STORE.is_symlink():
        if keep: raise RuntimeError('Successful handoff lost its retained artifact')
        receipt['retained_artifact_absent'] = True
        return
    path = retained_file(m)
    if keep:
        record = m.custody()
        if record['producer_uuid'] != ownership_released(m)['uuid']:
            raise RuntimeError('Retained producer identity differs')
        # The fresh consumer checked its complete copy; retain the original sealed bytes.
        record.update(consumer_verified=True, retained_at=time.time(), expires_at=time.time()+7*86400)
        m.write_custody(record)
        receipt['artifact_retained'] = {'bytes':record['bytes'], 'sha256':record['sha256'],
            'manifest_sha256':record['manifest_sha256'], 'expires_at':record['expires_at']}
    else:
        record = read(m.CUSTODY) if m.CUSTODY.exists() else {}
        if record.get('producer_uuid') != m.state()['uuid']:
            raise RuntimeError('Refuse deleting an unidentified artifact')
        path.unlink(); m.STORE.rmdir()
        record.update(eligible=False, discarded=True); m.write_custody(record)
        receipt['retained_artifact_absent'] = True


def ownership_released(m):
    s = m.state()
    leases = read(ROOT/'leases.json')
    matching = [lease for lease in leases['released'] if lease.get('uuid') == s['uuid']]
    if leases['active'] or len(matching) != 1:
        raise RuntimeError('Missing released artifact owner')
    validate_identity(s, matching[0], m.NAME, HASHES['producer-worker.py'], digest(m.SCRIPT))
    return s


def discard_artifact():
    # Caller must use the copied root-owned launcher after both workers are quiescent.
    m = module('producer'); m.safe_dir(ROOT)
    for case in CASES:
        worker = module(case)
        if not quiescent(properties(worker.UNIT)) or not absent(worker, worker.state()):
            raise RuntimeError('Worker still owns live resources')
    if not quiescent(properties(UNIT)): raise RuntimeError('Suite still active')
    state_value = ownership_released(m)
    record = read(m.CUSTODY)
    if record.get('producer_uuid') != state_value['uuid']: raise RuntimeError('Artifact owner mismatch')
    if record.get('discarded') is True and not m.STORE.exists(): return 0
    path = retained_file(m)
    if m.hash_file(path, 4*GIB, time.monotonic()+300) != record.get('sha256'):
        raise RuntimeError('Artifact bytes differ; retain for investigation')
    path.unlink(); m.STORE.rmdir()
    record.update(eligible=False, discarded=True, discarded_at=time.time()); m.write_custody(record)
    write(ROOT/'artifact-discard.json', {'complete':True, 'producer_uuid':state_value['uuid'],
                                       'sha256':record['sha256'], 'at':time.time()})
    print(json.dumps({'artifact_discarded':True,'original_suite_result_unchanged':True}))
    return 0
