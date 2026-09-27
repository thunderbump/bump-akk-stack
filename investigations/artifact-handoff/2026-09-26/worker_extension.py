# Appended to the pinned worker during preparation, before its main entry point.
ARTIFACT_BYTES = 4 * GIB
STORE = ROOT.parent / 'retained'
CUSTODY = ROOT.parent / 'custody.json'
EXPECTED_MANIFEST = '@MANIFEST@'
EXPECTED_PAYLOAD = '@PAYLOAD@'


def write_custody(value):
    # Apply the private mode before the atomic rename; no fallible work after promotion.
    temporary = CUSTODY.with_suffix('.new')
    temporary.write_text(json.dumps(value, indent=2)+'\n')
    temporary.chmod(0o600)
    os.replace(temporary, CUSTODY)


def custody():
    safe_dir(ROOT.parent)
    facts = CUSTODY.lstat()
    if not stat.S_ISREG(facts.st_mode) or facts.st_uid != 0 or facts.st_mode & 0o022 or facts.st_size > 16384:
        raise RuntimeError('Unsafe custody record')
    value = json.loads(CUSTODY.read_text())
    if value.get('eligible') is not True or value.get('bytes') != ARTIFACT_BYTES or value.get('manifest_sha256') != EXPECTED_MANIFEST:
        raise RuntimeError('Artifact is not eligible')
    if not re.fullmatch('[a-f0-9]{64}', value.get('sha256', '')):
        raise RuntimeError('Artifact digest format')
    safe_dir(STORE)
    return value


def prepare_artifact():
    path = DATA / 'artifact.raw'
    if CASE == 'producer':
        with path.open('xb') as output:
            os.posix_fallocate(output.fileno(), 0, ARTIFACT_BYTES)
        account = pwd.getpwnam('libvirt-qemu')
        os.chown(path, account.pw_uid, account.pw_gid)
        path.chmod(0o600)
    else:
        record = custody()
        copy_blob(STORE / 'artifact.raw', path, ARTIFACT_BYTES, record['sha256'], time.monotonic() + 600)
        path.chmod(0o444)


def artifact_before_data_removal(receipt):
    # The inherited cleanup has already proved no owned QEMU/domain remains here.
    path = DATA / 'artifact.raw'
    report = json.loads((EVIDENCE / 'report.json').read_text()) if (EVIDENCE / 'report.json').exists() else {}
    if CASE == 'producer' and report.get('workload_ok') is True and os.environ.get('SERVICE_RESULT') == 'success':
        if not STORE.exists(): STORE.mkdir(mode=0o700)
        safe_dir(STORE)
        if (STORE / 'artifact.raw').exists() or CUSTODY.exists():
            # A successful earlier handoff must never be overwritten by a rescue pass.
            record = json.loads(CUSTODY.read_text())
            if record.get('producer_uuid') != state()['uuid'] or path.exists():
                raise RuntimeError('Retained artifact ownership conflict')
            return
        digest_value = hash_file(path, ARTIFACT_BYTES, time.monotonic() + 300)
        os.chown(path, 0, 0)
        path.chmod(0o400)
        os.rename(path, STORE / 'artifact.raw')
        write_custody({'eligible': False, 'producer_uuid': state()['uuid'],
                            'bytes': ARTIFACT_BYTES, 'sha256': digest_value,
                            'manifest_sha256': EXPECTED_MANIFEST, 'scope': 'synthetic proof only'})
        receipt['artifact_staged'] = True
    elif CASE == 'consumer' and path.exists():
        receipt['artifact_input_unchanged'] = hash_file(path, ARTIFACT_BYTES, time.monotonic() + 300) == custody()['sha256']


inherited_cleanup = cleanup


def cleanup(preserve_failed_outcome=False):
    result = inherited_cleanup(preserve_failed_outcome)
    if CASE == 'producer' and CUSTODY.exists():
        record = json.loads(CUSTODY.read_text())
        report = json.loads((EVIDENCE / 'report.json').read_text())
        record['eligible'] = result == 0 and report.get('ok') is True and not preserve_failed_outcome
        record['cleanup_sha256'] = digest(EVIDENCE / 'cleanup.json')
        try:
            write_custody(record)
        except Exception as error:
            # Pending custody stays ineligible; publication failure cannot report success.
            report['ok'] = False
            report['publication_error'] = str(error)[:2000]
            write_json(EVIDENCE / 'report.json', report)
            return 1
    return result


def collect_build(sock, state_value, report, cg):
    nonce = uuid.uuid4().hex
    parser = BuildSerial()
    ready = False
    result = None
    deadline = time.monotonic() + 600
    with sock, (EVIDENCE / 'serial.log').open('xb') as log:
        while time.monotonic() < deadline:
            if shutil.disk_usage('/var/lib').free < 100 * GIB:
                raise RuntimeError('Disk reserve threatened')
            available = int(next(x.split()[1] for x in P('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))) * 1024
            if available < 8 * GIB:
                raise RuntimeError('Host memory reserve threatened')
            try: data = sock.recv(4096)
            except socket.timeout: continue
            if not data: break
            values = parser.feed(data)
            log.write(data)
            log.flush()
            for value in values:
                if result is not None or value.get('role') != CASE:
                    raise RuntimeError('Unexpected evidence identity/order')
                if value.get('kind') == 'ready' and not ready and value.get('nonce') is None:
                    ready = True
                    sock.sendall((json.dumps({'op': 'handoff', 'nonce': nonce}) + '\n').encode())
                elif value.get('kind') == 'result' and ready and value.get('nonce') == nonce:
                    result = value
                    report['guest_report_untrusted'] = value
                else:
                    raise RuntimeError('Unexpected evidence frame')
                write_json(EVIDENCE / 'report.json', report)
        else: raise RuntimeError('Synthetic handoff deadline')
    if parser.tail.strip() or result is None:
        raise RuntimeError('Missing/truncated terminal evidence')
    if result.get('ok') is not True:
        raise RuntimeError('Guest failure: ' + str(result.get('error', 'missing error'))[:2000])
    controls = result.get('controls', {})
    if result.get('manifest_sha256') != EXPECTED_MANIFEST or result.get('payload_sha256') != EXPECTED_PAYLOAD or result.get('unmounted') is not True:
        raise RuntimeError('Synthetic payload/completion mismatch')
    if controls.get('inventory_negatives') != 5 or controls.get('observed_child_exit') != 3:
        raise RuntimeError('Missing synthetic controls')
    end = time.monotonic() + 30
    while owned_pids(state_value) and time.monotonic() < end: time.sleep(.25)
    if owned_pids(state_value): raise RuntimeError('Guest did not stop')
    wait_domain_absent(state_value['uuid'])
    events = dict(line.split() for line in (cg / 'memory.events').read_text().splitlines())
    if int(events.get('oom_kill', 0)) or int(events.get('oom', 0)):
        raise RuntimeError('Worker memory event')
    report['workload_ok'] = True
