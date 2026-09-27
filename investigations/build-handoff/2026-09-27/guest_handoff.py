# Inserted into the corrected-build guest before main. No host execution.
import errno
import stat

ROLE = '@ROLE@'
BUILD_ID = '@BUILD_ID@'
ARTIFACT_SIZE = 4*1024**3
MOUNT = P('/opt/build-artifact')
DEVICE = '/dev/vdb'
EXPECTED_ARTIFACT = None
OBSERVATIONS = {}
PREFLIGHT = {}
original_emit = emit
original_build = build


def emit(value):
    if value.get('kind') == 'observation': OBSERVATIONS[value['name']] = value['value']
    if value.get('kind') == 'preflight': PREFLIGHT.update(value)
    original_emit(value)


def artifact_mount(producer):
    if not stat.S_ISBLK(os.stat(DEVICE).st_mode) or int(P('/sys/class/block/vdb/size').read_text())*512 != ARTIFACT_SIZE:
        raise RuntimeError('Artifact device identity')
    MOUNT.mkdir()
    if producer:
        command('artifact-format', ['mkfs.ext4', '-F', '-m', '0', '-E',
            'nodiscard,lazy_itable_init=0,lazy_journal_init=0', DEVICE], timeout=120)
    command('artifact-mount', ['mount', '-o', 'nosuid,nodev,noexec' if producer else
            'ro,noload,nosuid,nodev,noexec', DEVICE, str(MOUNT)])


def export_build(result):
    inventory = {'version': 1, 'identity': BUILD_ID, 'files': [], 'libraries': [],
                 'build': result, 'preflight': PREFLIGHT}
    for name, entry in OBSERVATIONS.items():
        if not name.startswith('elf-'): continue
        if entry['build_file']:
            path = P(entry['path'])
            if path.parent != WORK/'build/bin' or path.name not in NAMES or not entry['debug_info']:
                raise RuntimeError('Unmeasured build-tree dependency or missing debug information')
            inventory['files'].append({'path': path.name, 'type': 'file',
                                      'bytes': entry['bytes'], 'sha256': entry['sha256']})
        else:
            inventory['libraries'].append({k: entry[k] for k in ['path', 'bytes', 'sha256']})
    validate_payload(inventory, BUILD_ID)
    data = manifest_bytes(inventory)
    if len(data) > 262144: raise RuntimeError('Manifest size budget')
    artifact_mount(True)
    try:
        for entry in inventory['files']:
            copy_blob(WORK/'build/bin'/entry['path'], MOUNT/entry['path'], entry['bytes'], entry['sha256'], DEADLINE)
        (MOUNT/'manifest.json').write_bytes(data)
    finally:
        command('artifact-unmount', ['umount', str(MOUNT)], timeout=120)
    return {'identity': BUILD_ID, 'manifest_sha256': hashlib.sha256(data).hexdigest(),
            'files': 4, 'payload_bytes': sum(entry['bytes'] for entry in inventory['files']), 'unmounted': True}


def consume_build():
    before = sha(P('/var/lib/dpkg/status')); after = apt_preflight()
    artifact_mount(False)
    try:
        with (MOUNT/'manifest.json').open('rb') as stream: data = stream.read(262145)
        inventory = parse_manifest(data, BUILD_ID, EXPECTED_ARTIFACT)
        if after != inventory['preflight']['after_status']:
            raise RuntimeError('Consumer package state differs from producer')
        # Check package-provided files in place. Never overwrite guest system libraries.
        libraries = {}
        for entry in inventory['libraries']:
            if hash_file(P(entry['path']), entry['bytes'], DEADLINE) != entry['sha256']:
                raise RuntimeError('Consumer library differs: ' + entry['path'])
            libraries[entry['path']] = entry['sha256']
        target = WORK/'build/bin'; target.mkdir(parents=True)
        consume_files(MOUNT, target, inventory, BUILD_ID, DEADLINE)
        for name in sorted(NAMES): (target/name).chmod(0o700)
        # Exercise the read-only attachment on this disposable consumer copy only.
        try:
            fd = os.open(DEVICE, os.O_WRONLY)
            try: os.pwrite(fd, b'X', ARTIFACT_SIZE-1); os.fsync(fd)
            finally: os.close(fd)
        except OSError as error:
            if error.errno not in [errno.EROFS, errno.EPERM, errno.EACCES, errno.EIO]: raise
        else: raise RuntimeError('Read-only artifact accepted a write')
    finally:
        command('artifact-unmount', ['umount', str(MOUNT)], timeout=120)
    # Resolve all four in the new filesystem, and ask its loader to verify each ELF.
    observed = set()
    for index, name in enumerate(sorted(NAMES)):
        path = target/name
        output = command('consumer-loader-'+str(index), ['ldd', str(path)], timeout=30, cap=1024**2).read_text()
        if 'not found' in output: raise RuntimeError('Unresolved consumer dependency: '+name+'\n'+output[-2000:])
        paths = []
        for line in output.splitlines():
            match = re.search(r'(?:=>\s+)?(/\S+)\s+\(0x[0-9a-f]+\)', line)
            if match: paths.append(str(P(match[1]).resolve(strict=True)))
            elif line.strip() and not line.strip().startswith('linux-vdso.so.'):
                raise RuntimeError('Unrecognized consumer loader output: '+line[:500])
        if not paths or any(path not in libraries for path in paths):
            raise RuntimeError('Consumer dependency outside measured package set')
        observed.update(paths)
        command('consumer-verify-'+str(index), ['/lib64/ld-linux-x86-64.so.2', '--verify', str(path)], timeout=30)
    if observed != set(libraries): raise RuntimeError('Consumer dependency set differs')
    real_utility_suite()
    return {'identity': BUILD_ID, 'manifest_sha256': EXPECTED_ARTIFACT,
            'utility': OBSERVATIONS['utility'], 'binaries': {e['path']: e['sha256'] for e in inventory['files']},
            'libraries': libraries, 'before_status': before, 'after_status': after,
            'readonly': True, 'unmounted': True, 'compiled': False}


def build():
    if ROLE == 'consumer': return {'consumer': consume_build()}
    result = original_build()
    artifact = export_build(result)
    return dict(result, artifact=artifact)
