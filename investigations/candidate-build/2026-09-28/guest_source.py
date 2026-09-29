# Inserted into the fixed producer guest. Never executes candidate code on the host.
import importlib.util
import stat

CANDIDATE_INPUT = '@INPUT_ID@'
CANDIDATE_SEAL = '@MANIFEST_SHA@'
CANDIDATE_FACTS = json.loads('@CANDIDATE_FACTS@')


def verify_materialized(root, source):
    """Check exact regular files and modes, leaving gitlink trees to their own verifier."""
    expected = {entry['path']: entry for entry in source['entries']}
    links = set(source['gitlinks'])
    observed = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        parent = P(directory)
        for name in list(dirs):
            path = parent/name
            if path.is_symlink(): raise RuntimeError('Materialized directory symlink')
            if path.relative_to(root).as_posix() in links: dirs.remove(name)
        for name in files:
            path = parent/name
            relative = path.relative_to(root).as_posix()
            entry = expected.get(relative)
            info = path.lstat()
            if entry is None or not stat.S_ISREG(info.st_mode):
                raise RuntimeError('Unexpected materialized source: ' + relative)
            if (info.st_size != entry['bytes'] or sha(path) != entry['sha256']
                    or bool(info.st_mode & 0o111) != (entry['mode'] == '100755')
                    or info.st_mode & 0o7000):
                raise RuntimeError('Materialized source mismatch: ' + relative)
            observed.add(relative)
    if observed != set(expected): raise RuntimeError('Missing materialized source')


def materialize_candidate(src):
    spec = importlib.util.spec_from_file_location('candidate_inputs', '/opt/eqemu-proof/candidate_inputs.py')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    profile = json.loads(P('/opt/eqemu-proof/candidate-profile.json').read_text())
    mount = P('/opt/candidate-media')
    mount.mkdir()
    command('candidate-mount', ['mount', '-o', 'ro,nosuid,nodev,noexec',
            '/dev/disk/by-label/EQ_CANDIDATE', str(mount)])
    try:
        manifest = verifier.verify(mount, CANDIDATE_SEAL, profile, CANDIDATE_INPUT)
        for name, target in [('eqemu', src), ('websocketpp', src/'submodules/websocketpp')]:
            source = manifest['sources'][name]
            target.mkdir(parents=True, exist_ok=True)
            with tarfile.open(mount/source['archive']['path'], mode='r:') as archive:
                archive.extractall(target, filter='data')
            verify_materialized(target, source)
        # Check the parent again after populating its separately verified gitlink.
        verify_materialized(src, manifest['sources']['eqemu'])
    finally:
        command('candidate-unmount', ['umount', str(mount)])
    emit({'kind': 'observation', 'name': 'candidate', 'value': CANDIDATE_FACTS})
