"""One exact e35 release operation. Input bytes are data, never host commands."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SELECTION = 'fixed-e35-staging-build-export-v1'
OPERATION = 'staging-build-export'
INGRESS_LIMIT = 2 * 1024**3
HELPERS = ('staging_release.py', 'release_artifacts.py', 'staging_guest.py',
           'staging_container.py', 'staging_worker.py', 'staging-release-v1.json')


def contract():
    return json.loads(Path(__file__).with_name('staging-release-v1.json').read_bytes())


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError('release-input-type-or-size')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def request():
    c = contract()
    return dict(version=1, operation=OPERATION, selection=SELECTION,
                candidate=c['combined_manifest']['candidate'], tree=c['combined_manifest']['tree'],
                input_manifest_sha256=c['combined_manifest_sha256'], **c['media'])


def validate_request(value):
    if value != request() or type(value.get('version')) is not int or type(value.get('bytes')) is not int:
        raise ValueError('release-request-binding')


def verify_media(path):
    expected = contract()['media']
    with regular(path, INGRESS_LIMIT) as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        after = os.fstat(stream.fileno())
        fields = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if (fields(before) != fields(after) or before.st_size != expected['bytes'] or digest != expected['sha256']
                or fields(Path(path).lstat()) != fields(after)):
            raise ValueError('release-media-binding')
    return request()


def binding(run):
    if not isinstance(run, str) or not re.fullmatch('[a-f0-9]{32}', run):
        raise ValueError('release-run-binding')
    r = request()
    return {key: r[key] for key in ('selection', 'candidate', 'tree', 'input_manifest_sha256')} | {'run_id': run}


def frontend_identity(root):
    names = ('scripts/build-staging-release', *('validation/worker/' + name for name in HELPERS))
    records = {name: dict(bytes=(root / name).stat().st_size, sha256=sha(root / name)) for name in names}
    return hashlib.sha256(canonical(records)).hexdigest()


def verify_inputs(directory):
    """Exact sixteen files, including the sealed manifest, with no extra names."""
    directory = Path(directory)
    c = contract()
    raw = (directory / 'COMBINED-INPUT-MANIFEST.json').read_bytes()
    if len(raw) > 16384 or hashlib.sha256(raw).hexdigest() != c['combined_manifest_sha256']:
        raise ValueError('release-input-manifest')
    manifest = json.loads(raw)
    if manifest != c['combined_manifest']:
        raise ValueError('release-input-contract')
    expected = {entry['name']: entry for entry in manifest['files']}
    if {p.name for p in directory.iterdir()} != set(expected) | {'COMBINED-INPUT-MANIFEST.json'}:
        raise ValueError('release-input-members')
    for name, entry in expected.items():
        with regular(directory / name, INGRESS_LIMIT) as stream:
            if os.fstat(stream.fileno()).st_size != entry['bytes'] or hashlib.file_digest(stream, 'sha256').hexdigest() != entry['sha256']:
                raise ValueError('release-input-digest')
    return manifest


def validate_storage(info, filesystem):
    """No automatic storage-driver choice, snapshotter or filesystem fallback."""
    status = dict(info.get('DriverStatus', []))
    if (info.get('Driver') != 'overlay2' or filesystem != 'ext4'
            or status.get('Backing Filesystem') not in ('extfs', 'ext4')
            or status.get('Supports d_type') != 'true'
            or status.get('driver-type') == 'io.containerd.snapshotter.v1'):
        raise ValueError('release-storage-unsupported')


def write_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(canonical(value) + b'\n'); stream.flush(); os.fsync(stream.fileno())
    sync_dir(Path(path).parent)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
