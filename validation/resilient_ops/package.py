"""Finite, hash-pinned package operator. No subprocesses, activation, or adoption.

Preparation is unprivileged. An operator separately reviews and stages this file
under a protected root-owned path, checks its printed digest, and runs it with -I.
Install/upgrade only select immutable code and install the fixed unit definitions.
Enrollment creates fresh target roots and installs a separately reviewed policy.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile

MAX_ASSET = 1024 * 1024
MAX_PACKAGE = 4 * MAX_ASSET
ASSETS = ('engine.py', 'client.py', 'service.py', 'package.py',
          'host.py', 'adopt.py', 'enrollment-contract.json',
          'transition.py','bootstrap.py','ordinary-runtime.py','ordinary-runtime-baseline.py',
          'ordinary-apparmor-baseline','integration-release-baseline.json','ordinary-runtime.patch','worker-release.json','ordinary-unit','ordinary-config.json','ordinary-apparmor',
          'eqemu-resilient-ops.socket', 'eqemu-resilient-ops@.service')
UNITS = ASSETS[-2:]
HEX = re.compile(r'[a-f0-9]{64}\Z')
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z')
UNIT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,190}\.service\Z')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError('unknown or missing schema field')


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('integer out of range')


def path_string(value):
    if (not isinstance(value, str) or not value or '\x00' in value or
            not value.startswith('/') or str(PurePosixPath(value)) != value or
            '..' in PurePosixPath(value).parts or value == '/'):
        raise ValueError('canonical absolute path required')
    return Path(value)


def validate_schema(policy):
    """Pure schema shared by enrollment and execution, without filesystem checks."""
    exact(policy, ('peers', 'targets'))
    if not isinstance(policy['peers'], list) or not 1 <= len(policy['peers']) <= 64:
        raise ValueError('bounded peers required')
    if not isinstance(policy['targets'], dict) or not 0 <= len(policy['targets']) <= 64:
        raise ValueError('bounded targets required')
    peers = set()
    for peer in policy['peers']:
        exact(peer, ('uid', 'gid', 'methods', 'targets', 'actions'))
        for field, choices in (('methods', {'prepare', 'execute', 'status'}),
                               ('actions', {'publish', 'revert', 'recover'})):
            values = peer[field]
            if (not isinstance(values, list) or (field == 'methods' and not values) or
                    any(not isinstance(v, str) for v in values) or
                    len(set(values)) != len(values) or not set(values) <= choices):
                raise ValueError('invalid peer permissions')
        if (not isinstance(peer['targets'], list) or
                any(not isinstance(v, str) or v not in policy['targets'] for v in peer['targets']) or
                len(set(peer['targets'])) != len(peer['targets'])):
            raise ValueError('invalid peer targets')
        integer(peer['uid'], 0, 2**31 - 1)
        integer(peer['gid'], 0, 2**31 - 1)
        pair = (peer['uid'], peer['gid'])
        if pair in peers:
            raise ValueError('duplicate peer')
        peers.add(pair)
    roots = []
    units = set()
    for name, target in policy['targets'].items():
        if not isinstance(name, str) or not IDENTIFIER.fullmatch(name):
            raise ValueError('invalid target ID')
        keys = ('actions', 'resources', 'root', 'units', 'service_uid', 'timeout', 'files', 'max_bytes', 'max_files')
        if 'host_contract' in target:
            exact(target, (*keys, 'host_contract'))
        else:
            exact(target, keys)
        for field, maximum in (('actions', 3), ('resources', 16), ('units', 8), ('files', 256)):
            values = target[field]
            if (not isinstance(values, list) or not 1 <= len(values) <= maximum or
                    any(not isinstance(x, str) or not x or len(x.encode()) > 512 for x in values) or
                    len(set(values)) != len(values)):
                raise ValueError('invalid bounded unique list')
        for resource in target['resources']:
            if not IDENTIFIER.fullmatch(resource):
                raise ValueError('invalid resource ID')
        if not set(target['actions']) <= {'publish', 'revert', 'recover'}:
            raise ValueError('unknown action')
        root = path_string(target['root'])
        if any(root == other or root in other.parents or other in root.parents for other in roots):
            raise ValueError('overlapping target roots')
        roots.append(root)
        for unit in target['units']:
            if not UNIT.fullmatch(unit) or unit.startswith('eqemu-resilient-ops') or (unit in units and 'host_contract' not in target):
                raise ValueError('invalid or shared unit')
            units.add(unit)
        integer(target['service_uid'], 1, 2**31 - 1)
        integer(target['timeout'], 1, 120)
        integer(target['max_bytes'], 1, 4 * 1024 * 1024)
        integer(target['max_files'], 1, 256)
        if len(target['files']) > target['max_files']:
            raise ValueError('too many exact release files')
        for item in target['files']:
            relative = PurePosixPath(item)
            if (not relative.parts or '\x00' in item or len(relative.parts) > 8 or len(item) > 200 or relative.is_absolute() or str(relative) != item or
                    any(x in ('', '.', '..') for x in relative.parts)):
                raise ValueError('invalid exact release path')
        files = target['files']
        if any(a != b and a.startswith(b + '/') for a in files for b in files):
            raise ValueError('overlapping release files')
    return policy


def validate_policy(policy):
    """Enrollment adds fixed host-path and caller restrictions to the schema."""
    validate_schema(policy)
    for peer in policy['peers']:
        if (peer['uid'], peer['gid']) != (1000, 1000):
            raise ValueError('only reviewed caller UID/GID 1000 may be enrolled')
    for target in policy['targets'].values():
        root = Path(target['root'])
        if not (str(root).startswith('/var/lib/eqemu-resilient-targets/') and len(root.parts) == 5):
            raise ValueError('target root must be a direct child of /var/lib/eqemu-resilient-targets')
        if 'host_contract' in target:
            from host import validate_target
            validate_target(target)
    return policy


def protected(path, uid=0, leaf_file=False):
    """Walk every component without accepting links or writable ancestors."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('absolute path required')
    for entry in reversed((path, *path.parents)):
        st = entry.lstat()
        kind = stat.S_ISREG if entry == path and leaf_file else stat.S_ISDIR
        if st.st_uid != uid or st.st_mode & 0o022 or not kind(st.st_mode):
            raise ValueError('unprotected installed path')


def read_regular(path, limit=MAX_ASSET):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('regular file required')
        with os.fdopen(fd, 'rb', closefd=False) as source:
            value = source.read(limit + 1)
        if len(value) > limit:
            raise ValueError('asset too large')
        return value
    finally:
        os.close(fd)


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, data, mode=0o600):
    fd, name = tempfile.mkstemp(prefix='.stage-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        fsync_directory(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def manifest_for(assets):
    return {'version': 1, 'assets': {name: digest(data) for name, data in assets.items()}}


def load_package(directory, expected):
    directory = Path(directory)
    if not HEX.fullmatch(expected):
        raise ValueError('exact manifest SHA256 required')
    # Reject extra assets, links and directories, including hidden files.
    if set(os.listdir(directory)) != set(ASSETS) | {'manifest.json'}:
        raise ValueError('unknown or missing package asset')
    raw = read_regular(directory / 'manifest.json', 65536)
    if digest(raw) != expected:
        raise ValueError('manifest hash mismatch')
    manifest = decode(raw)
    exact(manifest, ('version', 'assets'))
    if manifest['version'] != 1 or type(manifest['version']) is not int:
        raise ValueError('unsupported manifest')
    exact(manifest['assets'], ASSETS)
    assets = {name: read_regular(directory / name) for name in ASSETS}
    if sum(map(len, assets.values())) > MAX_PACKAGE or manifest != manifest_for(assets):
        raise ValueError('package hash mismatch')
    return assets, raw


def prepare(source, output, policy_path=None, expected_assets=None):
    """Copy a finite source set; print commands only, never install or activate."""
    source, output = Path(source).absolute(), Path(output).absolute()
    assets = {name: read_regular(source / name) for name in ASSETS}
    if expected_assets is not None and manifest_for(assets)['assets'] != expected_assets:
        raise ValueError('source bytes differ from selected committed tree')
    raw = encode(manifest_for(assets))
    if sum(map(len, assets.values())) > MAX_PACKAGE:
        raise ValueError('package too large')
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, data in {**assets, 'manifest.json': raw}.items():
        atomic(output / name, data)
    manifest_hash = digest(raw)
    operator_hash = digest(assets['package.py'])
    operator = '/usr/local/libexec/eqemu-resilient-ops-operator-' + operator_hash + '.py'
    import shlex
    common = ['/usr/bin/python3', '-I', operator, '--expected-operator', operator_hash]
    result = {'manifest_sha256': manifest_hash, 'operator_sha256': operator_hash,
            'review': 'Review every asset. Separately stage package.py at operator_path as root-owned 0600 bytes and externally verify SHA256 before invocation. Enrollment is separate. No activation is performed.',
            'operator_path': operator,
            'host_adoption': {'enabled': False, 'contract_sha256': assets and digest(assets['enrollment-contract.json']), 'operator_sha256': digest(assets['adopt.py']), 'requirement': 'Separately stage and verify the entire immutable release, inspect adopt.py, and run /usr/bin/python3 -I RELEASE/adopt.py --expected-operator SHA256 --confinement-reviewed only after confinement/launcher review. No host adoption is performed by installation.'},
            'install_argv': common + ['install', '--package', str(output), '--expected-manifest', manifest_hash, '--expected-active', 'absent'],
            'upgrade_argv': common + ['upgrade', '--package', str(output), '--expected-manifest', manifest_hash, '--expected-active', 'REVIEWED_CURRENT_MANIFEST_SHA256'],
            'rollback_argv': common + ['rollback', '--release', 'REVIEWED_PREVIOUS_MANIFEST_SHA256', '--expected-active', manifest_hash],
            'uninstall_argv': common + ['uninstall', '--expected-active', manifest_hash],
            'install_command': shlex.join(common + ['install', '--package', str(output), '--expected-manifest', manifest_hash, '--expected-active', 'absent'])}
    bootstrap_hash = digest(assets['bootstrap.py'])
    bootstrap = '/usr/local/libexec/eqemu-resilient-ops-bootstrap-' + bootstrap_hash + '.py'
    release = '/usr/lib/eqemu-resilient-ops/releases/' + manifest_hash
    result['bootstrap_sha256'] = bootstrap_hash
    result['bootstrap_root_recipe'] = [
        ['/usr/bin/install','-o','root','-g','root','-m','0600','--',str(output/'bootstrap.py'),bootstrap],
        ['/usr/bin/sha256sum','--',bootstrap],
        ['/usr/bin/python3','-I',bootstrap,'--expected-bootstrap',bootstrap_hash,
         '--package',str(output),'--expected-manifest',manifest_hash],
        ['/usr/bin/sha256sum','--',operator]]
    result['verify_argv'] = common + ['verify','--package',str(output),'--expected-manifest',manifest_hash,'--expected-active',manifest_hash]
    result['adoption_argv'] = ['/usr/bin/python3','-I',release+'/adopt.py','--expected-operator',
                              digest(assets['adopt.py']),'--confinement-reviewed',
                              '--state-manifest','/root/eqemu-rootops-state-selection.json',
                              '--expected-state-manifest','EXTERNALLY_REVIEWED_PRIVATE_STATE_SELECTION_SHA256']
    result['confinement_argv'] = ['/usr/sbin/apparmor_parser','--replace','/etc/apparmor.d/eqemu-validator']
    result['rollback_limit'] = 'Package rollback cannot undo host adoption. Retained original authority bytes and state are evidence, not an automatic reinstall recipe. Publisher masks must remain until a separately reviewed namespace rollback. Do not run any old publisher against adopted sealed releases.'
    if policy_path is not None:
        policy_path = Path(policy_path).absolute()
        policy_raw = read_regular(policy_path, 65536)
        validate_policy(decode(policy_raw))
        result['policy_sha256'] = digest(policy_raw)
        result['enroll_argv'] = common + ['enroll', '--policy', str(policy_path), '--expected-policy', digest(policy_raw)]
    return result


class Operator:
    """Mutations are confined to these fixed additive assets and fresh roots.

    base is solely a test seam; the command line cannot override host paths.
    Releases, enrollment receipts and operation state survive rollback/uninstall.
    """
    def __init__(self, base=Path('/'), trusted_uid=0):
        self.base = Path(base)
        self.uid = trusted_uid
        self.code = self.base / 'usr/lib/eqemu-resilient-ops'
        self.state = self.base / 'var/lib/eqemu-resilient-ops'
        self.config = self.base / 'etc/eqemu-resilient-ops'
        self.units = self.base / 'etc/systemd/system'

    def mkdir(self, path, mode=0o700):
        # Internal fixed namespaces only. Revisit ancestors on explicit retries:
        # existence after an interrupted effect does not establish durability.
        if path != self.base:
            if self.base not in path.parents:
                raise ValueError('directory outside package namespace')
            self.mkdir(path.parent)
        elif not path.exists():
            protected(path.parent, self.uid)
        if not path.exists():
            path.mkdir(mode=mode)
            os.chmod(path, mode)
        protected(path, self.uid)
        fsync_directory(path)
        if path.parent != path:
            fsync_directory(path.parent)

    def initialize(self):
        for path in (self.code / 'releases', self.state / 'package-events', self.units):
            self.mkdir(path)
        lock = self.state / 'package.lock'
        fd = os.open(lock, os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
        try:
            protected(lock, self.uid, leaf_file=True)
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.fsync(fd)
            fsync_directory(self.state)
        except BaseException:
            os.close(fd)
            raise
        return os.fdopen(fd, 'rb')

    def active(self):
        if set(os.listdir(self.code)) - {'releases', 'current'}:
            raise ValueError('unknown package namespace asset; review required')
        for entry in (self.code / 'releases').iterdir():
            if not HEX.fullmatch(entry.name):
                raise ValueError('unknown or interrupted release asset; review required')
        current = self.code / 'current'
        if not current.is_symlink():
            if current.exists():
                raise ValueError('unknown current asset')
            return 'absent'
        link = os.readlink(current)
        if not link.startswith('releases/') or not HEX.fullmatch(link[9:]):
            raise ValueError('unknown current pointer')
        self.verify_release(link[9:])
        return link[9:]

    def verify_release(self, release):
        if not HEX.fullmatch(release):
            raise ValueError('invalid release hash')
        path = self.code / 'releases' / release
        protected(path, self.uid)
        for name in (*ASSETS, 'manifest.json'):
            protected(path / name, self.uid, leaf_file=True)
        return load_package(path, release)

    def check_units(self, active):
        expected = self.verify_release(active)[0] if active != 'absent' else None
        for name in UNITS:
            path = self.units / name
            if path.exists() or path.is_symlink():
                protected(path, self.uid, leaf_file=True)
                if expected is None or read_regular(path) != expected[name]:
                    raise ValueError('unknown installed unit asset')
            elif expected is not None:
                raise ValueError('missing installed unit')

    def select(self, release):
        temporary = self.code / '.next'
        if temporary.exists() or temporary.is_symlink():
            raise ValueError('unexpected staged pointer; review interrupted package')
        temporary.symlink_to('releases/' + release)
        os.replace(temporary, self.code / 'current')
        fsync_directory(self.code)

    def event(self, action, previous, selected):
        import uuid
        atomic(self.state / 'package-events' / (uuid.uuid4().hex + '.json'),
               encode({'action': action, 'previous': previous, 'selected': selected}))

    def apply(self, action, expected_active, package=None, expected_manifest=None, release=None):
        if action not in ('install', 'upgrade', 'rollback', 'uninstall'):
            raise ValueError('unknown package action')
        # Read and hash untrusted stage before any installed mutation.
        staged = load_package(package, expected_manifest) if action in ('install', 'upgrade') else None
        with self.initialize():
            active = self.active()
            if active != expected_active:
                raise ValueError('active release changed')
            if (action == 'install') != (active == 'absent'):
                raise ValueError('install requires absent; other actions require installed package')
            self.check_units(active)
            if staged:
                assets, manifest = staged
                release = expected_manifest
                destination = self.code / 'releases' / release
                if destination.exists():
                    self.verify_release(release)
                else:
                    # Stage root-owned fresh bytes. Interrupted stages remain evidence.
                    stage = Path(tempfile.mkdtemp(prefix='.stage-', dir=destination.parent))
                    for name, data in {**assets, 'manifest.json': manifest}.items():
                        atomic(stage / name, data)
                    os.rename(stage, destination)
                # Also sync a retained release when retrying an interrupted install.
                # Persist the release name before current can reference it.
                fsync_directory(destination.parent)
            elif action == 'rollback':
                assets, _ = self.verify_release(release)
            if action == 'uninstall':
                self.event(action + '-intent', active, 'absent')
                for name in UNITS:
                    (self.units / name).unlink()
                fsync_directory(self.units)
                (self.code / 'current').unlink()
                fsync_directory(self.code)
                selected = 'absent'
            else:
                # Unit changes require a separately designed transition, never overwrite
                # live unit semantics as an incidental code upgrade.
                if active != 'absent':
                    old = self.verify_release(active)[0]
                    if any(old[name] != assets[name] for name in UNITS):
                        raise ValueError('unit transition requires separate review')
                self.event(action + '-intent', active, release)
                for name in UNITS:
                    atomic(self.units / name, assets[name], 0o644)
                self.select(release)
                selected = release
            self.event(action, active, selected)
            return {'selected': selected, 'activation_performed': False,
                    'systemd_reload_required': True, 'state_and_releases_preserved': True}

    def enroll(self, policy_path, expected_policy):
        raw = read_regular(policy_path, 65536)
        if not HEX.fullmatch(expected_policy) or digest(raw) != expected_policy:
            raise ValueError('exact reviewed policy hash required')
        policy = validate_policy(decode(raw))
        if any('host_contract' in t for t in policy['targets'].values()):
            raise ValueError('host enrollment requires the separately reviewed fixed adoption operator')
        with self.initialize():
            self.mkdir(self.config)
            if (self.config / 'policy.json').exists() or (self.config / 'policy.json').is_symlink():
                raise ValueError('policy exists; policy upgrade/adoption needs separate review')
            intent = self.state / 'enrollment-intent.json'
            record = {'policy_sha256': expected_policy, 'phase': 'intent'}
            retry = intent.exists() or intent.is_symlink()
            if retry:
                protected(intent, self.uid, leaf_file=True)
                if decode(read_regular(intent, 65536)) != record:
                    raise ValueError('enrollment already completed or intent content conflict')
            roots = [self.base / target['root'].lstrip('/') for target in policy['targets'].values()]
            for root in roots:
                # Existing roots are reusable only under this exact incomplete
                # enrollment intent, and only while still protected and empty.
                if root.exists() or root.is_symlink():
                    if not retry:
                        raise ValueError('adoption forbidden; fresh target roots required')
                    protected(root, self.uid)
                    if stat.S_IMODE(root.stat().st_mode) != 0o711 or any(root.iterdir()):
                        raise ValueError('interrupted enrollment root contains unknown state')
                self.mkdir(root.parent, 0o711)
                if root.parent.stat().st_mode & 0o111 != 0o111:
                    raise ValueError('dedicated target parent must be traversable')
            # Re-sync identical intent on retry before any further effect.
            atomic(intent, encode(record))
            self.event('enroll-intent', 'absent', expected_policy)
            for root in roots:
                self.mkdir(root, 0o711)
            for name in ('plans', 'requests', 'operations', 'locks'):
                self.mkdir(self.state / name)
            atomic(self.config / 'policy.json', raw)
            atomic(intent, encode({**record, 'phase': 'complete'}))
            self.event('enroll', 'absent', expected_policy)
            return {'enrolled': expected_policy, 'activation_performed': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-operator', required=True)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('install', 'upgrade', 'rollback', 'uninstall', 'verify'):
        command = commands.add_parser(action)
        command.add_argument('--expected-active', required=True)
        if action in ('install', 'upgrade','verify'):
            command.add_argument('--package', type=Path, required=True)
            command.add_argument('--expected-manifest', required=True)
        if action == 'rollback':
            command.add_argument('--release', required=True)
    enroll = commands.add_parser('enroll')
    enroll.add_argument('--policy', type=Path, required=True)
    enroll.add_argument('--expected-policy', required=True)
    args = vars(parser.parse_args(argv))
    expected = args.pop('expected_operator')
    operator = Path(__file__).absolute()
    if os.geteuid() != 0:
        raise ValueError('external reviewed root operator required')
    protected(operator, leaf_file=True)
    if not HEX.fullmatch(expected) or digest(read_regular(operator)) != expected:
        raise ValueError('operator hash mismatch')
    instance = Operator()
    action = args.pop('action')
    if action == 'verify':
        load_package(args['package'], args['expected_manifest'])
        if instance.active() != args['expected_active'] or args['expected_active'] != args['expected_manifest']:
            raise ValueError('selected installed package differs')
        instance.verify_release(args['expected_manifest'])
        instance.check_units(args['expected_manifest'])
        print(json.dumps({'verified':args['expected_manifest'],'activation_performed':False}))
        return
    result = instance.enroll(args['policy'], args['expected_policy']) if action == 'enroll' else instance.apply(action, **args)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
