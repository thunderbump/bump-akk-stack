"""Fixed maintenance capabilities. Root never imports worker or candidate code."""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess

CODE = Path('/srv/eqemu-validator-code')
STATE = CODE / '.maintenance-v1'
LOCK = Path('/var/lib/eqemu-validator/worker.lock')
SOCKET = '/run/eqemu-validator-maintenance.sock'
FIXTURE = 'validation/actor-integration-fixture.json'
RELEASE = 'integration-release.json'
PAIR = (FIXTURE, RELEASE)
REQUEST_LIMIT = 196608
RESPONSE_LIMIT = 131072
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME
PROTOCOL_PATH = 'rust/actors/bridge/protocol/integration-v1.4.json'
LOCK_PATH = 'rust/actors/Cargo.lock'


class Refusal(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode() + b'\n'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'schema')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False, 'schema'))
    except (ValueError, UnicodeError):
        raise Refusal('schema') from None


def hex_value(value, width):
    require(type(value) is str and re.fullmatch('[0-9a-f]{%d}' % width, value), 'schema')
    return value


def metadata(info):
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid,
                gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))


def read(path, limit=131072):
    fd = os.open(path, FLAGS)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'file-type-or-bound')
        raw = os.pread(fd, limit + 1, 0)
        require(len(raw) == info.st_size and info == os.fstat(fd)
                and info == path.lstat(), 'file-changed')
        return raw, dict(metadata(info), bytes=len(raw), sha256=sha(raw))
    finally:
        os.close(fd)


@contextlib.contextmanager
def directory(path, owner=0, monitored=None):
    """Hold protected ancestors; check named/FD identities through exit."""
    fds = []
    links = []
    monitored = monitored or {}
    current = Path("/")
    try:
        fd = os.open('/', FLAGS | os.O_DIRECTORY)
        fds.append(fd)
        require(os.fstat(fd).st_uid == 0 and not os.fstat(fd).st_mode & 0o022, 'parent')
        for name in path.parts[1:]:
            parent = fd
            fd = os.open(name, FLAGS | os.O_DIRECTORY, dir_fd=parent)
            fds.append(fd)
            info = os.fstat(fd)
            current = current / name
            if str(current) in monitored:
                require(metadata(info) == monitored[str(current)], 'monitored-parent-drift')
            else:
                require(info.st_uid == owner and not info.st_mode & 0o022, 'parent')
            links.append((parent, name, fd, metadata(info)))
        def check():
            for parent, name, held, expected in links:
                require(metadata(os.fstat(held)) == expected
                        and metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)) == expected, 'parent-changed')
        yield fd, check
        check()
    finally:
        for fd in reversed(fds):
            os.close(fd)


def mount_identity(path):
    fd = os.open(path, FLAGS | os.O_DIRECTORY)
    try:
        with open('/proc/self/fdinfo/' + str(fd)) as stream:
            fields = dict(line.split(':', 1) for line in stream.read(4097).splitlines() if ':' in line)
        value = fields.get('mnt_id', '').strip()
        require(value.isascii() and value.isdecimal(), 'mount-unknown')
        return int(value)
    finally:
        os.close(fd)


def same_mount(code, state):
    paths = (code, state, (code / FIXTURE).parent, (code / RELEASE).parent)
    require(len({mount_identity(path) for path in paths}) == 1, 'cross-mount-layout')


def present(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def write_new(parent, name, raw, mode=0o600):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
    try:
        os.fchmod(fd, mode)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            require(count > 0, 'write')
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent)


def atomic(parent, name, raw, recognized=()):
    temporary = '.' + name + '.new'
    try:
        write_new(parent, temporary, raw)
    except FileExistsError:
        # A crash may retain this exact intended value. Unknown bytes are never
        # removed or adopted; the protected parent and held worker lock serialize.
        fd = os.open(temporary, FLAGS, dir_fd=parent)
        try:
            info = os.fstat(fd)
            existing = os.pread(fd, 131073, 0)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == len(existing)
                    and existing in (raw, *recognized) and info == os.fstat(fd)
                    and info == os.stat(temporary, dir_fd=parent, follow_symlinks=False), 'atomic-interrupted-drift')
        finally:
            os.close(fd)
        if existing != raw:
            os.unlink(temporary, dir_fd=parent)
            os.fsync(parent)
            write_new(parent, temporary, raw)
    os.replace(temporary, name, src_dir_fd=parent, dst_dir_fd=parent)
    os.fsync(parent)


def object_id(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def tree_entries(raw):
    result = {}
    while raw:
        header, separator, tail = raw.partition(b'\0')
        require(separator and len(tail) >= 20 and len(result) < 1024, 'source-proof')
        mode, space, name = header.partition(b' ')
        require(space and name and b'/' not in name and name not in result, 'source-proof')
        result[name] = (mode, tail[:20].hex())
        raw = tail[20:]
    return result


def prove_source(source, proof, fixture):
    require(type(source) is dict and set(source) == {'commit', 'tree', 'rust_tree'}, 'schema')
    for value in source.values():
        hex_value(value, 40)
    names = {'commit', '', 'rust', 'rust/actors', 'rust/actors/bridge',
             'rust/actors/bridge/protocol', LOCK_PATH, PROTOCOL_PATH}
    require(type(proof) is dict and set(proof) == names, 'source-proof')
    objects = {}
    for name, encoded in proof.items():
        require(type(encoded) is str and len(encoded) <= 87384, 'source-proof')
        try:
            objects[name] = base64.b64decode(encoded, validate=True)
        except ValueError:
            raise Refusal('source-proof') from None
        require(len(objects[name]) <= 65536, 'source-proof')
    commit = objects['commit']
    require(object_id('commit', commit) == source['commit']
            and commit.split(b'\n', 1)[0] == b'tree ' + source['tree'].encode(), 'source-proof')
    expected = source['tree']
    for path in ('', 'rust', 'rust/actors', 'rust/actors/bridge', 'rust/actors/bridge/protocol'):
        require(object_id('tree', objects[path]) == expected, 'source-proof')
        entries = tree_entries(objects[path])
        if path == 'rust':
            require(expected == source['rust_tree'], 'source-proof')
        next_name = {'': b'rust', 'rust': b'actors', 'rust/actors': b'bridge',
                     'rust/actors/bridge': b'protocol'}.get(path)
        if next_name:
            require(next_name in entries and entries[next_name][0] == b'40000', 'source-proof')
            expected = entries[next_name][1]
        if path in ('rust/actors', 'rust/actors/bridge/protocol'):
            file_path = LOCK_PATH if path == 'rust/actors' else PROTOCOL_PATH
            leaf = file_path.rsplit('/', 1)[1].encode()
            require(leaf in entries and entries[leaf][0] == b'100644'
                    and object_id('blob', objects[file_path]) == entries[leaf][1], 'source-proof')
    require(sha(objects[LOCK_PATH]) == fixture['rust_input']['lock_sha256']
            and len(objects[LOCK_PATH]) == fixture['rust_input']['lock_bytes'], 'source-contract')
    require(sha(objects[PROTOCOL_PATH]) == 'c604e154baf96908e2d6707714875924a198793438ec219565f05dc4e6cf6eb0', 'source-contract')


def repin(fixture_raw, release_raw, source):
    fixture = decode(fixture_raw)
    old = fixture['server_source']
    result = fixture_raw
    for key in ('commit', 'tree', 'rust_tree'):
        if old[key] != source[key]:
            before, after = ('"' + old[key] + '"').encode(), ('"' + source[key] + '"').encode()
            require(result.count(before) == 1, 'binding-encoding')
            result = result.replace(before, after)
    wanted = decode(fixture_raw)
    wanted['server_source'].update(source)
    require(decode(result) == wanted, 'binding-encoding')
    release = decode(release_raw)
    release['files'][FIXTURE].update(bytes=len(result), sha256=sha(result))
    return {FIXTURE: result, RELEASE: canonical(release)}


class Host:
    def socket_active(self):
        value = subprocess.run(['/usr/bin/systemctl', 'is-active', 'eqemu-validator.socket'],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
        require((value.returncode, value.stdout) in ((0, b'active\n'), (3, b'inactive\n')), 'socket-unknown')
        return value.returncode == 0

    def socket(self, active):
        subprocess.run(['/usr/bin/systemctl', 'start' if active else 'stop', 'eqemu-validator.socket'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        require(self.socket_active() == active, 'socket-unconfirmed')

    def quiescent(self):
        result = subprocess.run(['/usr/bin/systemctl', 'list-units', '--type=service',
                                 '--state=activating,active,deactivating', '--no-legend', '--no-pager',
                                 'eqemu-validator@*.service', 'eqemu-validator-asan-v*@*.service',
                                 'eqemu-validator-profiling@*.service'], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=5)
        require(result.returncode == 0 and not result.stdout.strip(), 'worker-active')
        for suffix in ('', '-asan-v1', '-asan-v2', '-asan-v3', '-profiling'):
            path = Path('/var/lib/eqemu-validator' + suffix) / 'active.json'
            require(not present(path), 'active-record')

    @contextlib.contextmanager
    def guard(self):
        fd = os.open(LOCK, FLAGS)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (995, 980, 0o600), 'worker-lock')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refusal('worker-busy') from None
            self.quiescent()
            yield
            self.quiescent()
            require(info == os.fstat(fd) and info == LOCK.lstat(), 'worker-lock-changed')
        finally:
            os.close(fd)


class Store:
    """Two fixed JSON assets, protected backups, explicit interrupted rollback."""
    def __init__(self, config, host=None, code=CODE, state=STATE, owner=0):
        self.config, self.host = config, host or Host()
        self.code, self.state, self.owner = code, state, owner

    def load(self, path):
        raw, item = read(path)
        require((item['uid'], item['gid'], item['mode']) == (self.owner, self.owner, 0o600), 'journal-metadata')
        return decode(raw)

    def head(self):
        path = self.state / 'head.json'
        return self.load(path) if present(path) else {'transaction': None, 'records': self.config['records']}

    def pending(self):
        path = self.state / 'pending.json'
        return self.load(path) if present(path) else None

    def snapshot(self, records):
        actual = {}
        for name, expected in records.items():
            path = self.code / name
            with directory(path.parent, self.owner, monitored={} if name in PAIR else self.config.get("monitored_directories", {})):
                _, actual[name] = read(path)
            require(actual[name] == expected, 'installed-drift')
        for path, expected in self.config.get('policies', {}).items():
            with directory(Path(path).parent, self.owner):
                require(read(Path(path))[1] == expected, 'policy-drift')
        return actual

    def binding(self, records):
        fixture, _ = read(self.code / FIXTURE)
        release, _ = read(self.code / RELEASE)
        base_fixture = decode(base64.b64decode(self.config['fixture']))
        actual = decode(fixture)
        base_fixture['server_source'] = actual['server_source']
        require(actual == base_fixture, 'fixture-drift')
        base_release = decode(base64.b64decode(self.config['release']))
        current = decode(release)
        base_release['files'][FIXTURE] = current['files'][FIXTURE]
        require(current == base_release, 'release-drift')
        for name, item in current['files'].items():
            require(all(records[name][key] == value for key, value in item.items()), 'release-drift')
        return fixture, release

    def overview(self):
        head = self.head()
        pending = self.pending()
        require(pending is not None or not present(self.state / '.head.json.new'), 'journal-drift')
        if pending:
            return dict(state='interrupted', transaction=pending['id'], archive_supported=False)
        records = self.snapshot(head['records'])
        fixture, _ = self.binding(records)
        return dict(state='ready', source=decode(fixture)['server_source'], expected=sha(canonical(records)),
                    transaction=head['transaction'], archive_supported=False,
                    retention_present=self.retention())

    def retention(self):
        try:
            Path('/var/lib/eqemu-validator/last-integration').lstat()
            return True
        except FileNotFoundError:
            return False
        except PermissionError:
            return None

    def event(self, tx, name, value):
        with directory(tx, self.owner) as (fd, _):
            write_new(fd, name + '.json', canonical(value))

    def record_once(self, tx, name, value):
        path = tx / (name + '.json')
        if present(path):
            raw,item=read(path)
            require((item['uid'],item['gid'],item['mode']) == (self.owner,self.owner,0o600)
                    and raw == canonical(value), 'receipt-drift')
        else:
            self.event(tx, name, value)

    def finish(self, tx, head, response):
        self.record_once(tx, 'result', response)
        with directory(self.state, self.owner) as (fd, _):
            atomic(fd, 'head.json', canonical(head))
            os.unlink('pending.json', dir_fd=fd)
            os.fsync(fd)

    def publish(self, request):
        require(self.pending() is None, 'interrupted')
        require(not present(self.state / '.head.json.new'), 'journal-drift')
        before = self.head()
        records = self.snapshot(before['records'])
        require(sha(canonical(records)) == request['expected'], 'stale-binding')
        fixture, release = self.binding(records)
        prove_source(request['source'], request['proof'], decode(fixture))
        require(request['source'] != {key: decode(fixture)['server_source'][key] for key in request['source']}, 'binding-unchanged')
        updates = repin(fixture, release, request['source'])
        same_mount(self.code, self.state)
        tx = self.state / request['id']
        tx.mkdir(mode=0o700)
        with directory(tx, self.owner) as (fd, _):
            for index, name in enumerate(PAIR):
                os.link(self.code / name, tx / ('old%d' % index), follow_symlinks=False)
                write_new(fd, 'new%d' % index, updates[name], 0o644)
            after = dict(records)
            for index, name in enumerate(PAIR):
                after[name] = read(tx / ('new%d' % index))[1]
            header = dict(request={key:value for key,value in request.items() if key!='proof'},
                          proof_sha256=sha(canonical(request['proof'])), before=before, after=after, prior_socket=self.host.socket_active())
            require(len(canonical(header)) <= 65536, 'intent-bound')
            write_new(fd, 'intent.json', canonical(header))
        with directory(self.state, self.owner) as (fd, _):
            write_new(fd, 'pending.json', canonical({'id': request['id']}))
        if header['prior_socket']:
            self.host.socket(False)
        self.host.quiescent()
        self.snapshot(records)
        for index, name in enumerate(PAIR):
            with directory((self.code / name).parent, self.owner) as (fd, _):
                os.replace(tx / ('new%d' % index), Path(name).name, dst_dir_fd=fd)
                os.fsync(fd)
        self.snapshot(after)
        self.binding(after)
        if header['prior_socket']:
            self.host.socket(True)
        require(self.host.socket_active() == header['prior_socket'], 'socket-unconfirmed')
        response = dict(state='published', transaction=request['id'], source=request['source'])
        self.finish(tx, dict(transaction=request['id'], records=after), response)
        return response

    def rollback(self, identifier):
        same_mount(self.code, self.state)
        tx = self.state / identifier
        header = self.load(tx / 'intent.json')
        pending, head = self.pending(), self.head()
        require((pending and pending['id'] == identifier) or (not pending and head['transaction'] == identifier), 'not-current-transaction')
        completed = present(tx / 'rollback.json')
        require(not completed or pending is not None, 'already-rolled-back')
        if completed:
            self.record_once(tx, 'rollback', dict(state='rolled-back', transaction=identifier))
        if present(tx / 'result.json'):
            self.record_once(tx, 'result', dict(state='published', transaction=identifier, source=header['request']['source']))
        current = {}
        for name in self.config['records']:
            current[name] = read(self.code / name)[1]
            require(current[name] in (header['before']['records'][name], header['after'][name]), 'installed-drift')
        self.snapshot(current)
        for index,name in enumerate(PAIR):
            require(read(tx / ('old%d' % index))[1] == header['before']['records'][name], 'backup-drift')
            temporary = (self.code/name).parent / ('.maintenance-restore-%d' % index)
            if present(temporary):
                require(read(temporary)[1] == header['before']['records'][name], 'restore-temporary-drift')
        staged_head = self.state / '.head.json.new'
        if present(staged_head):
            raw,item=read(staged_head)
            require((item['uid'],item['gid'],item['mode'])==(self.owner,self.owner,0o600) and raw in
                    (canonical(header['before']),canonical(dict(transaction=identifier,records=header['after']))), 'atomic-interrupted-drift')
        prior = header['prior_socket']
        if not pending:
            with directory(self.state, self.owner) as (fd, _):
                write_new(fd, 'pending.json', canonical({'id': identifier}))
        if self.host.socket_active():
            self.host.socket(False)
        self.host.quiescent()
        for index, name in enumerate(PAIR):
            old_path = tx / ('old%d' % index)
            require(read(old_path)[1] == header['before']['records'][name], 'backup-drift')
            with directory((self.code / name).parent, self.owner) as (fd, _):
                temporary = '.maintenance-restore-%d' % index
                try:
                    os.link(old_path, temporary, dst_dir_fd=fd, follow_symlinks=False)
                except FileExistsError:
                    require(read((self.code / name).parent / temporary)[1] == header['before']['records'][name], 'restore-temporary-drift')
                os.replace(temporary, Path(name).name, src_dir_fd=fd, dst_dir_fd=fd)
                os.fsync(fd)
        self.snapshot(header['before']['records'])
        self.binding(header['before']['records'])
        if prior:
            self.host.socket(True)
        require(self.host.socket_active() == prior, 'socket-unconfirmed')
        response = dict(state='rolled-back', transaction=identifier)
        self.record_once(tx, 'rollback', response)
        with directory(self.state, self.owner) as (fd, _):
            atomic(fd, 'head.json', canonical(header['before']),
                   recognized=(canonical(dict(transaction=identifier, records=header['after'])),))
            os.unlink('pending.json', dir_fd=fd)
            os.fsync(fd)
        return response


def validate_request(request):
    require(type(request) is dict and request.get('schema') == 1 and type(request['schema']) is int, 'schema')
    hex_value(request.get('id'), 32)
    op = request.get('op')
    fields = {'schema', 'id', 'op'}
    if op == 'publish':
        fields |= {'expected', 'source', 'proof'}
        hex_value(request.get('expected'), 64)
    elif op == 'rollback':
        fields.add('transaction')
        hex_value(request.get('transaction'), 32)
    else:
        require(op in ('health', 'status', 'diagnose', 'fixture'), 'unsupported-operation')
    require(set(request) == fields, 'schema')
    return op


def dispatch(request, config, store):
    op = validate_request(request)
    if op == 'health':
        return dict(service='eqemu-validator-maintenance-v1', schema=1, root=os.geteuid() == 0)
    with store.host.guard(), directory(store.state, store.owner):
        if op in ('status', 'diagnose'):
            value=store.overview()
            if op=='diagnose':
                same_mount(store.code,store.state)
                value.update(same_mount=True, checks=['worker-lock','active-work','installed-closure','policy','journal'],
                             archive_reason='unsupported-separate-02fee-maintenance', automatic_retry=False)
            return value
        if op == 'fixture':
            require(store.pending() is None, 'interrupted')
            records = store.snapshot(store.head()['records'])
            raw, _ = store.binding(records)
            return dict(fixture=base64.b64encode(raw).decode(), sha256=sha(raw))
        if op == 'publish':
            return store.publish(request)
        return store.rollback(request['transaction'])


def serve(connection, config, store):
    """One peer, one bounded JSON line, no retry or caller-selected code."""
    connection.settimeout(10)
    identifier = None
    try:
        pid, uid, gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(uid == config['submitter_uid'] and gid == config['submitter_gid'], 'peer-denied')
        raw = bytearray()
        while b'\n' not in raw:
            block = connection.recv(min(4096, REQUEST_LIMIT + 1 - len(raw)))
            require(block, 'request-incomplete')
            raw.extend(block)
            require(len(raw) <= REQUEST_LIMIT, 'request-bound')
        require(raw.count(b'\n') == 1 and raw.endswith(b'\n'), 'schema')
        request = decode(raw)
        identifier = hex_value(request.get('id'), 32)
        data = dispatch(request, config, store)
        value = dict(schema=1, id=identifier, ok=True, result=data)
    except Refusal as error:
        value = dict(schema=1, id=identifier, ok=False, reason=str(error))
    except Exception:
        value = dict(schema=1, id=identifier, ok=False, reason='io-or-interruption')
    raw = canonical(value)
    require(len(raw) <= RESPONSE_LIMIT, 'response-bound')
    connection.sendall(raw)
    return value
