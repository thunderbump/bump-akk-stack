"""One fixed, bounded integration artifact. No paths or commands travel on the wire."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SELECTION = 'central-cdau-integration-v1'
NAME = SELECTION + '.json'
PREFIX = b'EQEMU_INTEGRATION '
CAP = 851968
CHUNK = 4096
FRAME_CAP = 6144
WIRE_CAP = 1280000
FIXTURE_SHA = 'cf71b70acf549328552b3c203d2760571cb40b4d816f8aaf0ee447629039c48c'
CONTRACT_SHA = 'fa89512eeb7071570acd6b3fdc35affa65f9d178c553869e3dce1d5a5d8bfc4a'


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('integration-schema')
        value[key] = item
    return value


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: fail())


def fail():
    raise ValueError('integration-schema')


def hex_string(value, width):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{' + str(width) + '}', value):
        fail()
    return value


def binding(candidate, run_id, fixture=FIXTURE_SHA):
    return dict(version=1, name=NAME, candidate=hex_string(candidate, 40),
                run_id=hex_string(run_id, 32), fixture_sha256=hex_string(fixture, 64))


def wire(frame):
    raw = PREFIX + encoded(frame) + b'\n'
    if len(raw) > FRAME_CAP:
        fail()
    return raw


def frames(raw, candidate, run_id, *, complete, gaps, overflow):
    """Frame actual bytes, including a truthful incomplete prefix on failure."""
    if not isinstance(raw, bytes) or len(raw) > CAP or any(type(v) is not bool for v in (complete, gaps, overflow)):
        fail()
    fixed = binding(candidate, run_id)
    yield dict(fixed, kind='begin', cap=CAP)
    for sequence, offset in enumerate(range(0, len(raw), CHUNK)):
        block = raw[offset:offset + CHUNK]
        yield dict(fixed, kind='data', sequence=sequence, offset=offset,
                   sha256=hashlib.sha256(block).hexdigest(), data=base64.b64encode(block).decode('ascii'))
    yield dict(fixed, kind='end', bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
               complete=complete, gaps=gaps, overflow=overflow)


class Sink:
    """Retain a verified prefix at a fixed exclusive 0600 file in a new 0700 directory.

    Original receipt is finalized once. Read-only re-export never changes it.
    Directory/file descriptors remain open through fsync and receipt publication.
    """
    def __init__(self, directory, candidate, run_id):
        self.fixed = binding(candidate, run_id)
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self.fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.stream = None
        try:
            info = os.fstat(self.fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                fail()
            fd = os.open(NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            self.stream = os.fdopen(fd, 'wb')
        except BaseException:
            os.close(self.fd)
            raise
        self.digest = hashlib.sha256()
        self.total = self.sequence = self.wire_bytes = self.count = 0
        self.begun = self.ended = self.valid = self.finalized = False
        self.error = None
        try:
            fd = os.open('pending.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(encoded(self.fixed) + b'\n'); stream.flush(); os.fsync(stream.fileno())
            os.fsync(self.fd)
        except BaseException:
            self.close()
            raise

    def validate_path(self):
        named=self.directory.lstat();opened=os.fstat(self.fd)
        if (not stat.S_ISDIR(named.st_mode) or (named.st_dev,named.st_ino)!=(opened.st_dev,opened.st_ino)
                or named.st_uid!=os.geteuid() or stat.S_IMODE(named.st_mode)!=0o700): fail()
        file_named=os.stat(NAME,dir_fd=self.fd,follow_symlinks=False);file_open=os.fstat(self.stream.fileno())
        if not stat.S_ISREG(file_named.st_mode) or (file_named.st_dev,file_named.st_ino)!=(file_open.st_dev,file_open.st_ino): fail()

    def accept(self, frame):
        """Reject every unexpected field, binding, duplicate, gap and capacity violation."""
        try:
            self.validate_path()
            self._accept(frame)
        except Exception:
            self.error = 'integration-transfer-invalid'
            self.valid = False
            raise ValueError(self.error) from None

    def _accept(self, frame):
        size = len(wire(frame))
        self.wire_bytes += size
        self.count += 1
        if self.error or self.ended or self.count > 210 or self.wire_bytes > WIRE_CAP:
            fail()
        if not isinstance(frame, dict) or any(frame.get(k) != v or type(frame.get(k)) is not type(v) for k, v in self.fixed.items()):
            fail()
        common = set(self.fixed) | {'kind'}
        kind = frame.get('kind')
        if kind == 'begin':
            if self.begun or set(frame) != common | {'cap'} or type(frame['cap']) is not int or frame['cap'] != CAP or size > 1024:
                fail()
            self.begun = True
        elif kind == 'data':
            if not self.begun or set(frame) != common | {'sequence', 'offset', 'sha256', 'data'}:
                fail()
            if (type(frame['sequence']) is not int or frame['sequence'] != self.sequence or self.sequence >= 208
                    or type(frame['offset']) is not int or frame['offset'] != self.total
                    or not isinstance(frame['data'], str) or len(frame['data']) > 5464):
                fail()
            block = base64.b64decode(frame['data'], validate=True)
            if (not 0 < len(block) <= CHUNK or self.total + len(block) > CAP
                    or base64.b64encode(block).decode() != frame['data']
                    or hashlib.sha256(block).hexdigest() != hex_string(frame['sha256'], 64)):
                fail()
            self.stream.write(block)
            self.digest.update(block)
            self.total += len(block)
            self.sequence += 1
        elif kind == 'end':
            if (not self.begun or set(frame) != common | {'bytes', 'sha256', 'complete', 'gaps', 'overflow'}
                    or type(frame['bytes']) is not int or frame['bytes'] != self.total
                    or hex_string(frame['sha256'], 64) != self.digest.hexdigest() or size > 1024
                    or any(type(frame[k]) is not bool for k in ('complete', 'gaps', 'overflow'))):
                fail()
            self.stream.flush()
            os.fsync(self.stream.fileno())
            os.fsync(self.fd)
            self.ended = True
            self.valid = frame['complete'] and not frame['gaps'] and not frame['overflow']
        else:
            fail()

    def ack(self):
        self.validate_path()
        if not self.ended or self.error:
            fail()
        result = dict(version=1, run_id=self.fixed['run_id'], sha256=self.digest.hexdigest(), bytes=self.total, durable=True)
        if len(encoded(result)) + 1 > 256:
            fail()
        return result

    def finish(self, ack=None, *, execution=None):
        """Persist original export uncertainty before returning any terminal outcome."""
        if self.finalized:
            fail()
        try: self.validate_path()
        except (OSError,ValueError): self.error='integration-transfer-invalid';self.valid=False
        durable = ack == self.ack() if self.ended and not self.error else False
        # bools must not compare equal to integer protocol fields.
        durable = durable and all(type(ack[k]) is type(v) for k, v in self.ack().items())
        execution = execution or dict(workload_exit_code=None,validator_exit_code=None,native_cleanup='unknown',database_cleanup='unknown',vm_cleanup='unknown')
        validate_execution(execution)
        receipt = dict(version=1, **{k: self.fixed[k] for k in ('name', 'candidate', 'run_id', 'fixture_sha256')},
                       bytes=self.total, sha256=self.digest.hexdigest(), terminal=self.ended,
                       complete=self.valid and durable, client_durable=bool(durable),
                       original_transfer='durable' if durable else 'uncertain',
                       error=self.error or ('none' if self.valid and durable else 'integration-incomplete'), execution=execution)
        self.stream.flush()
        os.fsync(self.stream.fileno())
        fd = os.open('receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded(receipt) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(self.fd)
        self.finalized = True
        return receipt

    def abandon(self):
        try:
            if not self.finalized:
                self.finish()
        finally:
            self.close()

    def close(self):
        if self.fd is None:
            return
        try:
            if self.stream is not None:
                self.stream.close()
        finally:
            os.close(self.fd)
            self.fd = None


def validate_guest(value):
    """The integration envelope is measured from its actual fixed schema."""
    from actor_integration import validate_result
    required={'version','scope','nonce','exit_code','stage','selected_checks','completed_checks','integration'}
    optional={'zone_sha256','utilities','error','normal_world'}
    if not isinstance(value,dict) or not required<=set(value) or not set(value)<=required|optional:
        fail()
    if value['integration']!=SELECTION or value['scope']!='worker-build' or type(value['version']) is not int or value['version']!=1:
        fail()
    hex_string(value['nonce'],32)
    if type(value['exit_code']) is not int or value['exit_code'] not in (0,1,2): fail()
    if not isinstance(value['stage'],str) or not re.fullmatch('[a-z0-9-]{1,100}',value['stage']): fail()
    selected=['rust-format','rust-dependencies','rust-clippy','rust-tests','rust-doctests',
              'native-configure','native-build','zone-rust-symbol','native-utilities','actor-population-integration']
    if value['selected_checks']!=selected or not isinstance(value['completed_checks'],list): fail()
    completed=value['completed_checks']
    if completed!=selected[:len(completed)]: fail()
    if 'zone_sha256' in value: hex_string(value['zone_sha256'],64)
    if 'error' in value and (not isinstance(value['error'],str) or len(encoded(value['error']))>3500): fail()
    if 'utilities' in value:
        utility=value['utilities']
        if not isinstance(utility,dict) or set(utility)!={'version','selected','started','completed','failed','finalized','passed'}: fail()
        for key in ('version','selected','started','completed','failed'):
            if type(utility[key]) is not int or not 0<=utility[key]<=4294967295: fail()
        if utility['version']!=1 or any(type(utility[k]) is not bool for k in ('finalized','passed')): fail()
    if 'normal_world' in value: validate_result(value['normal_world'])
    if value['exit_code']==0 and (completed!=selected or 'normal_world' not in value or 'utilities' not in value): fail()
    if len(b'EQEMU_WORKER_RESULT ')+len(encoded(value))+1>9714: fail()
    return value


def validate_outer(value):
    """Reserve exact host/guest/receipt budgets without clipping cleanup facts."""
    from actor_integration import validate_result
    host=dict(value)
    guest=host.pop('guest',None)
    receipt=host.pop('integration_receipt',None)
    if guest:
        validate_guest(guest)
    if receipt is not None and len(encoded(receipt))>4096: fail()
    if len(encoded(host))>32768 or len(encoded(value))+1>46578: fail()
    return value


def protected_bytes(directory,name,limit):
    """Read fixed retained assets through the owned directory inode."""
    if name not in (NAME,'pending.json','receipt.json'): fail()
    directory=Path(directory)
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700: fail()
        child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        with os.fdopen(child,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>limit: fail()
            raw=stream.read(limit+1)
            if len(raw)!=info.st_size: fail()
            return raw
    finally: os.close(fd)


def retained(directory,run_id=None):
    """An exact retained receipt survives later ordinary last-result replacement."""
    directory=Path(directory)
    if set(p.name for p in directory.iterdir())!={NAME,'pending.json','receipt.json'}: fail()
    pending=decode(protected_bytes(directory,'pending.json',1024))
    if pending!=binding(pending.get('candidate'),pending.get('run_id')): fail()
    if run_id is not None and pending['run_id']!=run_id: fail()
    raw=protected_bytes(directory,NAME,CAP)
    receipt=decode(protected_bytes(directory,'receipt.json',4096))
    fields={'version','name','candidate','run_id','fixture_sha256','bytes','sha256','terminal','complete','client_durable','original_transfer','error','execution'}
    if (not isinstance(receipt,dict) or set(receipt)!=fields
            or any(receipt.get(k)!=v or type(receipt.get(k)) is not type(v) for k,v in pending.items())
            or type(receipt['bytes']) is not int or receipt['bytes']!=len(raw)
            or receipt['sha256']!=hashlib.sha256(raw).hexdigest()
            or any(type(receipt[k]) is not bool for k in ('terminal','complete','client_durable'))
            or receipt['original_transfer'] not in ('durable','uncertain')
            or receipt['error'] not in ('none','integration-transfer-invalid','integration-incomplete','integration-interrupted')):
        fail()
    validate_execution(receipt['execution'])
    if receipt['complete'] and (not receipt['terminal'] or not receipt['client_durable'] or receipt['original_transfer']!='durable' or receipt['error']!='none'): fail()
    return raw,receipt


def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def remove_retained(directory):
    retained(directory)
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for name in (NAME,'pending.json','receipt.json'): os.unlink(name,dir_fd=fd)
        os.fsync(fd)
    finally: os.close(fd)
    Path(directory).rmdir()


def retain(job,state,run_id):
    """One completed collection plus its current pending successor, under worker lock."""
    job=Path(job);state=Path(state)
    current=job/'integration';target=state/'last-integration';previous=job/'previous-integration'
    if current.exists():
        retained(current,run_id)
        if target.exists():
            retained(target)
            if previous.exists(): fail()
            os.rename(target,previous);sync_directory(state);sync_directory(job)
        elif previous.exists(): retained(previous)
        os.rename(current,target);sync_directory(state);sync_directory(job)
    retained(target,run_id)
    if previous.exists(): remove_retained(previous);sync_directory(job)
    return target


def recover_pending(directory,run_id):
    """Interrupted transfer stays uncertain, including a lost finalization write."""
    directory=Path(directory)
    if (directory/'receipt.json').exists(): return retained(directory,run_id)[1]
    pending=decode(protected_bytes(directory,'pending.json',1024))
    if pending!=binding(pending.get('candidate'),run_id): fail()
    raw=protected_bytes(directory,NAME,CAP)
    receipt=dict(pending,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),terminal=False,complete=False,
                 client_durable=False,original_transfer='uncertain',error='integration-interrupted',
                 execution=dict(workload_exit_code=None,validator_exit_code=None,native_cleanup='unknown',database_cleanup='unknown',vm_cleanup='unknown'))
    fd=os.open(directory/'receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(encoded(receipt)+b'\n');stream.flush();os.fsync(stream.fileno())
    sync_directory(directory)
    return receipt


def replay(directory,run_id,connection):
    """Read-only export never rewrites the original ACK or transfer outcome."""
    raw,original=retained(directory,run_id)
    complete=False
    try:
        from actor_integration import validate_artifact
        value=validate_artifact(raw)
        complete=value['complete'] and not value['overflow'] and value['gaps']==0
    except ValueError: pass
    connection.settimeout(10)
    for frame in frames(raw if complete else b'',original['candidate'],run_id,complete=complete,gaps=not complete,overflow=False):
        connection.sendall(wire(frame))
    ack=bytearray()
    while not ack.endswith(b'\n'):
        block=connection.recv(1)
        if not block or len(ack)>=256: fail()
        ack.extend(block)
    expected=dict(version=1,run_id=run_id,sha256=hashlib.sha256(raw if complete else b'').hexdigest(),bytes=len(raw) if complete else 0,durable=True)
    received=decode(ack)
    if received!=expected or any(type(received[k]) is not type(v) for k,v in expected.items()): fail()
    return dict(version=1,operation='integration-artifacts',scope='integration-export-only',exit_code=0 if complete else 2,
                executed=False,run_id=run_id,integration_receipt=original,reexport_complete=complete)


def validate_execution(value):
    if not isinstance(value,dict) or set(value)!={'workload_exit_code','validator_exit_code','native_cleanup','database_cleanup','vm_cleanup'}: fail()
    for key in ('workload_exit_code','validator_exit_code'):
        if value[key] is not None and (type(value[key]) is not int or value[key] not in (0,1,2)): fail()
    for key in ('native_cleanup','database_cleanup','vm_cleanup'):
        if type(value[key]) is not bool and value[key] not in ('unknown','not-run'): fail()

# Installed ordinary b999 closure plus only the fixed integration additions.
# Source master inventories remain separate and may contain other selections.
INSTALLED_FILES=(
    'validation/worker/runtime.py','validation/worker/guest.py','validation/worker/build_guest.py',
    'validation/worker/normal_world.py','validation/actor.py','validation/actor_runtime.py','validation/debugger.py',
    'validation/runtime-fixture.json','validation/worker/client.py','scripts/check-validation-worker',
    'validation/worker/format_guest.py','validation/worker/snapshot.py','validation/worker/quick_guest.py',
    'validation/worker/quick_snapshot.py','validation/worker/actor_integration.py',
    'validation/worker/integration_artifacts.py','validation/worker/integration-v1.4.json',
    'validation/actor-integration-fixture.json','integration-release.json')


def installed_inventory(code):
    """Verify the independently sealed narrow installed closure; never infer admission."""
    code=Path(code)
    for directory in (code,code/'validation',code/'validation/worker'):
        info=directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o755: fail()
    fd=os.open(code/'integration-release.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o644 or info.st_size>65536: fail()
        manifest=decode(stream.read(65537))
    if (not isinstance(manifest,dict) or set(manifest)!={'schema','selection','source_commit','base_runtime_sha256','files'}
            or manifest['schema']!=1 or type(manifest['schema']) is not int or manifest['selection']!=SELECTION
            or set(manifest['files'])!=set(INSTALLED_FILES)-{'integration-release.json'}): fail()
    hex_string(manifest['source_commit'],40);hex_string(manifest['base_runtime_sha256'],64)
    for name,expected in manifest['files'].items():
        fd=os.open(code/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            actual=dict(bytes=info.st_size,sha256=hashlib.file_digest(stream,'sha256').hexdigest(),uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))
        if not stat.S_ISREG(info.st_mode) or actual!=expected: fail()
    return INSTALLED_FILES
