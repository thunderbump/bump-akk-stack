"""Policy-bound, per-invocation executor. No uploaded Python is imported here."""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import time
import uuid

MAX_RECORDS = 1000
ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z')


class Rejected(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise Rejected('invalid opaque identifier')
    return value


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, value, mode=0o600):
    """A receipt exists only after file and parent-directory synchronization."""
    tmp = path.parent / ('.tmp-' + uuid.uuid4().hex)
    try:
        with tmp.open('xb') as out:
            os.fchmod(out.fileno(), mode)
            out.write(canonical(value))
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        sync_dir(path.parent)
    finally:
        tmp.unlink(missing_ok=True)


def read(path):
    return json.loads(path.read_bytes())


def protected(path, uid):
    """All existing ancestors must belong to the trusted administrator domain."""
    path = Path(path)
    if not path.is_absolute():
        raise Rejected('administrative requirement: absolute protected resource root')
    for part in [path, *path.parents]:
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
            raise Rejected('administrative requirement: protected root-owned ancestors')


class SystemdManager:
    """Only enrolled units. Application execution remains systemd's responsibility."""
    def _run(self, args, timeout):
        try:
            return subprocess.run(['/usr/bin/systemctl', *args], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  timeout=timeout, check=True, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}).stdout
        except (subprocess.SubprocessError, OSError):
            raise Rejected('owned unit lifecycle unavailable or timed out') from None

    def observe(self, target):
        result = {}
        for unit in target['units']:
            raw = self._run(['show', unit, '--property=User,ActiveState,ControlGroup,LoadState'], target['timeout'])
            values = dict(line.split('=', 1) for line in raw.decode().splitlines() if '=' in line)
            # Numeric users make enrollment independent of mutable NSS names.
            if values.get('User') != str(target['service_uid']) or values.get('LoadState') != 'loaded':
                raise Rejected('administrative requirement: unknown owned unit identity')
            group = values.get('ControlGroup', '')
            populated = False
            if group:
                if not group.startswith('/') or '..' in group.split('/'):
                    raise Rejected('unknown owned cgroup')
                events = Path('/sys/fs/cgroup' + group) / 'cgroup.events'
                try:
                    populated = 'populated 1' in events.read_text()
                except FileNotFoundError:
                    populated = False
            result[unit] = {'active': values['ActiveState'], 'populated': populated}
        return result

    def stop(self, target):
        for unit in target['units']:
            self._run(['stop', '--no-block', unit], target['timeout'])
        deadline = time.monotonic() + target['timeout']
        while True:
            observed = self.observe(target)
            if all(v['active'] == 'inactive' and not v['populated'] for v in observed.values()):
                return
            if time.monotonic() >= deadline:
                raise Rejected('owned writers remain active; conflicting resources fenced')
            time.sleep(.05)

    def start(self, target, before):
        for unit, state in before.items():
            if state['active'] == 'active':
                self._run(['start', unit], target['timeout'])
        observed = self.observe(target)
        if any(observed[u]['active'] != v['active'] for u, v in before.items()):
            raise Rejected('owned unit health failed')


class Engine:
    def __init__(self, policy, store, manager=None, fault=None, trusted_uid=0):
        self.policy, self.store = policy, Path(store)
        if manager is None and any('host_contract' in t for t in policy['targets'].values()):
            from host import HostManager
            manager = HostManager()
        self.manager, self.fault = manager or SystemdManager(), fault or (lambda _: None)
        self.uid = trusted_uid
        protected(self.store, trusted_uid)
        self.validate_policy()
        for name in ('plans', 'requests', 'operations', 'locks'):
            (self.store / name).mkdir(mode=0o700, exist_ok=True)
            protected(self.store / name, trusted_uid)

    def validate_policy(self):
        if set(self.policy) != {'peers', 'targets'}:
            raise Rejected('invalid policy keys')
        for name, target in self.policy['targets'].items():
            identifier(name)
            if 'host_contract' in target:
                from host import validate_target
                validate_target(target)
            required = {'actions', 'resources', 'root', 'units', 'service_uid', 'timeout', 'files', 'max_bytes', 'max_files'}
            if set(target) not in (required, required | {'host_contract'}) or not set(target['actions']) <= {'publish', 'revert', 'recover'}:
                raise Rejected('invalid target enrollment')
            if not 0 < len(target['resources']) <= 16 or not 0 < len(target['units']) <= 8 or not 0 < target['service_uid'] < 2**31:
                raise Rejected('administrative requirement: explicit owned resources and nonroot units')
            if not 0 < target['timeout'] <= 120 or not 0 < target['max_bytes'] <= 4*1024*1024 or not 0 < target['max_files'] <= 256:
                raise Rejected('invalid enrollment bounds')
            for resource in target['resources']:
                identifier(resource)
            for unit in target['units']:
                if not re.fullmatch(r'[A-Za-z0-9_.@-]+\.service', unit):
                    raise Rejected('invalid enrolled unit')
            protected(Path(target['root']), self.uid)
            if Path(target['root']).stat().st_mode & 0o111 != 0o111:
                raise Rejected('administrative requirement: enrolled root must permit nonroot traversal')
            for name in target['files']:
                self.safe_name(name)
        # Shared paths/units must share a resource gate, including ancestor roots.
        targets = list(self.policy['targets'].values())
        for i, a in enumerate(targets):
            for b in targets[i+1:]:
                pa, pb = Path(a['root']), Path(b['root'])
                if (pa == pb or pa in pb.parents or pb in pa.parents or (set(a['units']) & set(b['units']) and not ('host_contract' in a and 'host_contract' in b))) and not set(a['resources']) & set(b['resources']):
                    raise Rejected('administrative requirement: overlapping ownership needs common resource')

    @staticmethod
    def safe_name(name):
        p = PurePosixPath(name)
        if not name or not p.parts or '\x00' in name or p.is_absolute() or '..' in p.parts or str(p) != name or len(name) > 200 or len(p.parts) > 8:
            raise Rejected('invalid artifact path')

    @contextlib.contextmanager
    def lock(self, name, blocking=True):
        if name.startswith('op-'):
            name = 'operation-stripe-' + str(int(hashlib.sha256(name.encode()).hexdigest()[:8], 16) % 256)
        path = self.store / 'locks' / (name + '.lock')
        with path.open('a') as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
            except BlockingIOError:
                raise Rejected('busy: conflicting operation is running') from None
            yield

    def records(self, kind):
        paths = sorted((self.store / kind).glob('*.json'))
        if len(paths) > MAX_RECORDS:
            raise Rejected('administrative requirement: record capacity exhausted; retain evidence')
        return [self.status({'operation_id': p.stem}) if kind == 'operations' else read(p) for p in paths]

    def target(self, name):
        identifier(name)
        try:
            return self.policy['targets'][name]
        except KeyError:
            raise Rejected('administrative requirement: target not enrolled') from None

    def current(self, target):
        path = Path(target['root']) / 'current.json'
        return read(path) if path.exists() else {'generation': 0, 'workspace_generation': 0, 'release': None}

    def handle(self, req, peer):
        if len(canonical(req)) > 8*1024*1024:
            raise Rejected('request too large')
        permissions = [p for p in self.policy['peers'] if (p['uid'], p['gid']) == tuple(peer)]
        if not permissions:
            raise Rejected('peer is not enrolled')
        method = req.get('method')
        if method in ('health', 'diagnose'):
            method = 'status'
            req = {**req, 'method': method}
        if not any(method in p['methods'] for p in permissions):
            raise Rejected('peer method not authorized')
        if method == 'status':
            name = req.get('target')
            if req.get('operation_id'):
                name = read(self.store / 'operations' / (identifier(req['operation_id']) + '.json'))['target']
            if name and not any(method in p['methods'] and name in p['targets'] for p in permissions):
                raise Rejected('peer target not authorized')
            result = self.status(req)
            if not name:
                result['targets'] = sorted({t for p in permissions if method in p['methods'] for t in p['targets']})
            return result
        if method == 'prepare':
            target = self.target(req.get('target'))
            if not any(method in p['methods'] and req['target'] in p['targets'] and req.get('action') in p['actions'] for p in permissions):
                raise Rejected('peer action not authorized')
            return self.prepare(req, target)
        if method == 'execute':
            plan = read(self.store / 'plans' / (identifier(req.get('plan_id')) + '.json'))
            if not any(method in p['methods'] and plan['target'] in p['targets'] and plan['action'] in p['actions'] for p in permissions):
                raise Rejected('peer action not authorized')
            return self.execute(req, plan)
        raise Rejected('unknown method')

    def prepare(self, req, target):
        allowed = {'method', 'request_id', 'target', 'action', 'generation', 'artifact', 'release', 'recovery_of'}
        if set(req) - allowed or req['action'] not in target['actions'] or type(req.get('generation')) is not int:
            raise Rejected('action requires administrative enrollment or invalid request')
        rid = identifier(req.get('request_id'))
        fingerprint = digest(req)
        with self.lock('prepare'):
            saved = self.store / 'requests' / (rid + '.json')
            if saved.exists():
                prior = read(saved)
                if prior['fingerprint'] != fingerprint:
                    raise Rejected('request ID content conflict')
                if prior.get('phase') == 'sealed':
                    return prior
                sealed = self.store / 'plans' / (prior['plan_id'] + '.json')
                if sealed.exists():
                    atomic(sealed, read(sealed))
                    receipt = {**prior, 'phase': 'sealed'}
                    atomic(saved, receipt)
                    return receipt
            limit = MAX_RECORDS if req['action'] == 'recover' else MAX_RECORDS - 100
            if len(self.records('requests')) >= limit:
                raise Rejected('administrative requirement: preparation capacity exhausted; recovery reserve retained')
            if self.current(target)['generation'] != req['generation']:
                raise Rejected('stale target generation')
            plan = {k: v for k, v in req.items() if k != 'artifact'}
            plan.update(policy=digest(self.policy), effects=req['action'], service_scope=target['units'],
                        health='remain-stopped' if req['action'] == 'recover' else 'preserve-active-state', timeout=target['timeout'], compensation='restore-previous-release')
            plan_id = digest(req)
            atomic(saved, {'plan_id': plan_id, 'fingerprint': fingerprint, 'phase': 'preparing'})
            root = Path(target['root'])
            for name in ('releases', 'workspaces', 'evidence', 'quarantine'):
                (root / name).mkdir(mode=0o711 if name in ('releases', 'workspaces') else 0o700, exist_ok=True)
                if name in ('releases', 'workspaces'):
                    os.chmod(root / name, 0o711)
            if req['action'] == 'publish':
                artifact = req.get('artifact', {})
                if set(artifact) != set(target['files']) or len(artifact) > target['max_files']:
                    raise Rejected('artifact must match exact enrolled file set')
                release = root / 'releases' / plan_id
                staging = root / ('stage-' + plan_id)
                if staging.exists():
                    shutil.rmtree(staging)  # Only this bounded, never executed input copy.
                staging.mkdir(mode=0o700)
                try:
                    hashes, size = {}, 0
                    for name, data in sorted(artifact.items()):
                        self.safe_name(name)
                        raw = base64.b64decode(data, validate=True)
                        size += len(raw)
                        if size > target['max_bytes']:
                            raise Rejected('artifact byte limit')
                        dest = staging / name
                        dest.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                        with dest.open('xb') as out:
                            out.write(raw)
                            out.flush()
                            os.fsync(out.fileno())
                        dest.chmod(0o644)
                        hashes[name] = hashlib.sha256(dest.read_bytes()).hexdigest()
                    for directory, _, _ in os.walk(staging, topdown=False):
                        os.chmod(directory, 0o755)
                        sync_dir(directory)
                    if release.exists():
                        self.verify_release(release, hashes)
                    else:
                        os.rename(staging, release)
                        sync_dir(release.parent)
                    plan['hashes'], plan['release'] = hashes, plan_id
                finally:
                    if staging.exists():
                        shutil.rmtree(staging)
            elif req['action'] == 'revert':
                selected = read(self.store / 'plans' / (identifier(req.get('release')) + '.json'))
                if selected['target'] != req['target'] or selected['action'] != 'publish':
                    raise Rejected('revert requires same-target sealed publication')
                plan['release'], plan['hashes'] = selected['release'], selected['hashes']
            else:
                old = self.status({'operation_id': identifier(req.get('recovery_of'))})
                if old['target'] != req['target'] or old['state'] == 'succeeded':
                    raise Rejected('recovery requires linked failed or uncertain same-target operation')
            atomic(self.store / 'plans' / (plan_id + '.json'), plan)
            self.fault('prepare-sealed')
            receipt = {'plan_id': plan_id, 'fingerprint': fingerprint, 'phase': 'sealed'}
            atomic(saved, receipt)
            self.fault('prepare-receipt')
            return receipt

    def verify_release(self, path, hashes):
        actual = {}
        for item in path.rglob('*'):
            mode = item.lstat().st_mode
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode) or mode & 0o7022 or item.stat().st_uid != self.uid:
                raise Rejected('sealed release metadata changed')
            actual[str(item.relative_to(path))] = hashlib.sha256(item.read_bytes()).hexdigest()
        if actual != hashes:
            raise Rejected('sealed release bytes changed')

    def status(self, req):
        if req.get('operation_id'):
            op = read(self.store / 'operations' / (identifier(req['operation_id']) + '.json'))
            if op['state'] == 'running' or (self.store / 'operations' / (op['operation_id'] + '.reserve')).exists():
                try:
                    with self.lock('op-' + op['operation_id'], False):
                        op = {**op, 'state': 'uncertain', 'recovery_required': True}
                except Rejected:
                    pass
            return op
        if req.get('target'):
            target = self.target(req['target'])
            operations = [o for o in self.records('operations') if o['target'] == req['target']]
            return {'current': self.current(target), 'operations': [self.status({'operation_id': o['operation_id']}) for o in operations[-10:]]}
        return {'healthy': True, 'targets': sorted(self.policy['targets']), 'policy': digest(self.policy)}

    def execute(self, req, plan):
        if set(req) != {'method', 'operation_id', 'plan_id'}:
            raise Rejected('invalid execute fields')
        oid = identifier(req.get('operation_id'))
        path = self.store / 'operations' / (oid + '.json')
        with self.lock('op-' + oid, False):
            if path.exists():
                old = self.status({'operation_id': oid})
                if old['plan_id'] != req['plan_id']:
                    raise Rejected('operation ID content conflict')
                if old['state'] == 'running' or (self.store / 'operations' / (oid + '.reserve')).exists():
                    return {**old, 'state': 'uncertain', 'recovery_required': True}
                return old
            target = self.target(plan['target'])
            with contextlib.ExitStack() as locks:
                for resource in sorted(set(target['resources'])):
                    locks.enter_context(self.lock('resource-' + resource, False))
                if 'host_contract' in target:
                    locks.enter_context(self.manager.guard(target))
                if plan['policy'] != digest(self.policy) or self.current(target)['generation'] != plan['generation']:
                    raise Rejected('stale sealed plan or changed policy')
                records = self.records('operations')
                limit = MAX_RECORDS if plan['action'] == 'recover' else MAX_RECORDS - 100
                if len(records) >= limit:
                    raise Rejected('administrative requirement: operation capacity exhausted; recovery reserve retained')
                resolved = {oid for o in records if o['state'] == 'succeeded' for oid in o.get('resolves', [])}
                unresolved = [o for o in records if o.get('recovery_required') and o['operation_id'] not in resolved and set(o['resources']) & set(target['resources'])]
                if unresolved and (plan['action'] != 'recover' or any(o['target'] != plan['target'] for o in unresolved)):
                    raise Rejected('resource fenced: linked recovery required')
                if plan['action'] == 'recover' and plan['recovery_of'] not in {o['operation_id'] for o in unresolved}:
                    raise Rejected('recovery must link an unresolved resource operation')
                # Allocate receipt space before acceptance. Disk exhaustion cannot authorize a side effect.
                reserve = self.store / 'operations' / (oid + '.reserve')
                with reserve.open('xb') as out:
                    os.posix_fallocate(out.fileno(), 0, 65536)
                    os.fsync(out.fileno())
                sync_dir(reserve.parent)
                op = {'operation_id': oid, 'plan_id': req['plan_id'], 'target': plan['target'], 'resources': target['resources'],
                      'state': 'running', 'step': 'accepted', 'recovery_required': True}
                atomic(path, op)
                self.fault('accepted')
                try:
                    self.perform(plan, target, op, path)
                    op.update(state='succeeded', recovery_required=False)
                except Exception:
                    # Fixed error vocabulary avoids accidentally recording application secrets.
                    op.update(state='failed', error='operation failed; inspect bounded step evidence')
                self.fault('receipt-intent')
                atomic(path, op)
                # Keep the preallocated marker until the terminal receipt is synchronized.
                # Any failure above leaves a visible uncertainty marker, even after rename.
                reserve.unlink()
                self.fault('receipt-written')
                return op

    def step(self, op, path, name, effect):
        op['step'] = name + '-intent'
        atomic(path, op)
        self.fault(name + '-intent')
        value = effect()
        self.fault(name + '-effect')
        op['step'] = name + '-observed'
        atomic(path, op)
        self.fault(name + '-observed')
        return value

    def perform(self, plan, target, op, path):
        root, previous = Path(target['root']), self.current(target)
        before = self.manager.observe(target)
        if any(v['active'] not in (('active', 'inactive', 'failed') if 'host_contract' in target else ('active', 'inactive')) for v in before.values()):
            raise Rejected('unknown owned lifecycle')
        op['before'], op['previous'] = before, previous
        self.step(op, path, 'stop', lambda: self.manager.stop(target))
        if plan['action'] == 'recover' and 'host_contract' in target and 'publish' in target['actions']:
            original = self.status({'operation_id': plan['recovery_of']})
            chain = []
            for _ in range(MAX_RECORDS):
                origin_plan = read(self.store/'plans'/(original['plan_id']+'.json'))
                chain.append(original)
                if origin_plan['action'] != 'recover':
                    break
                original = self.status({'operation_id': origin_plan['recovery_of']})
            else:
                raise Rejected('administrative requirement: recovery link bound exceeded')
            restore = original.get('previous')
            if not restore or not restore.get('release'):
                raise Rejected('administrative requirement: unknown original binding')
            sealed = read(self.store/'plans'/(restore['release']+'.json'))
            self.verify_release(root/'releases'/restore['release'], sealed['hashes'])
            failed_plan = read(self.store/'plans'/(original['plan_id']+'.json'))
            candidates = [root/'releases'/restore['release']]
            for prior in chain:
                selected = prior.get('previous', {}).get('release')
                if selected:
                    selected_plan = read(self.store/'plans'/(selected+'.json'))
                    self.verify_release(root/'releases'/selected, selected_plan['hashes'])
                    candidates.append(root/'releases'/selected)
            if failed_plan.get('release'):
                self.verify_release(root/'releases'/failed_plan['release'], failed_plan['hashes'])
                candidates.append(root/'releases'/failed_plan['release'])
            self.manager.recovery_binding(target, list(dict.fromkeys(candidates)))
            restored = {**restore, 'generation': previous['generation']+1}
            self.step(op, path, 'restore-binding', lambda: self.publish(target, restored))
            op['resolves'] = [o['operation_id'] for o in self.records('operations') if o['target'] == plan['target'] and o.get('recovery_required') and o['operation_id'] != op['operation_id']]
            op['recovery_required'] = False
            return
        if plan['action'] == 'recover':
            gen = str(previous.get('workspace_generation', 0))
            workspace = self.manager.workspace(target) if 'host_contract' in target else root/'workspaces'/gen
            evidence, quarantine = root/'evidence'/gen, root/'quarantine'/gen
            def preserve():
                if evidence.exists():
                    for directory, _, files in os.walk(evidence, topdown=False):
                        for name in files:
                            with (Path(directory) / name).open('rb') as stream:
                                os.fsync(stream.fileno())
                        sync_dir(directory)
                    sync_dir(evidence.parent)
                    return
                stage = root / ('evidence-stage-' + str(op['operation_id']))
                if stage.exists():
                    raise Rejected('partial evidence staging retained; explicit administrative preservation required')
                stage.mkdir(mode=0o700)
                payload = stage / 'workspace'
                payload.mkdir(mode=0o700)
                total, count = 0, 0
                if workspace.exists():
                    for item in workspace.rglob('*'):
                        info = item.lstat()
                        count += 1
                        if count > target['max_files']:
                            raise Rejected('workspace entry count exceeds enrollment')
                        if info.st_mode & 0o7000:
                            raise Rejected('workspace privilege bits rejected')
                        if stat.S_ISDIR(info.st_mode):
                            continue
                        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o7000 or info.st_nlink != 1:
                            raise Rejected('workspace evidence format needs administrative preservation')
                        total += info.st_size
                        if total > target['max_bytes'] or count > target['max_files']:
                            raise Rejected('workspace evidence exceeds enrolled capacity')
                        dest = payload / item.relative_to(workspace)
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        with item.open('rb') as source, dest.open('xb') as out:
                            copied = 0
                            while True:
                                chunk = source.read(min(65536, target['max_bytes'] - total + info.st_size - copied + 1))
                                if not chunk:
                                    break
                                copied += len(chunk)
                                if total - info.st_size + copied > target['max_bytes']:
                                    raise Rejected('workspace grew past evidence byte limit')
                                out.write(chunk)
                            total += copied - info.st_size
                            out.flush()
                            os.fsync(out.fileno())
                atomic(stage / 'original-operation.json', read(self.store/'operations'/(plan['recovery_of']+'.json')))
                for directory, _, _ in os.walk(stage, topdown=False):
                    sync_dir(directory)
                os.rename(stage, evidence)
                sync_dir(evidence.parent)
            self.step(op, path, 'preserve', preserve)
            def retire():
                if workspace.exists():
                    if quarantine.exists():
                        if 'host_contract' in target and self.linked_fresh_workspace(plan, previous, workspace, target):
                            return
                        raise Rejected('ambiguous workspace ownership')
                    os.rename(workspace, quarantine)
                    sync_dir(workspace.parent)
                    sync_dir(quarantine.parent)
            self.step(op, path, 'retire', retire)
            fresh = workspace if 'host_contract' in target else root/'workspaces'/str(previous.get('workspace_generation', 0)+1)
            op['fresh_workspace'] = {'generation': previous.get('workspace_generation', 0)+1}
            self.step(op, path, 'allocate', lambda: self.allocate(fresh, target))
            self.step(op, path, 'publish', lambda: atomic(root/'current.json', {**previous, 'generation': previous['generation']+1, 'workspace_generation': previous.get('workspace_generation', 0)+1}, 0o644))
            # Preserve original records. Resolution is a separate durable link, never a rewritten failure.
            op['resolves'] = [o['operation_id'] for o in self.records('operations') if o['target'] == plan['target'] and o.get('recovery_required') and o['operation_id'] != op['operation_id']]
            op['recovery_required'] = False
            return
        if 'host_contract' in target:
            if not previous.get('release'):
                raise Rejected('administrative requirement: initial root adoption required')
            self.manager.check_binding(target, root/'releases'/previous['release'])
        self.verify_release(root/'releases'/plan['release'], plan['hashes'])
        new = {**previous, 'generation': previous['generation']+1, 'release': plan['release']}
        self.step(op, path, 'publish', lambda: self.publish(target, new))
        try:
            self.step(op, path, 'health', lambda: self.manager.start(target, before))
        except Exception:
            self.step(op, path, 'compensate-stop', lambda: self.manager.stop(target))
            self.step(op, path, 'compensate', lambda: self.publish(target, {**previous, 'generation': new['generation']}))
            self.step(op, path, 'compensate-health', lambda: self.manager.start(target, before))
            op['recovery_required'] = False
            raise
        op['recovery_required'] = False

    def allocate(self, fresh, target):
        if fresh.exists():
            if fresh.is_symlink() or not fresh.is_dir() or any(fresh.iterdir()):
                raise Rejected('fresh generation already contains unknown work')
        else:
            fresh.mkdir(mode=0o700)
        os.chown(fresh, target['service_uid'], 980 if 'host_contract' in target else -1)
        sync_dir(fresh)
        sync_dir(fresh.parent)

    def publish(self, target, selected):
        root = Path(target['root'])
        if 'host_contract' in target:
            self.manager.publish_binding(target, root/'releases'/selected['release'])
        atomic(root/'current.json', selected, 0o644)

    def linked_fresh_workspace(self, plan, previous, workspace, target):
        """Explicit recovery may finish only a prior recorded empty allocation.

        The fixed host path is reused. Its separate allocation intent distinguishes
        a new empty workspace from the quarantined failed generation.
        """
        linked = plan['recovery_of']
        for _ in range(MAX_RECORDS):
            prior = self.status({'operation_id': linked})
            intended = prior.get('fresh_workspace', {}).get('generation')
            if intended == previous.get('workspace_generation', 0)+1:
                info = workspace.lstat()
                return (stat.S_ISDIR(info.st_mode) and info.st_uid in (self.uid, target['service_uid'])
                        and stat.S_IMODE(info.st_mode) == 0o700 and not any(workspace.iterdir()))
            prior_plan = read(self.store/'plans'/(prior['plan_id']+'.json'))
            if prior_plan['action'] != 'recover':
                return False
            linked = prior_plan['recovery_of']
        raise Rejected('administrative requirement: allocation recovery link bound exceeded')
