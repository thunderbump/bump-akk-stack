"""Fixed host enrollment from ENROLLMENT-CONTRACT-v1, never request paths.

Adoption must establish the protected launcher symlink and managed current record.
This adapter neither adopts the old directory nor executes accepted workloads.
"""
import contextlib
import fcntl
import grp
import os
from pathlib import Path
import pwd
import re
import selectors
import stat
import subprocess
import time
import uuid

try:
    from .engine import Rejected, protected, sync_dir
except ImportError:  # Installed sibling modules under python -I.
    from engine import Rejected, protected, sync_dir

CONTRACT_SHA = 'dbd6bc9bccd5acf9df40b60caef95f3c0c0c6568a451918a738111715a8f6698'
SERVICE_UID, SERVICE_GID = 995, 980
CODE_ROOT = Path('/var/lib/eqemu-resilient-targets/validator-worker-code')
WORKSPACE_ROOT = Path('/var/lib/eqemu-resilient-targets/validator-integration-evidence')
BINDING = Path('/srv/eqemu-validator-code')
WORKSPACE = Path('/var/lib/eqemu-validator/ordinary/last-integration')
SHARED_LOCK = Path('/var/lib/eqemu-validator/worker.lock')
CGROUP_ROOT = Path('/sys/fs/cgroup')
FILES = (
    'integration-release.json', 'scripts/check-validation-worker',
    'validation/actor-integration-fixture.json', 'validation/actor.py',
    'validation/actor_runtime.py', 'validation/debugger.py',
    'validation/runtime-fixture.json', 'validation/worker/actor_integration.py',
    'validation/worker/build_guest.py', 'validation/worker/client.py',
    'validation/worker/format_guest.py', 'validation/worker/guest.py',
    'validation/worker/integration-v1.4.json', 'validation/worker/integration_artifacts.py',
    'validation/worker/normal_world.py', 'validation/worker/quick_guest.py',
    'validation/worker/quick_snapshot.py', 'validation/worker/runtime.py',
    'validation/worker/snapshot.py',
)
TEMPLATES = ('eqemu-validator@.service', 'eqemu-validator-asan-v1@.service',
             'eqemu-validator-asan-v2@.service', 'eqemu-validator-asan-v3@.service',
             'eqemu-validator-profiling@.service')
PUBLISHER = 'eqemu-validator-maintenance@.service'
SOCKETS = tuple(u.replace('@.service', '.socket') for u in (*TEMPLATES, PUBLISHER))
ORDINARY_SOCKET = SOCKETS[0]
MAX_OUTPUT, MAX_INSTANCES = 65536, 32
TRUSTED_UID = 0  # Tests replace the trust anchor, never a protocol option.


def validate_target(target):
    """Additional validation, after the core's bounded generic policy schema."""
    if target.get('host_contract') != CONTRACT_SHA or target.get('service_uid') != SERVICE_UID:
        raise Rejected('unknown host contract or runtime identity')
    root = Path(target['root'])
    if root == CODE_ROOT:
        valid = (set(target['actions']) <= {'publish', 'revert', 'recover'} and bool(target['actions'])
                 and set(target['resources']) == {'validator-worker-code'}
                 and len(target['files']) == len(FILES) and set(target['files']) == set(FILES))
    elif root == WORKSPACE_ROOT:
        valid = (target['actions'] == ['recover'] and
                 set(target['resources']) == {'validator-ordinary-state', 'validator-integration-evidence'}
                 and len(target['files']) == 3 and set(target['files']) == {'central-cdau-integration-v1.json', 'pending.json', 'receipt.json'})
    else:
        valid = False
    if not valid or target['units'] != ['eqemu-validator@.service']:
        raise Rejected('host target differs from fixed enrollment')


class HostManager:
    """Fence exact socket templates; publication requires the external lock.

    Call guard around observation, stop, effect, compensation and socket restore.
    check_binding is required before publication and after startup. The engine
    owns durable intent/receipt recording and compensation to the previous path.
    Errors leave ingress fenced until explicit safe recovery, never replay work.
    """
    def __init__(self):
        self._held = False
        self._checked = None
        self._fenced = False
        self._stopped = None

    def _run(self, args, timeout):
        # Drain incrementally: systemctl output cannot allocate unbounded memory.
        try:
            with subprocess.Popen(['/usr/bin/systemctl', *args], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}) as process:
                try:
                    output = bytearray()
                    deadline = time.monotonic() + timeout
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ)
                        while True:
                            left = deadline - time.monotonic()
                            if left <= 0 or not selector.select(left):
                                raise Rejected('systemctl timed out')
                            data = os.read(process.stdout.fileno(), 4096)
                            if not data:
                                break
                            output.extend(data)
                            if len(output) > MAX_OUTPUT:
                                raise Rejected('systemctl output exceeds bound')
                    if process.wait(timeout=max(.001, deadline-time.monotonic())):
                        raise Rejected('systemctl failed')
                    return bytes(output)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
        except (OSError, subprocess.SubprocessError):
            raise Rejected('host lifecycle unavailable') from None

    def _show(self, unit, target):
        raw = self._run(['show', unit, '--property=ControlGroup,InvocationID,User,Group,ActiveState,KillMode'], target['timeout'])
        try:
            pairs = [line.split('=', 1) for line in raw.decode('ascii').splitlines()]
            values = dict(pairs)
        except (ValueError, UnicodeError):
            raise Rejected('invalid systemd observation') from None
        if len(values) != len(pairs) or set(values) != {'ControlGroup', 'InvocationID', 'User', 'Group', 'ActiveState', 'KillMode'}:
            raise Rejected('incomplete systemd observation')
        return values

    def _instances(self, target):
        patterns = [t.replace('@.', '@*.') for t in (*TEMPLATES, PUBLISHER)]
        raw = self._run(['list-units', '--all', '--plain', '--no-legend', *patterns], target['timeout'])
        if len(raw) > MAX_OUTPUT:
            raise Rejected('instance output exceeds bound')
        units = []
        for line in raw.decode('ascii').splitlines():
            fields = line.split()
            if not fields:
                continue
            unit = fields[0]
            if len(unit) > 255 or not any(re.fullmatch(re.escape(t).replace('@', r'@[A-Za-z0-9_:.\\-]+'), unit) for t in (*TEMPLATES, PUBLISHER)):
                raise Rejected('unexpected accepted unit')
            units.append(unit)
            if len(units) > MAX_INSTANCES or len(set(units)) != len(units):
                raise Rejected('accepted instance bound exceeded')
        return sorted(units)

    def _populated(self, group, active=False):
        if not group:
            return False
        if not group.startswith('/') or any(p in ('', '.', '..') for p in group[1:].split('/')):
            raise Rejected('unknown cgroup path')
        path = CGROUP_ROOT / group[1:]
        try:
            with (path / 'cgroup.events').open('rb') as stream:
                raw = stream.read(4097)
        except FileNotFoundError:
            if active:
                raise Rejected('active cgroup unavailable') from None
            return False
        if len(raw) > 4096:
            raise Rejected('cgroup observation bound exceeded')
        lines = raw.splitlines()
        if lines.count(b'populated 0') + lines.count(b'populated 1') != 1:
            raise Rejected('unknown cgroup population')
        return b'populated 1' in lines

    def observe(self, target):
        validate_target(target)
        result = {}
        units = self._instances(target)
        for unit in (*SOCKETS, *units):
            values = self._show(unit, target)
            if unit in units:
                root = unit.startswith(PUBLISHER.split('@')[0] + '@')
                try:
                    uid = int(values['User']) if values['User'].isdigit() else pwd.getpwnam(values['User']).pw_uid
                    gid = int(values['Group']) if values['Group'].isdigit() else grp.getgrnam(values['Group']).gr_gid
                except (KeyError, ValueError):
                    raise Rejected('unknown runtime identity') from None
                if (uid, gid) != ((0, 0) if root else (SERVICE_UID, SERVICE_GID)) or values['KillMode'] != 'control-group':
                    raise Rejected('unowned runtime identity or kill mode')
            if values['ActiveState'] not in ('active', 'inactive', 'failed'):
                raise Rejected('transitional host lifecycle')
            invocation = values['InvocationID']
            if invocation and not re.fullmatch('[a-f0-9]{32}', invocation):
                raise Rejected('invalid invocation identity')
            if values['ActiveState'] == 'active' and unit in units and (not invocation or not values['ControlGroup']):
                raise Rejected('missing active instance identity')
            result[unit] = {'active': values['ActiveState'], 'populated': self._populated(values['ControlGroup'], values['ActiveState'] == 'active'),
                            'invocation': invocation, 'cgroup': values['ControlGroup']}
        if units != self._instances(target):
            raise Rejected('accepted instances changed during observation')
        return result

    def _require_guard(self):
        if not self._held:
            raise Rejected('external execution guard required')

    @contextlib.contextmanager
    def guard(self, target):
        validate_target(target)
        if self._held:
            raise Rejected('nested host guard')
        # Administrative precondition: every lock ancestor is root-owned and
        # not group/world writable. The packet does not establish this fact.
        # A worker-owned parent requires separate reviewed remediation.
        protected(SHARED_LOCK.parent, TRUSTED_UID)
        fd = os.open(SHARED_LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in (TRUSTED_UID, SERVICE_UID) or info.st_mode & 0o007:
                raise Rejected('untrusted shared lock')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Rejected('busy: shared worker execution') from None
            current = SHARED_LOCK.lstat()
            if (info.st_dev, info.st_ino) != (current.st_dev, current.st_ino):
                raise Rejected('shared lock inode changed')
            self._held = True
            if self._fenced:
                self._quiescent(target)
            yield
        finally:
            self._held = self._fenced = False
            self._checked = None
            os.close(fd)

    def stop(self, target):
        # Adoption fences first, then acquires the existing external lock.
        self._fenced = False
        validate_target(target)
        for socket in SOCKETS:
            self._run(['stop', socket], target['timeout'])
        observed = self.observe(target)
        if any(observed[s]['active'] != 'inactive' or observed[s]['populated'] for s in SOCKETS):
            raise Rejected('ingress fence failed')
        # Accepted workloads cannot be restarted without replaying their request.
        for unit, state in observed.items():
            if unit not in SOCKETS and not unit.startswith(PUBLISHER.split('@')[0] + '@'):
                if state['active'] not in ('inactive', 'failed') or state['populated']:
                    raise Rejected('accepted workload active; explicit retry required')
        publishers = [u for u in observed if u.startswith(PUBLISHER.split('@')[0] + '@')]
        for unit in publishers:
            self._run(['stop', unit], target['timeout'])
        final = self.observe(target)
        removed = set(observed) - set(final)
        if (set(final) - set(observed) or not removed <= set(publishers)
                or any(v['active'] not in ('inactive', 'failed') or v['populated'] for v in final.values())
                or any(self._populated(observed[u]['cgroup']) for u in publishers)
                or any(final[u]['invocation'] and final[u]['invocation'] != observed[u]['invocation']
                       for u in publishers if u in final)):
            raise Rejected('writers changed or remain populated')
        self._stopped = final
        self._fenced = True

    def start(self, target, before):
        self._require_guard()
        if not self._fenced:
            raise Rejected('writers not fenced')
        # Never start services, including the competing root publisher.
        self._quiescent(target)
        for socket in SOCKETS:
            if socket not in (ORDINARY_SOCKET, SOCKETS[-1]) and before.get(socket, {}).get('active') == 'active':
                self._run(['start', socket], target['timeout'])
        after = self.observe(target)
        for socket in SOCKETS:
            expected = 'active' if socket not in (ORDINARY_SOCKET, SOCKETS[-1]) and before.get(socket, {}).get('active') == 'active' else 'inactive'
            if after[socket]['active'] != expected:
                raise Rejected('socket restoration failed')
        self._fenced = False

    def _quiescent(self, target):
        state = self.observe(target)
        if self._stopped is None or state != self._stopped:
            raise Rejected('accepted instance or invocation changed after fencing')
        if any(v['active'] not in ('inactive', 'failed') or v['populated'] for v in state.values()):
            raise Rejected('host no longer fenced')

    def workspace(self, target):
        validate_target(target)
        if Path(target['root']) != WORKSPACE_ROOT:
            raise Rejected('target has no external workspace')
        return WORKSPACE

    def _release(self, target, path):
        validate_target(target)
        path = Path(path)
        if Path(target['root']) != CODE_ROOT or path.parent != CODE_ROOT / 'releases' or not re.fullmatch('[a-f0-9]{64}', path.name):
            raise Rejected('binding requires fixed managed release')
        protected(path, TRUSTED_UID)
        return path

    def check_binding(self, target, expected_path):
        expected = self._release(target, expected_path)
        protected(BINDING.parent, TRUSTED_UID)
        info = BINDING.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != TRUSTED_UID:
            raise Rejected('reviewed symlink adoption required')
        if os.readlink(BINDING) != str(expected):
            raise Rejected('launcher binding differs from managed current release')
        self._checked = (info.st_dev, info.st_ino, str(expected))

    def recovery_binding(self, target, paths):
        """Check only the sealed prior/intended release choices supplied by core.

        Core must verify both releases' sealed bytes before calling. This permits
        recovery across an interrupted link/current-record update without blessing
        any other release. No request may supply these administrative choices.
        """
        self._require_guard()
        if not isinstance(paths, (list, tuple)) or not 1 <= len(paths) <= 2:
            raise Rejected('bounded sealed recovery choices required')
        allowed = {str(self._release(target, path)) for path in paths}
        protected(BINDING.parent, TRUSTED_UID)
        info = BINDING.lstat()
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != TRUSTED_UID:
            raise Rejected('reviewed symlink adoption required')
        observed = os.readlink(BINDING)
        if observed not in allowed:
            raise Rejected('recovery binding outside sealed choices')
        self.check_binding(target, observed)
        return Path(observed)

    def publish_binding(self, target, path):
        self._require_guard()
        if not self._fenced or self._checked is None:
            raise Rejected('checked adopted binding and fence required')
        path = self._release(target, path)
        self._quiescent(target)
        previous = self._checked
        self.check_binding(target, previous[2])
        if previous != self._checked:
            raise Rejected('launcher binding changed')
        tmp = BINDING.parent / ('.eqemu-binding-' + uuid.uuid4().hex)
        try:
            tmp.symlink_to(path)
            os.replace(tmp, BINDING)
            # Record the observed effect before fsync so compensation remains
            # possible even if directory synchronization itself fails.
            self.check_binding(target, path)
            sync_dir(BINDING.parent)
        finally:
            tmp.unlink(missing_ok=True)
