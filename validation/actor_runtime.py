"""Maintained offline consumer runtime. Imported helpers start no process.

Only run() crosses the guest execution seam, after verified artifact consumption.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import selectors
import shutil
import signal
import subprocess
import tarfile
import time
import zipfile

from actor import PROFILE, RECIPE, RUNTIME_SECONDS, ZONE_SECONDS, completion

MEDIA = Path('/opt/runtime-inputs')
ROOT = Path('/opt/eqemu-actor')
GIB = 1024**3


class Runtime:
    def __init__(self, build, control, fixture):
        self.build = build
        self.control = control
        self.fixture = fixture
        self.processes = []
        self.secrets = []
        self.cancelled = False
        self.used = shutil.disk_usage('/opt').used
        self.deadline = min(build.DEADLINE, time.monotonic()+RUNTIME_SECONDS)
        self.stage_times = {}

    def scrub(self, value):
        for secret in self.secrets:
            value = value.replace(secret, '[redacted]')
        return value

    def guard(self):
        if self.cancelled or time.monotonic() >= self.deadline:
            raise RuntimeError('Actor runtime interrupted or deadline reached')
        if (shutil.disk_usage('/opt').free < 8*GIB
                or shutil.disk_usage('/opt').used-self.used > 8*GIB):
            raise RuntimeError('Actor runtime disk budget')
        for name, cap in [('database', 6*GIB), ('server/shared', 768*1024**2), ('server/logs', 256*1024**2)]:
            path = ROOT/name
            size = sum(p.stat().st_blocks*512 for p in path.rglob('*') if p.is_file() and not p.is_symlink())
            if size > cap:
                raise RuntimeError('Actor runtime allocation cap: '+name)
        console = ROOT/'database-console.log'
        if console.exists() and console.stat().st_size > 1024**2:
            raise RuntimeError('Database console budget')
        for proc in self.processes:
            if proc.poll() is not None:
                raise RuntimeError('Owned runtime service exited unexpectedly')

    def command(self, name, args, timeout=300, cwd=None, stdin=None, actor=False):
        """Drain bounded logs and own the process group through every exit."""
        self.guard()
        start = time.monotonic()
        end = min(self.deadline, start+timeout)
        path = self.build.LOGS/(name+'.log')
        self.build.emit({'kind': 'stage', 'name': name, 'state': 'started'})
        proc = subprocess.Popen(args, stdin=stdin or subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                env=self.build.ENV, cwd=cwd, start_new_session=True)
        output = bytearray(); pending = b''; created = False
        try:
            os.set_blocking(proc.stdout.fileno(), False)
            with selectors.DefaultSelector() as sel, path.open('xb') as log:
                sel.register(proc.stdout, selectors.EVENT_READ)
                eof = False
                while not eof or proc.poll() is None:
                    self.guard()
                    if time.monotonic() >= end:
                        raise RuntimeError(name+': deadline reached')
                    for key, _ in sel.select(.2):
                        block = os.read(key.fd, 65536)
                        if not block:
                            eof = True; sel.unregister(key.fileobj); continue
                        if len(output)+len(block) > 1024**2:
                            raise RuntimeError(name+': output budget')
                        output.extend(block)
                        # Never persist guest-local credentials in logs or frames.
                        # Keep bounded bytes until completion so split credentials are redacted together.
                        pending += block
                        while b'\n' in pending:
                            line, pending = pending.split(b'\n', 1)
                            if actor and line.startswith(b'EQEMU_ACTOR_PHASE '):
                                def unique(pairs):
                                    value = {}
                                    for key, item in pairs:
                                        if key in value: raise ValueError('Duplicate actor phase field')
                                        value[key] = item
                                    return value
                                phase = json.loads(line.removeprefix(b'EQEMU_ACTOR_PHASE '), object_pairs_hook=unique)
                                if (self.control != 'cancel' or created or not isinstance(phase,dict)
                                        or set(phase) != {'version','phase'} or type(phase['version']) is not int
                                        or phase['version'] != 1 or phase['phase'] != 'actor-created'):
                                    raise RuntimeError('Unexpected/duplicate actor-created phase')
                                created = True
                                self.build.emit({'kind': 'stage', 'name': 'actor-created', 'state': 'started'})
                        if len(pending) > 65536:
                            raise RuntimeError(name+': line budget')
                rc = proc.wait(timeout=5)
            text = self.scrub(output.decode(errors='replace'))
            if actor:
                if self.control == 'cancel' and not created:
                    raise RuntimeError('Actor cancellation phase missing')
                record = completion(text, rc, self.control)
                self.build.emit({'kind': 'stage', 'name': name, 'state': 'passed' if rc == 0 else 'failed'})
                return record
            if rc != 0:
                raise RuntimeError(name+': exit '+str(rc)+'\n'+text[-3000:])
            self.build.emit({'kind': 'stage', 'name': name, 'state': 'passed'})
            return text
        finally:
            self.stage_times[name] = round(time.monotonic()-start, 3)
            # A leader may exit before its children. Always terminate this owned group.
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait(timeout=10)
            proc.stdout.close()
            path.write_text(self.scrub(output.decode(errors='replace')))
            end = time.monotonic()+2
            while group_live(proc.pid) and time.monotonic() < end: time.sleep(.02)
            if group_live(proc.pid):
                raise RuntimeError(name+': owned process group remains')

    def verify_inputs(self):
        self.guard()
        raw = MEDIA/'runtime-bundle-manifest.json'
        if self.build.sha(raw) != self.fixture['manifest_sha256']:
            raise RuntimeError('Actor runtime manifest identity')
        manifest = json.loads(raw.read_text())
        if manifest != self.fixture['manifest']:
            raise RuntimeError('Actor runtime manifest differs from sealed package')
        for item in manifest['files']:
            self.guard()
            path = MEDIA/item['path']
            if path.is_symlink() or not path.is_file() or path.stat().st_size != item['bytes'] or self.build.sha(path) != item['sha256']:
                raise RuntimeError('Missing/changed runtime fixture: '+item['path'])

    def install_packages(self):
        proof = json.loads((MEDIA/'provenance/runtime-package-proof.json').read_text())
        allowed = {(p['Package'], p['Version']) for p in proof['packages']}
        cache = self.build.WORK/'apt/archives'
        for package in proof['packages']:
            self.guard()
            source = MEDIA/'debs'/Path(package['Filename']).name
            name = package['Package']+'_'+package['Version'].replace(':', '%3a')+'_'+package['Architecture']+'.deb'
            if Path(name).name != name or source.stat().st_size != int(package['Size']) or self.build.sha(source) != package['SHA256']:
                raise RuntimeError('Runtime package identity')
            target = cache/name
            with source.open('rb') as src, target.open('xb') as dst:
                shutil.copyfileobj(src, dst)
            if self.build.sha(target) != package['SHA256']:
                raise RuntimeError('Runtime package copy changed')
        args = ['apt-get', '--no-download', '--no-remove', '-y', '-o', 'Dpkg::Options::=--force-confdef',
                '-o', 'Dpkg::Options::=--force-confold', 'install', *(p+'='+v for p, v in sorted(allowed))]
        plan = self.command('actor-package-plan', ['apt-get', '-s', *args[1:]])
        selected = set()
        for line in plan.splitlines():
            if line.startswith('Remv '): raise RuntimeError('Runtime package removal')
            if line.startswith('Inst '):
                match = re.fullmatch(r'Inst (\S+) \((\S+) .*\)', line)
                if match is None: raise RuntimeError('Runtime solver upgrade or invalid line')
                selected.add((match[1].split(':')[0], match[2]))
        if selected != allowed:
            raise RuntimeError('Runtime solver differs from pinned closure')
        policy = Path('/usr/sbin/policy-rc.d')
        if policy.exists(): raise RuntimeError('Unexpected guest service policy')
        self.command('actor-mask-services', ['systemctl', 'mask', 'mariadb.service', 'mysql.service'])
        policy.write_text('#!/bin/sh\nexit 101\n'); policy.chmod(0o755)
        try: self.command('actor-package-install', args, timeout=600)
        finally: policy.unlink()
        if self.command('actor-package-audit', ['dpkg', '--audit']).strip():
            raise RuntimeError('Runtime dpkg state incomplete')
        identities = self.command('actor-package-identities', ['dpkg-query', '-W', '-f=${Package}\t${Version}\n',
                                  *(p for p, _ in sorted(allowed))])
        if set(tuple(line.split('\t')) for line in identities.splitlines()) != allowed:
            raise RuntimeError('Installed runtime identities differ')
        self.command('actor-perl-modules', ['perl', '-MDBI', '-MDBD::mysql', '-MJSON', '-MScalar::Util', '-e', 'print "modules loaded\\n"'])
        if subprocess.run(['pgrep', '-x', 'mariadbd'], stdout=subprocess.DEVNULL).returncode != 1:
            raise RuntimeError('Unexpected database process')
        return hashlib.sha256(plan.encode()).hexdigest()

    def query(self, label, sql, db=True, timeout=60):
        path = ROOT/'query.sql'
        path.write_text(sql+'\n'); path.chmod(0o600)
        try:
            with path.open('rb') as stream:
                return self.command('actor-'+label, self.db_args(db), stdin=stream, timeout=timeout)
        finally: path.unlink()

    def db_args(self, db=True):
        return ['/usr/bin/mariadb', '--no-defaults', '--protocol=socket', '--socket='+str(ROOT/'run/mysql.sock'),
                '--user=root', '--batch', '--skip-column-names', *(['eqemu_actor'] if db else [])]

    def initialize_database(self):
        data = ROOT/'database'; data.mkdir()
        run = ROOT/'run'; run.mkdir()
        account = pwd.getpwnam('mysql')
        for path in (data, run): os.chown(path, account.pw_uid, account.pw_gid)
        self.command('actor-db-init', ['mariadb-install-db', '--no-defaults', '--user=mysql', '--datadir='+str(data),
                     '--auth-root-authentication-method=socket', '--skip-test-db'], timeout=120)
        console = ROOT/'database-console.log'
        log = console.open('xb')
        args = ['/usr/sbin/mariadbd', '--no-defaults', '--user=mysql', '--datadir='+str(data),
                '--socket='+str(run/'mysql.sock'), '--pid-file='+str(run/'mysql.pid'), '--bind-address=127.0.0.1',
                '--port=3306', '--skip-name-resolve', '--skip-log-bin', '--innodb-buffer-pool-size=256M',
                '--innodb-log-file-size=64M', '--max-allowed-packet=64M', '--max-connections=30', '--tmpdir='+str(run)]
        try:
            proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                    cwd=ROOT, env=self.build.ENV, start_new_session=True)
        finally: log.close()
        self.processes.append(proc)
        end = min(self.deadline, time.monotonic()+60)
        while time.monotonic() < end:
            self.guard()
            if console.stat().st_size > 1024**2: raise RuntimeError('Database console cap')
            if (run/'mysql.sock').exists(): break
            time.sleep(.2)
        else: raise RuntimeError('Database socket readiness missing')
        self.query('db-create', 'CREATE DATABASE eqemu_actor CHARACTER SET latin1;', db=False)

    def import_database(self):
        inventory = json.loads((MEDIA/'provenance/database-inspection.json').read_text())
        expected = {m['path']: m for m in inventory['members']}
        contract = json.loads((MEDIA/'runtime-input-contract.json').read_text())
        if inventory['import_order'] != ['content', 'login', 'player', 'state', 'system']:
            raise RuntimeError('Public SQL import order differs')
        with zipfile.ZipFile(MEDIA/'database/peq-1787356814.zip') as archive:
            for name in contract['database']['import_members']:
                self.guard()
                target = ROOT/'import.sql'; hashed = hashlib.sha256(); count = 0
                try:
                    with archive.open(name) as src, target.open('xb') as dst:
                        while block := src.read(1024**2):
                            self.guard(); count += len(block)
                            if count > expected[name]['bytes']: raise RuntimeError('SQL member size')
                            hashed.update(block); dst.write(block)
                    if count != expected[name]['bytes'] or hashed.hexdigest() != expected[name]['sha256']:
                        raise RuntimeError('Public SQL member identity')
                    with target.open('rb') as stream:
                        self.command('actor-import-'+name.split('_')[-1].split('.')[0], self.db_args(), stdin=stream, timeout=300)
                finally: target.unlink(missing_ok=True)
        tables = sorted({t for g in inventory['groups'].values() for t in g['tables']})
        if set(self.query('tables', 'SHOW TABLES;').splitlines()) != set(tables) or len(tables) != 221:
            raise RuntimeError('Public fixture table inventory')
        if self.query('version', 'SELECT version,bots_version,custom_version FROM db_version;').strip() != '9328\t0\t0':
            raise RuntimeError('Public fixture version')
        empty = sorted(set(inventory['groups']['player']['tables']+inventory['groups']['login']['tables']))
        counts = self.query('empty', ' UNION ALL '.join("SELECT '"+t+"',COUNT(*) FROM `"+t+'`' for t in empty)+';')
        if len(counts.splitlines()) != len(empty) or any(line.split('\t')[1] != '0' for line in counts.splitlines()):
            raise RuntimeError('Public fixture player/login state')
        if self.query('content', "SELECT zoneidnumber,version,short_name FROM zone WHERE zoneidnumber=202 AND version=0; SELECT COUNT(*)>0 FROM items; SELECT COUNT(*)>0 FROM spells_new; SELECT name FROM rule_sets WHERE ruleset_id=1; SELECT rule_value FROM rule_values WHERE ruleset_id=1 AND rule_name='Bots:Enabled';").strip() != '202\t0\tpoknowledge\n1\n1\ndefault\nfalse':
            raise RuntimeError('Required actor public content or ruleset missing')
        if self.query('state', 'SELECT COUNT(*) FROM zone_state_spawns;').strip() != '0':
            raise RuntimeError('Actor fixture zone state is not empty')
        self.query('fixture', "DELETE FROM spawn2 WHERE zone='poknowledge'; UPDATE rule_values SET rule_value='false' WHERE ruleset_id=1 AND rule_name IN ('Zone:UseZoneController','Bots:Enabled','Analytics:CrashReporting','Zone:StateSavingOnShutdown'); UPDATE variables SET value='default' WHERE varname='RuleSet'; UPDATE logsys_categories SET log_to_file=0,log_to_gmsay=0,log_to_discord=0,discord_webhook_id=0; UPDATE logsys_categories SET log_to_console=1 WHERE log_category_description IN ('Info','Error','MySQL Error','QuestErrors','Quests','Crash'); UPDATE logsys_categories SET log_to_console=0 WHERE log_category_description='MySQL Query';")
        if self.query('fixture-checked', "SELECT COUNT(*) FROM spawn2 WHERE zone='poknowledge'; SELECT COUNT(*) FROM rule_values WHERE ruleset_id=1 AND rule_name IN ('Zone:UseZoneController','Bots:Enabled','Analytics:CrashReporting','Zone:StateSavingOnShutdown') AND rule_value='false'; SELECT COUNT(*) FROM discord_webhooks WHERE COALESCE(webhook_url,'')<>'';").strip() != '0\n4\n0':
            raise RuntimeError('Actor derived fixture preconditions')

    def configure(self):
        server = ROOT/'server'; server.mkdir()
        with tarfile.open(MEDIA/'quests/quests-b3e34b8.tar.gz') as archive:
            archive.extractall(server, filter='data')
        (server/'projecteqquests-b3e34b84457d570401ea954ddd66de19179d0e41').rename(server/'quests')
        shutil.copytree(MEDIA/'maps', server/'maps'); shutil.copytree(MEDIA/'opcodes', server/'opcodes')
        for name in ('shared', 'logs'): (server/name).mkdir()
        if self.control == 'missing-map': (server/'maps/base/poknowledge.map').unlink()
        # All required maps are a gate. Native boot tolerating a missing map cannot pass.
        for name in ('base/poknowledge.map', 'water/poknowledge.wtr', 'nav/poknowledge.nav'):
            if not (server/'maps'/name).is_file(): raise RuntimeError('Required actor map missing: '+name)
        password = secrets.token_hex(24); key = secrets.token_hex(24)
        self.secrets.extend((password, key))
        self.query('account', "CREATE USER 'eqemu'@'127.0.0.1' IDENTIFIED BY '"+password+"'; GRANT ALL ON eqemu_actor.* TO 'eqemu'@'127.0.0.1';", db=False)
        config = {'server': {'auto_database_updates': 'false', 'world': {'shortname': 'offlineactor', 'longname': 'Disposable actor validation', 'address': '127.0.0.1', 'localaddress': '127.0.0.1', 'key': key, 'tcp': {'ip': '127.0.0.1', 'port': '9000'}, 'telnet': {'enabled': 'false'}, 'http': {'enabled': 'false'}}, 'database': {'host': '127.0.0.1', 'port': '3306', 'username': 'eqemu', 'password': password, 'db': 'eqemu_actor'}, 'ucs': {'host': '127.0.0.1', 'port': '7778'}, 'queryserver': {'host': '127.0.0.1'}, 'directories': {'quests': 'quests', 'plugins': 'quests/plugins', 'lua_modules': 'quests/lua_modules', 'maps': 'maps', 'patches': 'opcodes/', 'opcodes': 'opcodes/', 'shared_memory': 'shared/', 'logs': 'logs/'}}}
        path = server/'eqemu_config.json'; path.write_text(json.dumps(config)); path.chmod(0o600)
        return server

    def cleanup(self):
        clean = True
        for proc in reversed(self.processes):
            if proc.poll() is not None:
                clean = False
                try: os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                proc.wait(timeout=10)
                continue
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                try: rc = proc.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL); proc.wait(timeout=10); clean = False; continue
                clean = clean and rc == 0
                try: os.killpg(proc.pid, 0)
                except ProcessLookupError: pass
                else:
                    clean = False; os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, OSError): clean = False
        self.processes.clear()
        return clean


def group_live(group):
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            fields = path.read_text().rsplit(')', 1)[1].split()
            if fields[0] != 'Z' and int(fields[2]) == group:
                return True
        except (FileNotFoundError, ProcessLookupError, ValueError, PermissionError):
            continue
    return False


def run(build, control, fixture, binaries, libraries):
    """Run the fixed native scenario on consumed bytes, preserving cleanup on failure."""
    # Package/setup and zone work need a full reserved allocation before any launch.
    if build.DEADLINE-time.monotonic() < RUNTIME_SECONDS:
        raise RuntimeError('Insufficient remaining actor runtime budget')
    if os.geteuid() != 0 or not Path('/opt/eqemu-proof/BUILD_GUEST_ONLY').is_file():
        raise RuntimeError('Actor runtime is guest-only')
    ROOT.mkdir(mode=0o755)
    runtime = Runtime(build, control, fixture)
    prior = {sig: signal.signal(sig, lambda *_: setattr(runtime, 'cancelled', True))
             for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    record = None; error = None; clean = False
    start = time.monotonic()
    try:
        MEDIA.mkdir()
        runtime.command('actor-mount-input', ['mount', '-o', 'ro,nosuid,nodev,noexec', '/dev/disk/by-label/EQEMURUNTIME', str(MEDIA)])
        runtime.verify_inputs()
        package_plan = runtime.install_packages()
        def verify_outputs():
            for name, digest in binaries.items():
                if build.sha(build.WORK/'build/bin'/name) != digest:
                    raise RuntimeError('Runtime replaced candidate executable: '+name)
            for name, digest in libraries.items():
                if build.sha(Path(name)) != digest:
                    raise RuntimeError('Runtime replaced measured library: '+name)
        verify_outputs()
        runtime.initialize_database(); runtime.import_database()
        server = runtime.configure()
        runtime.command('actor-shared-memory', [str(build.WORK/'build/bin/shared_memory')], timeout=180, cwd=server)
        shared = {}
        for name in ('items', 'spells'):
            path = server/'shared'/name
            if not path.is_file() or path.is_symlink() or not 0 < path.stat().st_size <= 768*1024**2:
                raise RuntimeError('Actor shared data incomplete')
            shared[name] = {'bytes': path.stat().st_size, 'sha256': build.sha(path)}
        args = [str(build.WORK/'build/bin/zone'), 'tests:actor-lifecycle']
        if control == 'assertion': args.append('--force-failure-after-create')
        if control == 'cancel': args.append('--wait-for-cancellation-after-create')
        if runtime.deadline-time.monotonic() < ZONE_SECONDS:
            raise RuntimeError('Insufficient remaining ordinary zone budget')
        record = runtime.command('actor-lifecycle', args, timeout=ZONE_SECONDS, cwd=server, actor=True)
        verify_outputs(); runtime.verify_inputs()
    except Exception as exc:
        error = runtime.scrub(str(exc))[-3000:]
    finally:
        clean = runtime.cleanup()
        for sig, handler in prior.items(): signal.signal(sig, handler)
    if record is not None:
        value = {'profile': PROFILE, 'fixture_manifest_sha256': fixture['manifest_sha256'], 'recipe': RECIPE,
                 'result': record, 'database_cleanup': clean, 'elapsed_seconds': round(time.monotonic()-start, 3),
                 'stage_seconds': runtime.stage_times, 'shared': shared, 'package_plan_sha256': package_plan,
                 'outputs_unchanged': error is None, 'inputs_unchanged': error is None}
        build.emit({'kind': 'observation', 'name': 'actor-runtime', 'value': value})
    if error or not clean or record is None:
        raise RuntimeError('Actor runtime refused: '+(error or 'Missing result or database cleanup'))
    if record['exit_code'] != 0:
        raise RuntimeError('actor-lifecycle: exit '+str(record['exit_code'])+'\nCompleted native scenario with database cleanup')
    return value
