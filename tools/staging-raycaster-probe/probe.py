#!/usr/bin/env python3
"""One operator-owned, fixed two-zone private probe. Importing has no side effects."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import selectors
import shutil
import signal
import socket
import sys
import subprocess
import time

HERE = Path(__file__).resolve().parent
ZONE_SHA = '825751d410c661c76b24f97e8e8e28ab495cdbb14116b48e115ffd8181a8490b'
WORLD_SHA = '1a922b6a7b56e052d27e4a841a9e1a02b67779c472860e54897d15eab0b70dec'
ZONES = (('qeynos2', 2, '2011.pl', 'route.json'),
         ('poknowledge', 202, 'pok-2011.pl', 'pok-route.json'))
NAV_INPUTS = {
    'qeynos2':{'bytes':232993,'sha256':'9e528179eb619005301d6d34566471a8e264c1282235c624382cfaecdc973a08'},
    'poknowledge':{'bytes':1210906,'sha256':'edf48789922d0de8a7b30ee47b8fe023c89c07cebd014f399dd6202ee7752b24'}}
STATE = ('respawn_times', 'spawn_condition_values', 'spawn2_disabled',
         'data_buckets', 'zone_state_spawns')
PROTECTED = {'instance_list_player': 'id', 'character_corpses': 'instance_id',
             'dynamic_zones': 'instance_id', 'character_data': 'zone_instance'}
RULES = {'Map:FindBestZHeightAdjust': '1', 'Map:FixZWhenPathing': 'true',
         'Zone:UseZoneController': 'true', 'Bots:Enabled': 'false',
         'Zone:StateSavingOnShutdown': 'false'}
MAX_LOG = 4 * 1024 * 1024
TIMER_ROWS = 256
TIMER_BYTES = 65536
SHARED_BYTES = 256 * 1024 * 1024
SUPPORT_BYTES = 65536
SUPPORT_MANIFEST_SHA = '69e8d20fc25e3a0bfe8793762e765a7423956521b0d23b373c9bb629af24c381'
SUPPORT_FILES = {'plugins/check_handin.pl', 'plugins/globals.pl',
                 'modules/items.lua', 'modules/string_ext.lua'}
# On unconfirmed reap, do not explicitly close/collect live-child streams.
# Keep their owners reachable until helper exit, which is always NONPASS.
_UNREAPED_IO = []


class Refusal(Exception):
    """Safe fixed-message failure; driver/native error strings are never published."""


def require(condition, message):
    if not condition:
        raise Refusal(message)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, default=str, allow_nan=False, separators=(',', ':'))


def save(path, value):
    # Private root is exclusively created by this invocation; never follow old artifacts.
    with Path(path).open('w', encoding='utf-8') as stream:
        stream.write(encoded(value) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def identifier(name):
    require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_]+', name), 'unsafe SQL identifier')
    return '`' + name + '`'


def load_comparator():
    pins = json.loads((HERE / 'vendor/pins.json').read_text())
    for name, sha in pins['files'].items():
        require(digest(HERE / 'vendor' / name) == sha, 'vendored source changed')
    spec = importlib.util.spec_from_file_location('pinned_evidence', HERE / 'vendor/evidence.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_driver():
    """Import only the reviewed task-local wheel; never install a package."""
    wheel = HERE/'vendor/pymysql-1.1.2-py3-none-any.whl'
    require(wheel.is_file() and not wheel.is_symlink(), 'driver wheel missing')
    require(digest(wheel) == 'e6b1d89711dd51f8f74b1631fe08f039e7d76cf67a42a323d3178f0f25762ed9', 'driver wheel differs')
    require(not any(n == 'cryptography' or n.startswith('cryptography.') or n == 'nacl' or n.startswith('nacl.') for n in sys.modules), 'ambient optional authentication module refused')
    # The wheel opportunistically imports cryptography. Block that optional import
    # in this fresh helper process, then remove only our temporary sentinels.
    sys.path.insert(0, str(wheel))
    sys.modules['cryptography'] = None
    sys.modules['nacl'] = None
    try:
        import pymysql
        require(pymysql.__file__.startswith(str(wheel)+'/'), 'driver origin differs')
        return pymysql
    finally:
        sys.path.remove(str(wheel))
        del sys.modules['cryptography']
        del sys.modules['nacl']


def native_connection_class(driver):
    """Refuse alternate authentication before the pinned driver can dispatch it."""
    class NativeConnection(driver.connections.Connection):
        def _request_authentication(self):
            require(self._auth_plugin_name == 'mysql_native_password', 'unsupported authentication refused')
            return super()._request_authentication()

        def _process_auth(self, plugin_name, auth_packet):
            require(plugin_name == b'mysql_native_password', 'unsupported authentication refused')
            return super()._process_auth(plugin_name, auth_packet)
    return NativeConnection


def selected_zones(contract):
    """One fixed zone per hourly window; initial qualification may select both."""
    selected = contract.get('only_zone')
    require(selected is None or selected in {z[0] for z in ZONES}, 'unknown selected zone')
    return tuple(z for z in ZONES if selected is None or z[0] == selected)


def quest(source, output_fd):
    """Duplicate only our internally created, inherited quest-pipe descriptor."""
    require(type(output_fd) is int and output_fd >= 3, 'invalid private quest descriptor')
    text = source.read_text().replace('quest::debug(', 'probe_emit(')
    text = text.replace('"/runtime/stop-map-validation"', '"stop-map-validation"')
    text = text.replace('sub EVENT_SPAWN { quest::settimer("server_collision", 1); }', '''sub EVENT_SPAWN {
    $npc->ChangeSize(6);
    $npc->SetNPCFactionID(0);
    $npc->ModifyNPCStat("aggro", "0");
    $npc->ModifyNPCStat("assist", "0");
    $npc->ModifyNPCStat("runspeed", "1.25");
    quest::processmobswhilezoneempty(1);
    quest::settimer("server_collision", 1);
}''')
    return r'''# This is a dup of the task-owned pipe, never global STDOUT/STDERR.
open(my $probe_output, '>&', PRIVATE_FD) or die 'private probe output open';
binmode($probe_output, ':raw') or die 'private probe output mode';
my $probe_output_failed = 0;
sub probe_emit {
    die 'private probe output failed' if $probe_output_failed;
    my $line = $_[0]."\n";
    # Each fixed ASCII record fits PIPE_BUF. syswrite has no buffered flush.
    if (length($line) > 4096) {
        $probe_output_failed = 1;
        die 'private probe output record bound';
    }
    local $SIG{PIPE} = 'IGNORE';
    my $written = syswrite($probe_output, $line);
    unless (defined($written) && $written == length($line)) {
        $probe_output_failed = 1;
        die 'private probe output write';
    }
}
'''.replace('PRIVATE_FD', str(output_fd)) + text


def private_config(original, root, assets):
    config = copy.deepcopy(original)
    server = config['server']
    server['auto_database_updates'] = 'false'
    # Replace the entire path collection, including arrays that override scalar paths.
    server['directories'] = {**assets, 'shared_memory':str(root/'shared'), 'quests': str(root/'quests'),
        'plugins': str(root/'plugins'), 'lua_modules': str(root/'modules'),
        'logs': str(root/'logs'), 'quest_paths': [str(root/'quests')],
        'plugin_paths': [str(root/'plugins')], 'lua_module_paths': [str(root/'modules')]}
    server['files'] = {'plugin.pl': str(root/'plugins/plugin.pl')}
    return config


def runtime_inputs(c):
    """Verify the finite deployed utility closure and immutable shared seeds."""
    require(c['support_manifest_sha256'] == SUPPORT_MANIFEST_SHA, 'runtime support selection differs')
    require(digest(HERE/'vendor/runtime-support-pins.json') == SUPPORT_MANIFEST_SHA, 'runtime support source pin differs')
    source = Path(c['support_root'])
    require(source.is_absolute() and source.is_dir(), 'runtime support root missing')
    manifest = source/'MANIFEST.json'
    require(manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size <= SUPPORT_BYTES, 'runtime support manifest missing')
    require(digest(manifest) == c['support_manifest_sha256'], 'runtime support manifest differs')
    entries = json.loads(manifest.read_text())['files']
    require(len(entries) == 4 and {e['destination'] for e in entries} == SUPPORT_FILES, 'runtime support closure differs')
    shared = c['shared_blobs']
    require(set(shared) == {'items','spells'}, 'shared seed closure differs')
    def check(path, entry, bound):
        require(path.is_file() and not path.is_symlink(), 'runtime input missing')
        require(type(entry['bytes']) is int and 0 < entry['bytes'] <= bound, 'runtime input size bound')
        require(path.stat().st_size == entry['bytes'] and digest(path) == entry['sha256'], 'runtime input differs')
    for entry in entries:
        require(entry['name'] == Path(entry['destination']).name, 'runtime support name differs')
        check(source/entry['name'], entry, SUPPORT_BYTES)
    require(sum(e['bytes'] for e in entries) <= SUPPORT_BYTES, 'runtime support total bound')
    for name, entry in shared.items():
        check(Path(c['assets']['shared_memory'])/name, entry, SHARED_BYTES)
    require(sum(e['bytes'] for e in shared.values()) <= SHARED_BYTES, 'shared seed total bound')
    # Verify the source-defined compatibility marker in unchanged deployed data.
    # This is neither native execution nor hand-in behavior qualification.
    for name in ('items.lua','check_handin.pl'):
        require(b'CheckHandin' in (source/name).read_bytes(), 'compatible runtime utility absent')
    return entries


def nav_inputs(c):
    """Only the selected fixed navmeshes, verified before private prep or SQL."""
    result = {}
    for zone, *_ in selected_zones(c):
        source = Path(c['assets']['maps'])/'nav'/(zone+'.nav')
        pin = NAV_INPUTS[zone]
        require(not source.parent.is_symlink() and not source.parent.parent.is_symlink(), 'nav input directory aliased')
        require(source.is_file() and not source.is_symlink(), 'nav input missing or aliased')
        require(not source.stat().st_mode & 0o222, 'mutable nav input refused')
        require(source.stat().st_size == pin['bytes'] and digest(source) == pin['sha256'], 'nav input differs')
        result[zone] = {'source':str(source),**pin}
    return result


def verify_nav_copy(private, zone, record=None):
    """Match the native ServerPath lookup, not the configured maps directory."""
    path = private/'maps/nav'/(zone+'.nav')
    require(not (private/'maps').is_symlink() and not path.parent.is_symlink(), 'nav copy path aliased')
    require(path.is_file() and not path.is_symlink(), 'effective nav missing or aliased')
    st = path.stat()
    require(st.st_uid == os.geteuid() and st.st_mode & 0o777 == 0o400 and st.st_nlink == 1, 'mutable or unowned nav copy')
    require(os.access(path,os.R_OK), 'effective nav unreadable')
    pin = NAV_INPUTS[zone]
    require(st.st_size == pin['bytes'] and digest(path) == pin['sha256'], 'effective nav differs')
    identity = [st.st_dev,st.st_ino]
    if record is not None:
        require(record['effective_path'] == str(path) and record['identity'] == identity, 'effective nav identity differs')
    return {'effective_path':str(path),'bytes':st.st_size,'sha256':pin['sha256'],
            'identity':identity,'mode':'0400','readable':True,'retained':True}


def prepare_nav(private, zone, source, data):
    """Fresh private read-only copy; never chmod or link the approved source."""
    maps = private/'maps'
    maps.mkdir(mode=0o700)
    nav = maps/'nav'
    nav.mkdir(mode=0o700)
    path = nav/(zone+'.nav')
    original = Path(source['source'])
    require(original.name == zone+'.nav' and original.parent.name == 'nav' and
            {k:source[k] for k in ('bytes','sha256')} == NAV_INPUTS[zone], 'nav source mapping differs')
    require(original.is_file() and not original.is_symlink() and not original.parent.is_symlink() and not original.parent.parent.is_symlink(), 'nav source aliased')
    require(not original.stat().st_mode & 0o222 and original.stat().st_size == source['bytes'] and digest(original) == source['sha256'], 'nav source changed before copy')
    with original.open('rb') as src, path.open('xb') as dst:
        shutil.copyfileobj(src,dst,1024*1024)
        dst.flush()
        os.fchmod(dst.fileno(),0o400)
        os.fsync(dst.fileno())
    require(digest(original) == source['sha256'], 'nav source changed during copy')
    data['nav'] = {'source':str(original),**verify_nav_copy(private,zone)}
    nav.chmod(0o500)
    maps.chmod(0o500)


def native_nav_load(native, private, zone):
    """Existing native LogInfo success, bound to this private effective path."""
    path = str(private/'maps/nav'/(zone+'.nav'))
    marker = rb'Loaded Navmesh \[V([1-9][0-9]{0,3})\] file \['+re.escape(path.encode())+rb'\][ \t]*\n'
    matches = re.findall(marker,native)
    count = native.count(b'Loaded Navmesh')
    observed = count == 1 and len(matches) == 1
    return {'effective_path':path,'observed':observed,'marker_count':count,
            'version':int(matches[0]) if observed else None}


def prepare_runtime(private, c, entries, record):
    """Copy only pinned utilities and per-process RW shared files, before DB writes."""
    shared = private/'shared'
    record.update(support=[], shared={'directory':str(shared),'files':[],'locks':[],'removed':False})
    total = sum(e['bytes'] for e in c['shared_blobs'].values())
    require(shutil.disk_usage(private).free >= total + 64*1024*1024, 'private shared copy space')
    shared.mkdir(mode=0o700)
    def copy(source, target, entry, mode):
        with source.open('rb') as src, target.open('xb') as dst:
            shutil.copyfileobj(src,dst,1024*1024)
            dst.flush()
            os.fchmod(dst.fileno(),mode)
            os.fsync(dst.fileno())
        require(target.stat().st_size == entry['bytes'] and digest(target) == entry['sha256'] and digest(source) == entry['sha256'], 'runtime copy differs')
    for entry in entries:
        target = private/entry['destination']
        copy(Path(c['support_root'])/entry['name'],target,entry,0o400)
        record['support'].append({'file':entry['destination'],'bytes':entry['bytes'],'sha256':entry['sha256']})
    for name, entry in c['shared_blobs'].items():
        item={'name':name,'bytes':entry['bytes'],'sha256':entry['sha256'],'copied':False,'removed':False}
        record['shared']['files'].append(item)
        copy(Path(c['assets']['shared_memory'])/name,shared/name,entry,0o600)
        st=(shared/name).stat();item.update(copied=True,identity=[st.st_dev,st.st_ino])
    for name in ('items.lock','spells.lock'):
        with (shared/name).open('xb') as stream:os.fchmod(stream.fileno(),0o600)
        st=(shared/name).stat();record['shared']['locks'].append({'name':name,'identity':[st.st_dev,st.st_ino]})


def release_shared_copy(record, c):
    """Only after all started children are reaped; never remove inputs or logs."""
    shared=record['shared'];directory=Path(shared['directory'])
    if not directory.exists():
        require(not shared['files'] and not shared['locks'], 'private shared directory disappeared')
        shared['removed']=True
        return
    files=shared['files']+shared['locks']
    require({f.name for f in directory.iterdir()} == {e['name'] for e in files}, 'unknown private shared file')
    for item in files:
        f=directory/item['name'];st=f.lstat()
        require(not f.is_symlink() and f.is_file() and [st.st_dev,st.st_ino] == item.get('identity'), 'private shared identity differs')
        require(st.st_size <= SHARED_BYTES, 'private shared size bound')
        item['after_sha256']=digest(f)
        if item['name'] in c['shared_blobs']:
            require(item.get('copied') is True, 'private shared copy incomplete')
            source=Path(c['assets']['shared_memory'])/item['name']
            require(digest(source) == c['shared_blobs'][item['name']]['sha256'], 'shared source changed')
    for item in files:
        (directory/item['name']).unlink();item['removed']=True
    directory.rmdir();shared['removed']=True


def validate_contract(c):
    selected_zones(c)
    require(c.get('allow_native_expired_timer_housekeeping') is True, 'native housekeeping scope not accepted')
    require(c['monitor_window'] == 'exclusive-between-public-samples', 'monitor exclusion missing')
    require(c['read_only_assets'] is True, 'read-only asset mount contract missing')
    require(c['operator_exclusive_reservations'] is True, 'operator reservation ownership missing')
    require(c['ruleset_id'] >= 0 and type(c['ruleset_id']) is int, 'invalid ruleset')
    require(set(c['zones']) == {z[0] for z in ZONES}, 'fixed zone set required')
    ids, ports = [], []
    for z, *_ in ZONES:
        item = c['zones'][z]
        for key, low, high in [('instance', 1, 65535), ('version', 1, 255),
                               ('port', 1024, 65535), ('spawn', 1, 4294967295),
                               ('group', 1, 4294967295)]:
            require(type(item[key]) is int and low <= item[key] <= high, 'invalid reservation')
        ids.append(item['instance']); ports.append(item['port'])
        require(re.fullmatch('[0-9a-f]{64}', item['reference_sha256']) is not None, 'reference pin missing')
        require(item['reference_backend'] in ('ON', 'OFF'), 'reference backend missing')
    require(len(set(ids)) == 2 and len(set(ports)) == 2, 'reservations overlap')
    for key in ('spawn', 'group'):
        require(len({c['zones'][z[0]][key] for z in ZONES}) == 2, 'row reservations overlap')
    require(set(c['assets']) == {'maps', 'patches', 'opcodes', 'shared_memory'}, 'fixed assets required')
    for path in c['assets'].values():
        require(Path(path).is_absolute() and Path(path).is_dir(), 'asset directory missing')


class Store:
    """Single transaction spans gameplay and content DBs on one reviewed server."""
    def __init__(self, config, contract):
        pymysql = load_driver()
        a = config['server']['database']
        b = config['server'].get('content_database') or a
        require(all(a.get(k) == b.get(k) for k in ('host', 'port', 'username', 'password')),
                'separate content credentials/server unsupported')
        self.names = {'game': a['db'], 'content': b['db']}
        for name in self.names.values():
            identifier(name)
        self.db = native_connection_class(pymysql)(host=a['host'], port=int(a.get('port', 3306)),
            user=a['username'], password=a['password'], database=a['db'],
            autocommit=False, connect_timeout=5, read_timeout=5, write_timeout=5,
            cursorclass=pymysql.cursors.DictCursor)
        self.contract = contract
        self.created = []
        self.manifest = {'schemas': {}, 'originals': {}, 'created': self.created}

    def sql(self, query, args=()):
        with self.db.cursor() as cursor:
            cursor.execute(query, args)
            return cursor.fetchall()

    def table(self, role, table):
        return identifier(self.names[role]) + '.' + identifier(table)

    def rows(self, role, table, where, args=()):
        return self.sql('SELECT * FROM '+self.table(role, table)+' WHERE '+where+' FOR UPDATE', args)

    def schema(self):
        expected = self.contract['schemas']
        tables = {'game': ('instance_list', *STATE, *PROTECTED, 'rule_values', 'rule_sets', 'variables', 'spawn_events'),
                  'content': ('spawn2', 'spawngroup', 'spawnentry', 'npc_types', 'zone')}
        require(set(expected) == {r+'.'+t for r, ts in tables.items() for t in ts}, 'schema contract incomplete')
        for role, names in tables.items():
            for table in names:
                ddl = list(self.sql('SHOW CREATE TABLE '+self.table(role, table))[0].values())[1]
                # AUTO_INCREMENT counters change normally; all structural bytes remain pinned.
                ddl = re.sub(r' AUTO_INCREMENT=\d+', '', ddl)
                key = role+'.'+table
                require(hashlib.sha256(ddl.encode()).hexdigest() == expected[key], 'unknown schema: '+key)
                require('ENGINE=InnoDB' in ddl, 'nontransactional table refused')
                self.manifest['schemas'][key] = {'ddl': ddl, 'sha256': expected[key]}
        # Unrelated schema constraints are not fixture effects. Check both ends
        # of every FK and every trigger touching a table this helper may mutate.
        affected = {'game':('instance_list',*STATE),
                    'content':('spawn2','spawngroup','spawnentry')}
        for db in set(self.names.values()):
            names = sorted({t for r,ts in affected.items() if self.names[r] == db for t in ts})
            slots = ','.join(['%s']*len(names))
            require(not self.sql('SELECT CONSTRAINT_NAME FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE (CONSTRAINT_SCHEMA=%s AND TABLE_NAME IN ('+slots+')) OR (UNIQUE_CONSTRAINT_SCHEMA=%s AND REFERENCED_TABLE_NAME IN ('+slots+'))', (db,*names,db,*names)), 'fixture foreign-key side effects refused')
            require(not self.sql('SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=%s AND EVENT_OBJECT_TABLE IN ('+slots+')', (db,*names)), 'fixture DB triggers refused')
        self.db.rollback()

    def preflight(self):
        self.schema()
        require(self.sql("SELECT GET_LOCK('staging-raycaster-probe',0) AS locked")[0]['locked'] == 1, 'probe lock held')
        self.sql('SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE')
        game = self.table('game', 'rule_values')
        rules = self.sql('SELECT rule_name,rule_value FROM '+game+' WHERE ruleset_id=%s ORDER BY rule_name', (self.contract['ruleset_id'],))
        require(hashlib.sha256(encoded(rules).encode()).hexdigest() == self.contract['default_rule_rows_sha256'], 'default rule rows differ')
        self.manifest['effective_rule_rows'] = {'rows': rules, 'sha256': hashlib.sha256(encoded(rules).encode()).hexdigest()}
        rules = {r['rule_name']: r['rule_value'].lower() for r in rules}
        require(all(rules.get(k) == v for k, v in RULES.items()), 'effective rules do not match fixed probe')
        require(self.sql('SELECT ruleset_id FROM '+game+' WHERE ruleset_id=%s LIMIT 1', (self.contract['ruleset_id'],)), 'ruleset absent')
        hotfix = self.rows('game','variables','varname=%s',('hotfix_name',))
        require(len(hotfix) <= 1 and (not hotfix or hotfix[0]['value'] == ''), 'hotfix shared prefix unsupported')
        active = self.rows('game', 'variables', 'varname=%s', ('RuleSet',))
        # Native zone/main.cpp falls back to the named default when absent.
        require(len(active) <= 1 and (not active or active[0]['value'] == self.contract['ruleset_name']), 'active ruleset differs')
        sets = self.rows('game', 'rule_sets', 'ruleset_id=%s', (self.contract['ruleset_id'],))
        require(len(sets) == 1 and sets[0]['name'] == self.contract['ruleset_name'] == 'default', 'default ruleset ID/name mismatch')
        for zone, *_ in ZONES:
            require(not self.rows('game','spawn_events','zone=%s',(zone,)), 'shared zone spawn events refused')
        # rulesys.cpp loads explicit default rows, then the selected zone ruleset.
        for zone, zid, *_ in selected_zones(self.contract):
            item = self.contract['zones'][zone]
            require(item['instance'] <= int(rules.get('Instances:ReservedInstances', '0')), 'instance outside reserved range')
            zrows = self.rows('content', 'zone', 'zoneidnumber=%s AND (version=%s OR version=0)', (zid, item['version']))
            require(zrows and all(int(r['ruleset']) == item['ruleset_id'] for r in zrows), 'zone ruleset differs')
            selected_rules = self.sql('SELECT rule_name,rule_value FROM '+game+' WHERE ruleset_id=%s ORDER BY rule_name', (item['ruleset_id'],))
            require(selected_rules, 'zone ruleset empty')
            require(hashlib.sha256(encoded(selected_rules).encode()).hexdigest() == item['rule_rows_sha256'], 'zone rule rows differ')
            effective = dict(rules)
            effective.update({r['rule_name']:r['rule_value'].lower() for r in selected_rules})
            require(all(effective.get(k) == v for k,v in RULES.items()), 'zone effective rules differ')
            self.manifest.setdefault('zone_rules', {})[zone] = {'rows':selected_rules,'effective_fixed':{k:effective[k] for k in RULES}}
            require(not self.rows('game', 'instance_list', 'zone=%s AND version=%s', (zid, item['version'])), 'instance version already in use')
            originals = {'zone': zrows, 'active_ruleset': active, 'rule_sets': sets}
            originals['npc_types'] = self.rows('content', 'npc_types', 'id=2011')
            require(len(originals['npc_types']) == 1, 'NPC 2011 absent')
            originals['spawn2'] = self.rows('content', 'spawn2', 'zone=%s AND (version=%s OR version=-1)', (zone, item['version']))
            require(not originals['spawn2'], 'matching or wildcard spawns exist')
            checks = [('game','instance_list','id',item['instance']),
                ('content','spawn2','id',item['spawn']), ('content','spawngroup','id',item['group']),
                ('content','spawnentry','spawngroupID',item['group'])]
            for role, table, column, value in checks:
                originals[role+'.'+table] = self.rows(role,table,identifier(column)+'=%s',(value,))
                require(not originals[role+'.'+table], 'reservation occupied')
            for table in STATE:
                require(not self.rows('game',table,'instance_id=%s',(item['instance'],)), 'instance state already exists')
            self.protected_empty(item['instance'])
            self.manifest['originals'][zone] = {'rows': originals,
                'sha256': hashlib.sha256(encoded(originals).encode()).hexdigest()}
        self.manifest['respawn_timers_before'] = self.timer_snapshot()
        # Retain range/row locks through bootstrap; no write happened before all checks.

    def timer_snapshot(self):
        """Complete bounded native-housekeeping evidence, never a restore source."""
        stamp = self.sql('SELECT UNIX_TIMESTAMP(NOW()) AS captured_unix')[0]['captured_unix']
        require(type(stamp) is int and stamp >= 0, 'invalid timer snapshot time')
        rows = self.sql('SELECT * FROM '+self.table('game','respawn_times')+' ORDER BY id,instance_id LIMIT '+str(TIMER_ROWS+1))
        require(len(rows) <= TIMER_ROWS, 'timer snapshot row bound')
        snapshot = {'captured_unix':stamp, 'rows':rows}
        require(len(encoded(snapshot).encode()) <= TIMER_BYTES, 'timer snapshot byte bound')
        return snapshot

    def protected_empty(self, instance):
        for table, column in PROTECTED.items():
            require(not self.rows('game',table,identifier(column)+'=%s',(instance,)), 'player/dynamic instance state exists')

    def insert(self, role, table, values, identity):
        cols = ','.join(identifier(c) for c in values)
        self.sql('INSERT INTO '+self.table(role, table)+' ('+cols+') VALUES ('+','.join(['%s']*len(values))+')', tuple(values.values()))
        rows = self.rows(role, table, identity[0], identity[1])
        require(len(rows) == 1, 'created row not unique')
        self.created.append({'role': role, 'table': table, 'row': rows[0],
                             'sha256': hashlib.sha256(encoded(rows[0]).encode()).hexdigest()})

    def bootstrap(self):
        for zone, zid, _, route in selected_zones(self.contract):
            item = self.contract['zones'][zone]
            now = int(time.time())
            self.insert('game', 'instance_list', {'id':item['instance'], 'zone':zid,
                'version':item['version'], 'is_global':0, 'start_time':now, 'duration':600,
                'expire_at':now+600,'never_expires':0,'notes':'staging-raycaster-probe'}, ('id=%s',(item['instance'],)))
            self.insert('content','spawngroup',{'id':item['group'],'name':'private_raycaster_'+zone,
                'spawn_limit':1}, ('id=%s',(item['group'],)))
            self.insert('content','spawnentry',{'spawngroupID':item['group'],'npcID':2011,'chance':100}, ('spawngroupID=%s',(item['group'],)))
            point = json.loads((HERE/'vendor'/route).read_text())['points'][0]
            self.insert('content','spawn2',{'id':item['spawn'],'spawngroupID':item['group'],
                'zone':zone,'version':item['version'],'x':point[0],'y':point[1],'z':point[2],
                'heading':0,'respawntime':600,'variance':0,'pathgrid':0,'_condition':0}, ('id=%s',(item['spawn'],)))

    def delete_exact(self, role, table, row):
        # These keys are fixed by the complete schema hashes. No FLOAT predicate
        # or text collation is allowed to establish ownership. The SELECT lock
        # spans the exact canonical comparison and DELETE in this transaction.
        keys = {
            'game.instance_list':('id',), 'game.respawn_times':('id','instance_id'),
            'game.spawn_condition_values':('id','instance_id','zone'),
            'game.spawn2_disabled':('id',), 'game.data_buckets':('id',),
            'game.zone_state_spawns':('id',), 'content.spawn2':('id',),
            'content.spawngroup':('id',), 'content.spawnentry':('spawngroupID','npcID')}
        columns = keys.get(role+'.'+table)
        require(columns is not None, 'unknown cleanup identity')
        require(all(type(row.get(c)) in (int,str) for c in columns), 'invalid cleanup identity')
        parts = [identifier(c)+' <=> BINARY %s' if isinstance(row[c],str)
                 else identifier(c)+' <=> %s' for c in columns]
        # Explicit BINARY on the column too, avoiding case/space-folding collation.
        parts = [('BINARY '+part) if isinstance(row[c],str) else part for c,part in zip(columns,parts)]
        where, args = ' AND '.join(parts), tuple(row[c] for c in columns)
        current = self.rows(role, table, where, args)
        require(len(current) == 1 and encoded(current[0]) == encoded(row), 'owned row changed or missing; cleanup refused')
        with self.db.cursor() as cursor:
            cursor.execute('DELETE FROM '+self.table(role,table)+' WHERE '+where+' LIMIT 1', args)
            require(cursor.rowcount == 1, 'conditional delete did not remove exactly one row')

    def cleanup(self):
        # Called only after owned children were reaped. Preserve player state on conflict.
        for zone, *_ in selected_zones(self.contract):
            item = self.contract['zones'][zone]
            self.protected_empty(item['instance'])
            for table in STATE:
                for row in self.rows('game',table,'instance_id=%s',(item['instance'],)):
                    self.delete_exact('game',table,row)
        for created in reversed(self.created):
            self.delete_exact(created['role'],created['table'],created['row'])
        self.db.commit()


def verify_evidence(text, reference, zone, comparator):
    require(len(text.encode()) <= MAX_LOG, 'evidence overflow')
    fixture = json.loads((HERE/'vendor'/next(z[3] for z in ZONES if z[0] == zone)).read_text())
    queries = comparator.parse_queries(text)
    require({q['npc'] for q in queries.values()} == {'2011'}, 'wrong NPC')
    require(len({q['entity'] for q in queries.values()}) == 1 and int(queries['start']['entity']) > 0, 'wrong query entity')
    route = comparator.parse_route(text, 'ON', fixture)
    require([int(r['remaining']) for r in route['native']] == list(range(4095, 4095-len(route['native']), -1)), 'native budget sequence invalid')
    before_queries = comparator.parse_queries(reference[0])
    before_route = comparator.parse_route(reference[0], reference[1], fixture)
    comparator.compare(before_queries, queries)
    comparator.compare_route(before_route, route)
    return {'queries':queries, 'route':route}


def world_connected(world, zone, port):
    """Both loopback TCP endpoints must be owned by the pinned world/private PIDs."""
    def inodes(pid):
        found = set()
        for fd in Path('/proc', str(pid), 'fd').iterdir():
            try:
                link = os.readlink(fd)
            except FileNotFoundError:
                continue
            if link.startswith('socket:['):
                found.add(link[8:-1])
        return found
    world_fds, zone_fds = inodes(world), inodes(zone)
    target = '0100007F:' + format(port, '04X')
    rows = [line.split() for line in Path('/proc/net/tcp').read_text().splitlines()[1:]]
    return any(row[3] == '01' and row[9] in zone_fds and row[2] == target
               and row[1].startswith('0100007F:') and any(
                   peer[3] == '01' and peer[9] in world_fds and peer[1] == row[2]
                   and peer[2] == row[1] for peer in rows) for row in rows)


def child_wait_snapshot(pid, start_ticks):
    """Advisory bounded reads of this child only, without ptrace or permission changes."""
    def read(path, bound):
        with Path(path).open('rb') as stream:
            raw = stream.read(bound+1)
        require(len(raw) <= bound, 'passive proc bound')
        return raw.decode('ascii')
    def identity():
        return int(read(Path('/proc',str(pid),'stat'),8192).rsplit(')',1)[1].split()[19])
    def state(root):
        status = read(root/'status',4096)
        fields = {k:v.strip() for k,v in (line.split(':',1) for line in status.splitlines())
                  if k in ('State','Threads','VmRSS','voluntary_ctxt_switches','nonvoluntary_ctxt_switches')}
        try:
            fields['wchan'] = read(root/'wchan',128).strip()
        except (OSError, ValueError):
            fields['wchan'] = None
            fields['wchan_unavailable'] = True
        return fields
    try:
        if start_ticks is None or identity() != start_ticks:
            return {'unavailable':'child start identity unavailable or changed'}
        root = Path('/proc',str(pid))
        result = {'start_ticks':start_ticks,'main':state(root),'threads':[],'thread_limit':16}
        for index, entry in enumerate((root/'task').iterdir()):
            if index == 16:
                result['threads_truncated'] = True
                break
            try:
                result['threads'].append({'tid':int(entry.name),**state(entry)})
            except (OSError, ValueError):
                result['threads'].append({'tid':int(entry.name),'unavailable':True})
        require(identity() == start_ticks, 'child identity changed during observation')
        return result
    except (OSError, ValueError, IndexError, Refusal):
        return {'unavailable':'passive proc read unavailable'}


def capture_text(native, quest_bytes):
    """Validate both complete streams independently; never repair mixed records."""
    texts = []
    fields = {
        b'SERVER_COLLISION_NATIVE':set('caller entity backend kind from to result remaining'.split()),
        b'SERVER_COLLISION_QUERY':set('id time npc entity from size origin adjusted eyes to target_size target_eyes ground los'.split()),
        b'SERVER_COLLISION_FLOOR':set('id xyz ground'.split()),
        b'SERVER_COLLISION_REQUEST':set('caller to'.split()),
        b'SERVER_COLLISION_POSE':set('tick xyz ground moving'.split()),
        b'SERVER_COLLISION_QUERIES_DONE':set(),b'SERVER_COLLISION_ROUTE_DONE':set(),b'MAP_SERVER_PROBE_STOPPED':set()}
    for kind, data in (('native',native),('quest',quest_bytes)):
        data = bytes(data)
        require(data and data.endswith(b'\n'), kind+' capture incomplete')
        try:
            text = bytes(data).decode('utf-8' if kind == 'native' else 'ascii')
        except UnicodeError:
            raise Refusal(kind+' capture encoding invalid')
        for line in data.split(b'\n')[:-1]:
            if kind == 'quest' or b'SERVER_COLLISION_' in line or b'MAP_SERVER_PROBE_STOPPED' in line:
                require(b'\r' not in line,'CR inside evidence record')
                tokens = line.split()
                require(tokens and tokens[0] in fields and b'\x00' not in line,'invalid capture record')
                require((tokens[0] == b'SERVER_COLLISION_NATIVE') == (kind == 'native'),'record on wrong stream')
                pairs = [token.split(b'=',1) for token in tokens[1:]]
                require(all(len(pair) == 2 and pair[1] for pair in pairs),'invalid record fields')
                keys = [pair[0].decode('ascii') for pair in pairs]
                require(len(keys) == len(set(keys)) and set(keys) == fields[tokens[0]],'record field set differs')
            if b'SERVER_COLLISION_' in line:
                require(line.count(b'SERVER_COLLISION_') == 1 and line.startswith(b'SERVER_COLLISION_'), 'mixed collision framing')
        texts.append(text)
    for marker in (b'SERVER_COLLISION_QUERIES_DONE',b'SERVER_COLLISION_ROUTE_DONE',b'MAP_SERVER_PROBE_STOPPED'):
        require(bytes(quest_bytes).split(b'\n').count(marker) == 1,'missing or duplicate quest completion')
    # Both already end in LF. This orders streams, not events across streams.
    return texts[0]+texts[1]


def run_child(binary, root, zone, item, receipt, world_pid=None, world_port=None):
    """Two owned streams share one budget; independent cleanup stages always reap."""
    env = {'PATH':'/usr/bin:/bin','HOME':str(root),
           'EQEMU_COLLISION_OBSERVE':'server-collision-npc-2011'}
    chunks = {'native':bytearray(),'quest':bytearray()}
    observed = {'native':0,'quest':0}
    eof = {'native':False,'quest':False}
    selector, process, quest_stream = None, None, None
    write_fd = None
    cleanup_errors = []
    started = time.monotonic()
    receipt.update(started=False,reaped=None,phases={},passive_observations=[],
                   capture={'complete':False,'budget':MAX_LOG,'overflow':False})
    def mark(name):
        receipt['phases'].setdefault(name,time.monotonic()-started)
    def cleanup_stage(name, action):
        try:
            return action()
        except BaseException:
            cleanup_errors.append(name)
            return None
    def poll():
        code = process.poll()
        if code is not None:
            mark('exit_first_observed')
        return code
    def observe(label):
        receipt['passive_observations'].append({'phase':label,'seconds':time.monotonic()-started,
            'facts':child_wait_snapshot(process.pid,receipt.get('start_ticks'))})
    def child_limits():
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_LOG,MAX_LOG))
    def drain(wait):
        if selector is None or not selector.get_map():
            time.sleep(wait)
            return
        for key, _ in selector.select(wait):
            data = os.read(key.fd,65536)
            kind = key.data
            if not data:
                selector.unregister(key.fileobj)
                eof[kind] = True
            observed[kind] += len(data)
            space = MAX_LOG-sum(len(value) for value in chunks.values())
            chunks[kind].extend(data[:space])
            if len(data) > space:
                receipt['capture']['overflow'] = True
            require(len(data) <= space,'combined output overflow')
        if b'MAP_SERVER_PROBE_STOPPED\n' in chunks['quest']:
            mark('stop_ack_first_observed')
    def await_exit(until):
        while poll() is None and time.monotonic() < until:
            drain(min(.1,max(0,until-time.monotonic())))
    def send(sig,key):
        if poll() is None:
            try:
                os.killpg(process.pid,sig)
                receipt[key] = True
                mark(key)
            except ProcessLookupError:
                pass
    def stop_file():
        mark('stop_file_attempt')
        (root/'stop-map-validation').touch()
        mark('stop_file_created')
    def retain(kind):
        # Raw files are private and may contain native console secrets. Never print them.
        name = kind+'-capture.bin'
        payload = bytes(chunks[kind])
        with (root/name).open('xb') as stream:
            os.fchmod(stream.fileno(),0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        require((root/name).read_bytes() == payload,'raw capture readback differs')
        receipt['capture'][kind] = {'file':name,'bytes':len(payload),
            'sha256':hashlib.sha256(payload).hexdigest(),'eof':eof[kind],'observed_bytes':observed[kind]}
    try:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        quest_stream = os.fdopen(read_fd,'rb',buffering=0)
        # The descriptor comes only from this pipe, not a CLI/contract selector.
        target = root/'quests'/zone/('v'+str(item['version']))/'2011.pl'
        source = HERE/'vendor'/next(z[2] for z in ZONES if z[0] == zone)
        with target.open('x') as stream:
            stream.write(quest(source,write_fd))
        process = subprocess.Popen([str(binary),zone+':'+str(item['port']),'NONE',str(item['instance'])],
            cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True,
            pass_fds=(write_fd,),preexec_fn=child_limits)
        try:
            receipt.update(started=True,pid=process.pid,argv_zone=zone,port=item['port'],instance=item['instance'],
                           term_sent=False,kill_sent=False,reaped=False,quest_descriptor=write_fd)
            os.close(write_fd)
            write_fd = None
            try:
                with Path('/proc',str(process.pid),'stat').open() as stream:
                    receipt['start_ticks'] = int(stream.read(8192).rsplit(')',1)[1].split()[19])
            except (OSError,ValueError,IndexError):
                receipt['start_ticks'] = None
            selector = selectors.DefaultSelector()
            selector.register(process.stdout,selectors.EVENT_READ,'native')
            selector.register(quest_stream,selectors.EVENT_READ,'quest')
            require(digest(Path('/proc')/str(process.pid)/'exe') == ZONE_SHA,'executed zone differs')
            complete = False
            while time.monotonic()-started < 120:
                drain(.1)
                require(poll() is None,'private zone exited early')
                if world_pid is not None:
                    receipt['world_connected'] = receipt.get('world_connected',False) or world_connected(world_pid,process.pid,world_port)
                if b'SERVER_COLLISION_ROUTE_DONE\n' in chunks['quest']:
                    require(receipt.get('world_connected') or world_pid is None,'world connection not proved')
                    complete = True
                    break
            require(complete,'private zone deadline')
        finally:
            # Passive reads consume these existing windows; they add no extra wait.
            until = time.monotonic()+3
            cleanup_stage('stop_file',stop_file)
            cleanup_stage('observe_stop',lambda:observe('stop_file'))
            cleanup_stage('quiesce_wait',lambda:await_exit(until))
            until = time.monotonic()+5
            cleanup_stage('term',lambda:send(signal.SIGTERM,'term_sent'))
            cleanup_stage('observe_term',lambda:observe('after_term'))
            cleanup_stage('term_wait',lambda:await_exit(until))
            until = time.monotonic()+5
            cleanup_stage('observe_before_kill',lambda:observe('before_kill'))
            cleanup_stage('kill',lambda:send(signal.SIGKILL,'kill_sent'))
            code = cleanup_stage('reap',lambda:process.wait(timeout=max(.001,until-time.monotonic())))
            receipt['exit'] = code
            receipt['reaped'] = code is not None
            if code is not None:
                mark('exit_first_observed')
                mark('reaped')
            def final_drain():
                until = time.monotonic()+2
                while selector is not None and selector.get_map() and time.monotonic() < until:
                    drain(.1)
            cleanup_stage('final_pipe_drain',final_drain)
            receipt['pipe_eof'] = eof['native'] and eof['quest']
            receipt['quiesced'] = b'MAP_SERVER_PROBE_STOPPED\n' in chunks['quest']
            receipt['navmesh_load'] = native_nav_load(chunks['native'],root,zone)
            receipt['seconds'] = time.monotonic()-started
            # Final capture and closure require confirmed reap; errors never yield PASS.
            if receipt['reaped']:
                cleanup_stage('retain_native',lambda:retain('native'))
                cleanup_stage('retain_quest',lambda:retain('quest'))
            else:
                cleanup_errors.append('capture_unconfirmed_reap')
            receipt['capture']['complete'] = receipt['reaped'] and all(eof.values()) and not cleanup_errors and not receipt['capture']['overflow']
    finally:
        if process is None or receipt.get('reaped'):
            if write_fd is not None:
                cleanup_stage('writer_close',lambda:os.close(write_fd))
            if selector is not None:
                cleanup_stage('selector_close',selector.close)
            if quest_stream is not None:
                cleanup_stage('quest_pipe_close',quest_stream.close)
            if process is not None:
                cleanup_stage('native_pipe_close',process.stdout.close)
        else:
            _UNREAPED_IO.append((process,selector,quest_stream,write_fd))
            receipt['capture']['close_deferred_unconfirmed_reap'] = True
        if cleanup_errors:
            receipt['cleanup_errors'] = cleanup_errors
            receipt['capture']['complete'] = False
    require(not cleanup_errors,'private child cleanup/capture fault')
    require(receipt['quiesced'] and receipt['exit'] == 0 and receipt['pipe_eof'],'private shutdown not clean')
    require(receipt['navmesh_load']['observed'],'native navmesh load not observed')
    return capture_text(chunks['native'],chunks['quest'])

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--contract', required=True, type=Path)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--zone-binary', required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.root.absolute()
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    def terminate(signum, frame):
        raise Refusal('operator terminated probe')
    signal.signal(signal.SIGTERM, terminate)
    receipt = {'passed':False, 'cleanup':False, 'children':{}, 'reload_gap':'no qualified targeted reload route',
        'native_housekeeping':{'scope':'unchanged native lifecycle: global expired NPC timers/quest globals and event-log default initialization; not fixture-confined',
                               'attribution':'before/after differences may include concurrent world activity',
                               'before':None,'after':None}, 'runtime_data':{}, 'shared_cleanup':False}
    store = None
    committed = False
    try:
        comparator = load_comparator()
        c = json.loads(args.contract.read_text())
        validate_contract(c)
        require(digest(args.zone_binary) == ZONE_SHA, 'candidate zone hash differs')
        require(digest(Path('/proc')/str(c['world_pid'])/'exe') == WORLD_SHA, 'world hash differs')
        config = json.loads(args.config.read_text())
        require(config['server']['world']['tcp']['ip'] == '127.0.0.1', 'world TCP must be loopback')
        references = {}
        for zone, *_ in selected_zones(c):
            item = c['zones'][zone]
            require(digest(item['reference']) == item['reference_sha256'], 'reference digest differs')
            require(Path(item['reference']).stat().st_size <= MAX_LOG, 'reference too large')
            references[zone] = (Path(item['reference']).read_text(), item['reference_backend'])
            # Verify port availability now; operator retains exclusive reservation until cleanup.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(('0.0.0.0', item['port']))
        inputs = runtime_inputs(c)
        navigation = nav_inputs(c)
        for zone, _, source, _ in selected_zones(c):
            private = root/zone
            private.mkdir(mode=0o700)
            for name in ('quests','plugins','modules','logs','mods'):
                (private/name).mkdir(mode=0o700)
            target = private/'quests'/zone/('v'+str(c['zones'][zone]['version']))
            target.mkdir(parents=True)
            data = receipt['runtime_data'].setdefault(zone,{})
            prepare_nav(private,zone,navigation[zone],data)
            prepare_runtime(private,c,inputs,data)
            save(private/'eqemu_config.json', private_config(config, private, c['assets']))
        for zone, data in receipt['runtime_data'].items():
            verify_nav_copy(root/zone,zone,data['nav'])
        store = Store(config, c)
        store.preflight()
        receipt['native_housekeeping']['before'] = store.manifest.get('respawn_timers_before')
        save(root/'ownership.json', store.manifest)
        store.bootstrap()
        save(root/'ownership.json', store.manifest)
        # Treat an ambiguous COMMIT response as potentially committed and compensate exactly.
        committed = True
        store.db.commit()
        for zone, *_ in selected_zones(c):
            private = root/zone
            verify_nav_copy(private,zone,receipt['runtime_data'][zone]['nav'])
            child = receipt['children'].setdefault(zone, {})
            text = run_child(args.zone_binary.absolute(), private, zone, c['zones'][zone], child, c['world_pid'], int(config['server']['world']['tcp']['port']))
            receipt[zone] = verify_evidence(text, references[zone], zone, comparator)
        receipt['passed'] = True
    except BaseException as error:
        # Driver messages/config/native output can contain credentials. Keep fixed messages only.
        receipt['error'] = str(error) if isinstance(error, Refusal) else type(error).__name__
    finally:
        if store:
            try:
                if committed:
                    require(all(child.get('started') is False or child.get('reaped') is True for child in receipt['children'].values()), 'unreaped child; DB cleanup refused')
                    store.cleanup()
                else:
                    store.db.rollback()
                receipt['cleanup'] = True
            except BaseException:
                receipt['cleanup_error'] = 'conditional cleanup failed; operator must inspect ownership manifest'
                try:
                    store.db.rollback()
                except BaseException:
                    receipt['rollback_error'] = 'rollback unavailable'
            finally:
                if receipt['native_housekeeping']['before'] is not None:
                    try:
                        receipt['native_housekeeping']['after'] = store.timer_snapshot()
                        require(type(receipt['native_housekeeping']['after']) is dict, 'timer snapshot unavailable')
                    except BaseException:
                        receipt['passed'] = False
                        receipt['housekeeping_snapshot_error'] = 'complete timer snapshot unavailable'
                try:
                    store.db.close()
                except BaseException:
                    receipt['cleanup'] = False
                    receipt['close_error'] = 'connection close unavailable'
        all_reaped = all(child.get('started') is False or child.get('reaped') is True for child in receipt['children'].values())
        receipt['shared_cleanup'] = all_reaped
        for zone, data in receipt['runtime_data'].items():
            try:
                require(all_reaped, 'unreaped child; shared copies retained')
                if 'shared' in data:
                    release_shared_copy(data,c)
            except BaseException:
                receipt['shared_cleanup'] = False
                receipt['shared_cleanup_error'] = 'private copies retained; inspect runtime data receipt'
            if 'nav' in data:
                try:
                    verify_nav_copy(root/zone,zone,data['nav'])
                    data['nav']['post_hash_equal'] = True
                except BaseException:
                    receipt['passed'] = False
                    receipt['nav_input_error'] = 'retained effective nav verification failed'
        receipt['passed'] = receipt['passed'] and receipt['cleanup'] and receipt['shared_cleanup']
        save(root/'receipt.json', receipt)
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
