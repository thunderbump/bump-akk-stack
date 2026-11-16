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
STATE = ('respawn_times', 'spawn_condition_values', 'spawn2_disabled',
         'data_buckets', 'zone_state_spawns')
PROTECTED = {'instance_list_player': 'id', 'character_corpses': 'instance_id',
             'dynamic_zones': 'instance_id', 'character_data': 'zone_instance'}
RULES = {'Map:FindBestZHeightAdjust': '1', 'Map:FixZWhenPathing': 'true',
         'Zone:UseZoneController': 'true', 'Bots:Enabled': 'false',
         'Zone:StateSavingOnShutdown': 'false'}
MAX_LOG = 4 * 1024 * 1024


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


def quest(source):
    """Keep pinned inputs/call order; send evidence directly to bounded stdout."""
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
    return '$|=1;\nsub probe_emit { print STDOUT $_[0]."\\n"; }\n' + text


def private_config(original, root, assets):
    config = copy.deepcopy(original)
    server = config['server']
    server['auto_database_updates'] = 'false'
    # Replace the entire path collection, including arrays that override scalar paths.
    server['directories'] = {**assets, 'quests': str(root/'quests'),
        'plugins': str(root/'plugins'), 'lua_modules': str(root/'modules'),
        'logs': str(root/'logs'), 'quest_paths': [str(root/'quests')],
        'plugin_paths': [str(root/'plugins')], 'lua_module_paths': [str(root/'modules')]}
    server['files'] = {'plugin.pl': str(root/'plugins/plugin.pl')}
    return config


def validate_contract(c):
    selected_zones(c)
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
        tables = {'game': ('instance_list', *STATE, *PROTECTED, 'rule_values', 'rule_sets', 'variables'),
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
            require(not self.sql('SELECT CONSTRAINT_NAME FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=%s AND (TABLE_NAME IN ('+slots+') OR REFERENCED_TABLE_NAME IN ('+slots+'))', (db,*names,*names)), 'fixture foreign-key side effects refused')
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
        active = self.rows('game', 'variables', 'varname=%s', ('RuleSet',))
        # Native zone/main.cpp falls back to the named default when absent.
        require(len(active) <= 1 and (not active or active[0]['value'] == self.contract['ruleset_name']), 'active ruleset differs')
        sets = self.rows('game', 'rule_sets', 'ruleset_id=%s', (self.contract['ruleset_id'],))
        require(len(sets) == 1 and sets[0]['name'] == self.contract['ruleset_name'] == 'default', 'default ruleset ID/name mismatch')
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
        # Retain range/row locks through bootstrap; no write happened before all checks.

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


def run_child(binary, root, zone, item, receipt, world_pid=None, world_port=None):
    """Guard immediately after spawn; independent cleanup stages always reach reap."""
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(root),
           'EQEMU_COLLISION_OBSERVE': 'server-collision-npc-2011'}
    chunks = bytearray()
    selector = None
    cleanup_errors = []
    started = time.monotonic()
    def child_limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_LOG, MAX_LOG))
    def cleanup_stage(name, action):
        try:
            return action()
        except BaseException:
            cleanup_errors.append(name)
            return None
    def drain(wait):
        if selector is None or not selector.get_map():
            time.sleep(wait)
            return
        for key, _ in selector.select(wait):
            data = os.read(key.fd, 65536)
            if not data:
                selector.unregister(key.fileobj)
            space = MAX_LOG-len(chunks)
            chunks.extend(data[:space])
            require(len(data) <= space, 'native output overflow')
    def await_exit(seconds):
        until = time.monotonic()+seconds
        while process.poll() is None and time.monotonic() < until:
            drain(.1)
    def send(sig, key):
        if process.poll() is None:
            try:
                os.killpg(process.pid, sig)
                receipt[key] = True
            except ProcessLookupError:
                pass
    process = subprocess.Popen([str(binary), zone+':'+str(item['port']), 'NONE', str(item['instance'])],
        cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=child_limits)
    try:
        receipt.update(pid=process.pid, argv_zone=zone, port=item['port'], instance=item['instance'], term_sent=False, kill_sent=False, reaped=False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        require(digest(Path('/proc')/str(process.pid)/'exe') == ZONE_SHA, 'executed zone differs')
        complete = False
        while time.monotonic()-started < 120:
            drain(.1)
            require(process.poll() is None, 'private zone exited early')
            if world_pid is not None:
                receipt['world_connected'] = receipt.get('world_connected', False) or world_connected(world_pid, process.pid, world_port)
            if b'SERVER_COLLISION_ROUTE_DONE' in chunks:
                require(receipt.get('world_connected') or world_pid is None, 'world connection not proved')
                complete = True
                break
        require(complete, 'private zone deadline')
    finally:
        cleanup_stage('stop_file', lambda: (root/'stop-map-validation').touch())
        cleanup_stage('quiesce_wait', lambda: await_exit(3))
        cleanup_stage('term', lambda: send(signal.SIGTERM, 'term_sent'))
        cleanup_stage('term_wait', lambda: await_exit(5))
        cleanup_stage('kill', lambda: send(signal.SIGKILL, 'kill_sent'))
        # wait is independent of stop-file, selector, pipe and signal failures.
        code = cleanup_stage('reap', lambda: process.wait(timeout=5))
        receipt['exit'] = code
        receipt['reaped'] = code is not None
        def final_drain():
            until = time.monotonic()+2
            while selector is not None and selector.get_map() and time.monotonic() < until:
                drain(.1)
            receipt['pipe_eof'] = selector is not None and not selector.get_map()
        cleanup_stage('final_pipe_drain', final_drain)
        if selector is not None:
            cleanup_stage('selector_close', selector.close)
        cleanup_stage('pipe_close', process.stdout.close)
        receipt['quiesced'] = b'MAP_SERVER_PROBE_STOPPED' in chunks
        receipt['seconds'] = time.monotonic()-started
        receipt['evidence'] = '\n'.join(line for line in chunks.decode(errors='replace').splitlines() if line.startswith('SERVER_COLLISION_'))
        if cleanup_errors:
            receipt['cleanup_errors'] = cleanup_errors
    require(not cleanup_errors, 'private child cleanup fault')
    require(receipt['quiesced'] and receipt['exit'] == 0 and receipt['pipe_eof'], 'private shutdown not clean')
    return receipt['evidence']+'\n'


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
    receipt = {'passed':False, 'cleanup':False, 'children':{}, 'reload_gap':'no qualified targeted reload route'}
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
        store = Store(config, c)
        store.preflight()
        save(root/'ownership.json', store.manifest)
        store.bootstrap()
        save(root/'ownership.json', store.manifest)
        # Treat an ambiguous COMMIT response as potentially committed and compensate exactly.
        committed = True
        store.db.commit()
        for zone, _, source, _ in selected_zones(c):
            private = root/zone
            private.mkdir(mode=0o700)
            for name in ('quests','plugins','modules','logs','mods'):
                (private/name).mkdir(mode=0o700)
            target = private/'quests'/zone/('v'+str(c['zones'][zone]['version']))
            target.mkdir(parents=True)
            (target/'2011.pl').write_text(quest(HERE/'vendor'/source))
            save(private/'eqemu_config.json', private_config(config, private, c['assets']))
            child = receipt['children'].setdefault(zone, {})
            text = run_child(args.zone_binary.absolute(), private, zone, c['zones'][zone], child, c['world_pid'], int(config['server']['world']['tcp']['port']))
            (root/(zone+'-evidence.log')).write_text(text)
            receipt[zone] = verify_evidence(text, references[zone], zone, comparator)
        receipt['passed'] = True
    except BaseException as error:
        # Driver messages/config/native output can contain credentials. Keep fixed messages only.
        receipt['error'] = str(error) if isinstance(error, Refusal) else type(error).__name__
    finally:
        if store:
            try:
                if committed:
                    require(all(child.get('reaped') for child in receipt['children'].values()), 'unreaped child; DB cleanup refused')
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
                try:
                    store.db.close()
                except BaseException:
                    receipt['cleanup'] = False
                    receipt['close_error'] = 'connection close unavailable'
        receipt['passed'] = receipt['passed'] and receipt['cleanup']
        save(root/'receipt.json', receipt)
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
