"""Fixed public input admission and typed observation checks for central-cdau.

This module contains no host candidate launcher. Native observation is supplied
by the separately owned Server interface, never inferred from status polling.
"""
import hashlib
import io
import json
import math
from pathlib import Path
import re
import tarfile

from integration_artifacts import CAP, CONTRACT_SHA, FIXTURE_SHA, SELECTION, decode, encoded, fail, hex_string

FIXTURE_BYTES = 1300480
MANIFEST_SHA = 'bc266220eba8cf0685463856221ed2a71d035ec1c5607c73e2058d1376df8797'
KINDS = {5: 2304, 6: 256, 7: 20, 8: 12, 9: 16, 10: 64, 11: 384, 12: 128}
TYPES = {
    5: ('cause', 'bool', 'u32', 'u8', 'u64', 'u64', 'u16', 'sha'),
    6: ('ctx', 'direction', 'bool', 'reaction', 'denial', 'i64', 'i64'),
    7: ('u16', 'i32', 'i32', 'i32'),
    9: ('level_phase', 'u8', 'u8', 'u64', 'u64'),
    10: ('ctx', 'i32', 'i32', 'i32', 'i32', 'reaction', 'flags', 'u32'),
    12: ('fault_phase', 'case', 'u64', 'u16', 'failure', 'u64', 'u64', 'u64'),
}
RANGES = {'u8': (0, 255), 'u16': (0, 65535), 'u32': (0, 4294967295),
          'i32': (-2147483648, 2147483647), 'proc': (0, 23), 'ctx': (0, 127),
          'cause': (0, 10), 'direction': (0, 1), 'reaction': (0, 9), 'denial': (0, 3),
          'level_phase': (0, 2), 'fault_phase': (0, 4), 'case': (0, 2), 'failure': (0, 12), 'flags': (0, 255)}


def scalar(value, kind):
    if kind in RANGES:
        lo, hi = RANGES[kind]
        if type(value) is not int or not lo <= value <= hi:
            fail()
    elif kind == 'bool':
        if type(value) is not bool:
            fail()
    elif kind == 'sha':
        hex_string(value, 64)
    elif kind in ('u64', 'i64'):
        if not isinstance(value, str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}' if kind == 'u64' else r'0|-?[1-9][0-9]{0,18}|-?[1-9][0-9]{19}', value):
            fail()
        lo, hi = (0, 2**64 - 1) if kind == 'u64' else (-2**63, 2**63 - 1)
        if not lo <= int(value) <= hi:
            fail()
    elif kind == 'f64':
        if (not isinstance(value, str) or len(value) > 32 or not re.fullmatch(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?', value)
                or not math.isfinite(float(value))):
            fail()
    else:
        fail()


def typed(values, kinds):
    if not isinstance(values, list) or len(values) != len(kinds):
        fail()
    for value, kind in zip(values, kinds):
        scalar(value, kind)


def verify_fixture(path, target=None):
    """Verify exact tar bytes and all 27 safe regular members before any extraction."""
    import os
    import stat
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != FIXTURE_BYTES:
            fail()
        raw = stream.read(FIXTURE_BYTES + 1)
    if len(raw) != FIXTURE_BYTES or hashlib.sha256(raw).hexdigest() != FIXTURE_SHA:
        fail()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        names = [m.name for m in members]
        if len(names) != 27 or len(set(names)) != 27 or any(not m.isfile() or m.linkname or m.mode != 0o444 for m in members):
            fail()
        manifest = archive.extractfile('manifest.json').read()
        if hashlib.sha256(manifest).hexdigest() != MANIFEST_SHA:
            fail()
        records = decode(manifest)['files']
        expected = {r['path']: r for r in records}
        if set(names) != set(expected) | {'manifest.json'}:
            fail()
        payload = {}
        for name in names:
            if name.startswith('/') or '..' in name.split('/'):
                fail()
            data = archive.extractfile(name).read()
            if name != 'manifest.json' and (len(data) != expected[name]['bytes'] or hashlib.sha256(data).hexdigest() != expected[name]['sha256']):
                fail()
            payload[name] = data
    if target is not None:
        target = Path(target)
        target.mkdir(mode=0o700)
        for name, data in payload.items():
            path = target / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(data)
            path.chmod(0o400)
    return payload


class Events:
    """Reject loss, overflow, unregistered references and typed variant mismatch."""
    def __init__(self, contexts):
        self.contexts = contexts
        self.last = {}
        self.counts = dict.fromkeys(KINDS, 0)

    def accept(self, event):
        if not isinstance(event, list) or len(event) != 7:
            fail()
        proc, sequence, micros, kind, context, revision, payload = event
        typed([proc, context, revision], ['proc', 'ctx', 'u64'])
        if (type(sequence) is not int or sequence != self.last.get(proc, 0) + 1 or sequence > 4096
                or type(micros) is not int or not 0 <= micros <= 1800000000
                or type(kind) is not int or kind not in KINDS
                or context >= len(self.contexts) or self.contexts[context][0] != proc):
            fail()
        kinds = TYPES.get(kind)
        if kind == 8:
            if not isinstance(payload, list) or len(payload) != 8 or type(payload[0]) is not int:
                fail()
            phase = payload[0]
            kinds = {0: ('u8','u16','ctx','ctx','u64','u64','u64','u64'),
                     1: ('u8','u16','ctx','u64','u64','u64','u64','u8'),
                     2: ('u8','u16','proc','u64','u64','u64','u64','u64')}.get(phase)
            if kinds is None or (phase == 0 and payload[4:] != ['0'] * 4) or (phase == 1 and (type(payload[7]) is not int or payload[7] > 5)):
                fail()
        if kind == 11:
            if not isinstance(payload, list) or len(payload) != 8 or type(payload[0]) is not int or not 0 <= payload[0] <= 8:
                fail()
            kinds = ('u8','u16','ctx','u32','flags', *(['f64'] * 3 if payload[0] == 0 else ['u64'] * 3))
        typed(payload, kinds)
        self.counts[kind] += 1
        if self.counts[kind] > KINDS[kind]:
            fail()
        self.last[proc] = sequence


def validate_contexts(contexts, process_count):
    if not isinstance(contexts, list) or len(contexts) > 128:
        fail()
    for context in contexts:
        typed(context, ['proc','u8', *(['u64'] * 7), *(['u32'] * 4), 'u8','u8'])
        if (context[13] in (0,1) and context[1] not in (1,2,3)) or (context[13] in (2,3) and context[1]!=0): fail()
        if context[13]==3 and (context[1:12]!=[0,*(['0']*7),0,0,0] or context[14]!=0): fail()
        if context[0] >= process_count or context[1] > 3 or len(encoded(context)) + 1 > 256:
            fail()
    if len({encoded(c) for c in contexts}) != len(contexts):
        fail()


def checksums(raw_records):
    if not isinstance(raw_records, list) or len(raw_records) != 3 or any(not isinstance(v, str) for v in raw_records):
        fail()
    if sum(len(v.encode()) for v in raw_records) > 8192:
        fail()
    return [hashlib.sha256(v.encode()).hexdigest() for v in raw_records]


def validate_snapshot(snapshot):
    fields = {'process_index','sequence','raw_record_sha256_by_actor','raw_json_by_actor'}
    if not isinstance(snapshot, dict) or set(snapshot) != fields or len(encoded(snapshot)) + 1 > 11264:
        fail()
    scalar(snapshot['process_index'], 'proc')
    scalar(snapshot['sequence'], 'u32')
    if snapshot['raw_record_sha256_by_actor'] != checksums(snapshot['raw_json_by_actor']):
        fail()
    total_items = 0
    for actor, raw in enumerate(snapshot['raw_json_by_actor']):
        record = decode(raw)
        if not isinstance(record, dict) or set(record) != {'schema','id','profile','revision','clean','saved'}:
            fail()
        if (record['schema'] != 3 or type(record['schema']) is not int or type(record['id']) is not int
                or record['id'] != actor or record['profile'] != 'west-qeynos-v1' or type(record['clean']) is not bool):
            fail()
        if type(record['revision']) is not int or not 0 <= record['revision'] < 2**64:
            fail()
        saved = record['saved']
        fields = {'desired','zone','previous_zone','owner_epoch','transfer','point','hp','max_hp','rest_ms','level','experience','reputation','inventory','completed','yielded','failed'}
        if not isinstance(saved, dict) or set(saved) != fields or not isinstance(saved['inventory'], list):
            fail()
        inventory = saved['inventory']
        if actor != 0 and inventory:
            fail()
        total_items += len(inventory)
        fields = {'parent','kind','slot','id','charges','color','custom','attuned','ornament_icon','ornament_file','ornament_model','serial','recast','scaling','scaling_exp','evolve_id','evolve_character','evolve_item','evolve_final','evolve_amount','evolve_progress','evolve_active','evolve_equipped'}
        for item in inventory:
            if not isinstance(item, dict) or set(item) != fields:
                fail()
            if not isinstance(item['custom'], str) or len(item['custom']) > 64 or not re.fullmatch(r'[A-Za-z0-9_^:.-]*', item['custom']):
                fail()
            for key in ('attuned','scaling','evolve_active','evolve_equipped'):
                if type(item[key]) is not bool:
                    fail()
            if item['scaling'] or any(item[k] != 0 for k in ('scaling_exp','evolve_id','evolve_character','evolve_item','evolve_final','evolve_amount','evolve_progress')) or item['evolve_active'] or item['evolve_equipped']:
                fail()
    if total_items > 8:
        fail()


def public_predicate(row):
    """Finite sealed public rows only; values become SQL literals, never identifiers."""
    parts = []
    for column, value in row.items():
        if not re.fullmatch('[A-Za-z_][A-Za-z_0-9]*', column):
            fail()
        literal = 'NULL' if value is None else "CONVERT(0x" + str(value).encode('latin1').hex() + " USING latin1)" if value != '' else "''"
        parts.append('`' + column + '` <=> ' + literal)
    return ' AND '.join(parts)


def derive_fixture(runtime, directory):
    """Verify every selected complete public row before private fixture derivation."""
    directory = Path(directory)
    world = decode((directory/'public-world-rows.json').read_bytes())
    tables = dict(world, items=decode((directory/'public-items.json').read_bytes()))
    predicates = []
    for table, rows in tables.items():
        if not re.fullmatch('[a-z_]+', table):
            fail()
        for entry in rows:
            if hashlib.sha256(entry['raw_sql_row'].encode()).hexdigest() != entry['raw_sql_row_sha256']:
                fail()
            predicates.append('SELECT COUNT(*) FROM `' + table + '` WHERE ' + public_predicate(entry['row']))
    result = runtime.query('integration-public-rows', ';\n'.join(predicates) + ';').splitlines()
    if result != ['1'] * len(predicates):
        fail()
    rules = decode((directory/'xp-rule-selection.json').read_bytes())['selected_values']
    changes = []
    for name, value in rules.items():
        # Exact verified public tar permits only these reviewed rule literals.
        if not re.fullmatch('[A-Za-z]+:[A-Za-z]+', name) or not re.fullmatch('[0-9]+|true|false', value):
            fail()
        changes.append("UPDATE rule_values SET rule_value='"+value+"' WHERE ruleset_id=1 AND rule_name='"+name+"'")
    changes += [
        "DELETE FROM spawn2 WHERE zone='qeynos2' AND NOT (version=0 AND id IN (10863,10865))",
        "DELETE FROM spawn2 WHERE zone='qeytoqrg' AND NOT (version=0 AND id=4347)",
        "DELETE FROM spawn2 WHERE zone='poknowledge'",
        "UPDATE zone SET idle_when_empty=0 WHERE version=0 AND zoneidnumber IN (2,4)",
        "UPDATE rule_values SET rule_value='false' WHERE ruleset_id=1 AND rule_name IN ('Zone:UseZoneController','Bots:Enabled','Analytics:CrashReporting','Zone:StateSavingOnShutdown')",
        "UPDATE variables SET value='default' WHERE varname='RuleSet'",
        "UPDATE logsys_categories SET log_to_file=0,log_to_gmsay=0,log_to_discord=0,discord_webhook_id=0",
        "UPDATE logsys_categories SET log_to_console=0 WHERE log_category_description='MySQL Query'",
        "UPDATE npc_types SET npc_faction_id=104 WHERE id=2014",
        "UPDATE npc_types SET npc_faction_id=1425 WHERE id=2021",
    ]
    changes.append("UPDATE rule_values SET rule_value='true' WHERE ruleset_id=1 AND rule_name='Zone:UseZoneController'")
    runtime.query('integration-private-derive', ';\n'.join(changes) + ';')
    checks = ["SELECT id FROM spawn2 WHERE zone='qeynos2' ORDER BY id", "SELECT id FROM spawn2 WHERE zone='qeytoqrg' ORDER BY id",
              "SELECT COUNT(*) FROM zone WHERE version=0 AND zoneidnumber IN (2,4) AND idle_when_empty=0",
              "SELECT COUNT(*) FROM discord_webhooks WHERE COALESCE(webhook_url,'')<>''"]
    if runtime.query('integration-private-check', ';'.join(checks)+';').splitlines() != ['10863','10865','4347','2','0']:
        fail()


def seed_records(earned=None, inventory=False):
    """Offline-only fresh fixture seed. Earned actor bytes retain A's actual XP/level."""
    records = []
    for actor in range(3):
        saved = dict(desired='paused', zone=2, previous_zone=0, owner_epoch=0, transfer=None,
                     point=dict(x=-917.0 + (0,3,-3)[actor], y=1224.0, z=3.75), hp=100, max_hp=100,
                     rest_ms=10000, level=1, experience=0, reputation={}, inventory=[], completed=0, yielded=0, failed=0)
        records.append(dict(schema=3, id=actor, profile='west-qeynos-v1', revision=1, clean=True, saved=saved))
    if earned is not None:
        source = decode(earned)
        if source['id'] != 0 or source['clean'] is not True or source['saved']['level'] != 2 or source['saved']['experience'] < 1000:
            fail()
        records[0] = source
        records[0]['saved']['desired'] = 'paused'
    elif inventory:
        fail()
    if inventory:
        items = []
        layout = [(-1,0,13,1074),(0,2,0,41085),(-1,0,2,2947),(-1,0,23,17005),
                  (3,1,0,1115),(3,1,1,11602),(-1,3,0,1001),(-1,3,1,7007)]
        for parent, kind, slot, item_id in layout:
            items.append(dict(parent=parent, kind=kind, slot=slot, id=item_id, charges=3 if item_id==1115 else -1,
                              color=4279905084 if item_id==11602 else 0, custom='cdau^native-fixture-v1^' if item_id==11602 else '',
                              attuned=item_id==11602, ornament_icon=0, ornament_file=0, ornament_model=0, serial=0,
                              recast=0, scaling=False, scaling_exp=0, evolve_id=0, evolve_character=0, evolve_item=0,
                              evolve_final=0, evolve_amount=0, evolve_progress=0.0, evolve_active=False, evolve_equipped=False))
        records[0]['saved']['inventory'] = items
    return [encoded(record) for record in records]

INTERFACE_SHA = 'c604e154baf96908e2d6707714875924a198793438ec219565f05dc4e6cf6eb0'
PROCESS_FIELDS = {'index','native_pid','process_start_identity','role_world_source_destination','zone','binary_sha256','first_seq','last_seq','exit_kind','complete_prefix'}
SUMMARY_FIELDS = {'outcome','failure_cause','case_outcomes','check_results','event_counts','process_count','context_count','snapshot_count','credited_kills','attack_decisions','transfer_intents','boot_attempts','zone_starts','commands','complete_prefixes'}


def bounded_int(value, lo, hi):
    if type(value) is not int or not lo <= value <= hi:
        fail()


def validate_process(process):
    if not isinstance(process, dict) or set(process) != PROCESS_FIELDS or len(encoded(process))+1 > 512:
        fail()
    typed([process['index'],process['native_pid'],process['process_start_identity'],process['binary_sha256']], ['proc','u32','u64','sha'])
    if process['native_pid'] == 0 or process['role_world_source_destination'] not in ('world','source','destination'):
        fail()
    if type(process['zone']) is not int or process['zone'] != {'world':0,'source':2,'destination':4}[process['role_world_source_destination']]:
        fail()
    bounded_int(process['first_seq'],0,1)
    bounded_int(process['last_seq'],0,4096)
    bounded_int(process['exit_kind'],0,4)
    scalar(process['complete_prefix'],'bool')
    if bool(process['first_seq']) != bool(process['last_seq']):
        fail()
    if process['zone']==0 and (process['first_seq'] or process['last_seq']):
        fail()


def validate_admission(value, contexts):
    if not isinstance(value, dict) or set(value) != {'actors','connection','native_route_flags','geometry'} or not isinstance(value['actors'],list) or len(value['actors']) != 3:
        fail()
    for actor in value['actors']:
        typed(actor,['ctx','sha','u8','u8','u64','u8'])
        if actor[0] >= len(contexts) or actor[2] > 8 or actor[3] > 127 or actor[5] > 127:
            fail()
    bounded_int(value['native_route_flags'],0,127)
    typed(value['geometry'], ['bool', *(['ctx']*3), *(['f64']*9), 'flags'])
    if any(ref>=len(contexts) for ref in value['geometry'][1:4]): fail()
    typed(value['connection'], ['bool', *(['u32']*3), *(['f64']*6)])
    if not value['connection'][0] and value['connection'][1:] != [0,0,0,*(['0']*6)]:
        fail()


def validate_summary(summary):
    if not isinstance(summary, dict) or set(summary) != SUMMARY_FIELDS or len(encoded(summary))>4096:
        fail()
    bounded_int(summary['outcome'],0,2)
    bounded_int(summary['failure_cause'],0,12)
    for name, count, high in [('case_outcomes',3,2),('check_results',12,3),('event_counts',8,4096)]:
        if not isinstance(summary[name],list) or len(summary[name]) != count:
            fail()
        for item in summary[name]: bounded_int(item,0,high)
    for name, cap in dict(process_count=24,context_count=128,snapshot_count=12,credited_kills=4,attack_decisions=256,
                          transfer_intents=6,boot_attempts=12,zone_starts=16,commands=24,complete_prefixes=24).items():
        bounded_int(summary[name],0,cap)
    if any(n>cap for n,cap in zip(summary['event_counts'], KINDS.values())):
        fail()
    if summary['outcome']==1 and (summary['case_outcomes'] != [1]*3 or summary['check_results'] != [1]*12 or summary['failure_cause']):
        fail()


def validate_record_values(record):
    saved = record['saved']
    if saved['desired'] not in ('paused','enabled','dead'):
        fail()
    for name in ('zone','previous_zone'):
        scalar(saved[name], 'u32')
    for name in ('owner_epoch','rest_ms','experience','completed','yielded','failed'):
        if type(saved[name]) is not int or not 0 <= saved[name] < 2**64:
            fail()
    for name in ('hp','max_hp'):
        if type(saved[name]) is not int or not -2**63 <= saved[name] < 2**63:
            fail()
    bounded_int(saved['level'],1,127)
    def point(value):
        if not isinstance(value,dict) or set(value) != {'x','y','z'}:
            fail()
        for number in value.values():
            if type(number) not in (int,float) or not math.isfinite(number) or len(str(number))>32:
                fail()
    point(saved['point'])
    if saved['transfer'] is not None:
        route=saved['transfer']
        if not isinstance(route,dict) or set(route) != {'id','zone','exit','arrival','distance'}:
            fail()
        scalar(route['id'],'u32'); scalar(route['zone'],'u32')
        point(route['exit']); point(route['arrival'])
        if type(route['distance']) not in (int,float) or not math.isfinite(route['distance']) or route['distance']<0:
            fail()
    reputation=saved['reputation']
    if not isinstance(reputation,dict) or len(reputation)>20:
        fail()
    for key,value in reputation.items():
        if not re.fullmatch('[1-9][0-9]{0,9}',key) or int(key)>2**31-1:
            fail()
        bounded_int(value,-32768,32767)
    slots=set();serials=set();depths=[];cursor=0
    for index,item in enumerate(saved['inventory']):
        slot=(item['parent'],item['kind'],item['slot'])
        if slot in slots or (item['serial']!=0 and item['serial'] in serials): fail()
        slots.add(slot);serials.add(item['serial'])
        if item['kind'] in (0,3):
            if item['parent']!=-1 or item['slot']<0: fail()
            depth=0
        else:
            if not 0<=item['parent']<index or not 0<=item['slot']<(10 if item['kind']==1 else 6): fail()
            depth=depths[item['parent']]+1
        if depth>3: fail()
        depths.append(depth)
        if item['kind']==3:
            if item['slot']!=cursor: fail()
            cursor+=1
        for key in ('parent','serial'): scalar(item[key],'i32')
        for key in ('slot','charges'): bounded_int(item[key],-32768,32767)
        bounded_int(item['kind'],0,3)
        for key in ('id','color','ornament_icon','ornament_file','ornament_model','recast','scaling_exp','evolve_character','evolve_item','evolve_final'):
            scalar(item[key],'u32')
        for key in ('evolve_id','evolve_amount'):
            if type(item[key]) is not int or not 0<=item[key]<2**64:
                fail()
        if type(item['evolve_progress']) not in (int,float) or not math.isfinite(item['evolve_progress']):
            fail()
        if item['id'] not in (1074,41085,2947,17005,1115,11602,1001,7007) or item['custom'] not in ('','cdau^native-fixture-v1^'):
            fail()


def validate_artifact(raw):
    """Validate the fixed complete public schema before any raw export or PASS."""
    if not isinstance(raw,bytes) or len(raw)>CAP:
        fail()
    value=decode(raw)
    fields={'schema','contract_sha256','fixture_sha256','processes','contexts','events','snapshots','manifest','summary','complete','overflow','gaps'}
    if not isinstance(value,dict) or set(value)!=fields or value['schema']!=SELECTION or value['contract_sha256']!=CONTRACT_SHA or value['fixture_sha256']!=FIXTURE_SHA:
        fail()
    for key in ('complete','overflow'): scalar(value[key],'bool')
    bounded_int(value['gaps'],0,4096)
    processes=value['processes']
    if not isinstance(processes,list) or not 1<=len(processes)<=24:
        fail()
    for index,process in enumerate(processes):
        validate_process(process)
        if process['index']!=index: fail()
    contexts=value['contexts'];validate_contexts(contexts,len(processes))
    for context in contexts: bounded_int(context[13],0,3)
    events=Events(contexts)
    if not isinstance(value['events'],list) or len(value['events'])>3184: fail()
    for event in value['events']:
        events.accept(event)
        if event[0]>=len(processes): fail()
        payload=event[6]; refs=[]
        if event[3] in (6,10): refs=[payload[0]]
        elif event[3]==11: refs=[payload[2]]
        elif event[3]==8:
            if payload[0]==0: refs=payload[2:4]
            elif payload[0]==1: refs=[payload[2]]
            elif payload[2]>=len(processes) or int(payload[3])>processes[payload[2]]['last_seq']: fail()
        if any(ref>=len(contexts) for ref in refs): fail()
    for process in processes:
        if events.last.get(process['index'],0)!=process['last_seq']: fail()
    if not isinstance(value['snapshots'],list) or len(value['snapshots'])>12: fail()
    sequences=set()
    for snapshot in value['snapshots']:
        validate_snapshot(snapshot)
        if snapshot['process_index']>=len(processes) or not 1<=snapshot['sequence']<=12 or snapshot['sequence'] in sequences: fail()
        sequences.add(snapshot['sequence'])
        for raw_record in snapshot['raw_json_by_actor']: validate_record_values(decode(raw_record))
    manifest=value['manifest']
    fields={'server_commit','server_tree','stack_commit','fixture_selection_sha256','public_fixture_sha256','event_contract_sha256','interface_sha256','run','admission_by_case'}
    if not isinstance(manifest,dict) or set(manifest)!=fields or len(encoded(manifest))>16384: fail()
    for key in ('server_commit','server_tree','stack_commit'): hex_string(manifest[key],40)
    for key in ('fixture_selection_sha256','public_fixture_sha256','event_contract_sha256','interface_sha256'): hex_string(manifest[key],64)
    if (manifest['fixture_selection_sha256']!='cec8c281604549b7c4d54259ff7760ffe37dae26dc09e5fa4462ef2823c86871'
            or manifest['public_fixture_sha256']!=FIXTURE_SHA or manifest['event_contract_sha256']!=CONTRACT_SHA
            or manifest['interface_sha256']!=INTERFACE_SHA): fail()
    hex_string(manifest['run'],32)
    if not isinstance(manifest['admission_by_case'],list) or len(manifest['admission_by_case'])!=3: fail()
    for case in manifest['admission_by_case']:
        if not isinstance(case,list) or len(case)!=2: fail()
        for admission in case: validate_admission(admission,contexts)
    summary=value['summary'];validate_summary(summary)
    derived=counters(value['events'])
    if any(summary[key]!=expected for key,expected in derived.items()): fail()
    if sum(e[3]==11 and e[6][0]==0 for e in value['events'])>48: fail()
    if sum(e[3]==11 and e[6][0] in (6,7) for e in value['events'])>96: fail()
    if (summary['event_counts']!=list(events.counts.values()) or summary['process_count']!=len(processes)
            or summary['context_count']!=len(contexts) or summary['snapshot_count']!=len(value['snapshots'])): fail()
    if summary['outcome']==1 and not all(qualify(value)): fail()
    if summary['outcome']==1 and (not value['complete'] or value['overflow'] or value['gaps'] or any(not p['complete_prefix'] for p in processes)): fail()
    return value


class Collection:
    """Merge cumulative process shards with a bijective, deterministic context map."""
    def __init__(self, run):
        self.run=hex_string(run,32)
        self.shards={}
        self.failed=False
        self.overflow=False
        self.gaps=0

    def accept(self,shard,expected_process):
        if isinstance(shard,dict):
            if shard.get('overflow') is True: self.overflow=True
            gap=shard.get('gaps')
            if type(gap) is int and 0<gap<=4096: self.gaps=max(self.gaps,gap)
        try: return self._accept(shard,expected_process)
        except BaseException:
            self.failed=True
            raise

    def _accept(self, shard, expected_process):
        fields={'schema','contract_sha256','run','case','process','contexts','events','snapshots','admission','complete','overflow','gaps'}
        if not isinstance(shard,dict) or set(shard)!=fields or len(encoded(shard))>CAP:
            fail()
        if shard['schema']!=SELECTION or shard['contract_sha256']!=CONTRACT_SHA or shard['run']!=self.run:
            fail()
        bounded_int(shard['case'],0,2)
        process=shard['process'];validate_process(process)
        for key in ('index','native_pid','process_start_identity','role_world_source_destination','zone','binary_sha256'):
            if process[key]!=expected_process[key]: fail()
        if type(shard['complete']) is not bool or shard['complete'] is not True or shard['overflow'] is not False or type(shard['gaps']) is not int or shard['gaps']!=0:
            fail()
        if not isinstance(shard['contexts'],list): fail()
        contexts=[]
        for index,pair in enumerate(shard['contexts']):
            if not isinstance(pair,list) or len(pair)!=2 or type(pair[0]) is not int or pair[0]!=index:
                fail()
            contexts.append(pair[1])
        validate_contexts(contexts,24)
        if any(c[0]!=process['index'] for c in contexts): fail()
        events=Events(contexts)
        if not isinstance(shard['events'],list) or len(shard['events'])>3184: fail()
        for event in shard['events']:
            if event[0]!=process['index']: fail()
            events.accept(event)
        if events.last.get(process['index'],0)!=process['last_seq']: fail()
        if not isinstance(shard['snapshots'],list) or len(shard['snapshots'])>12: fail()
        for snapshot in shard['snapshots']:
            validate_snapshot(snapshot)
            if snapshot['process_index']!=process['index']: fail()
            for raw in snapshot['raw_json_by_actor']: validate_record_values(decode(raw))
        validate_admission(shard['admission'],contexts)
        old=self.shards.get(process['index'])
        if old:
            for key in ('contexts','events','snapshots'):
                if shard[key][:len(old[key])]!=old[key]: fail()
            if shard['case']!=old['case']: fail()
        proposed=dict(self.shards);proposed[process['index']]=shard
        if sum(len(s['contexts']) for s in proposed.values())>128 or sum(len(s['snapshots']) for s in proposed.values())>12:
            fail()
        totals=dict.fromkeys(KINDS,0)
        for s in proposed.values():
            for event in s['events']: totals[event[3]]+=1
        if any(totals[k]>KINDS[k] for k in KINDS): fail()
        self.shards=proposed

    def merged(self):
        import copy
        mapping={}
        contexts=[]
        for proc,shard in sorted(self.shards.items()):
            for local,context in shard['contexts']:
                mapping[proc,local]=len(contexts)
                contexts.append(copy.deepcopy(context))
        events=[];snapshots=[];admissions={}
        for proc,shard in sorted(self.shards.items()):
            def ref(local):
                if (proc,local) not in mapping: fail()
                return mapping[proc,local]
            for event in copy.deepcopy(shard['events']):
                event[4]=ref(event[4]);kind=event[3];payload=event[6]
                if kind in (6,10): payload[0]=ref(payload[0])
                elif kind==11: payload[2]=ref(payload[2])
                elif kind==8:
                    if payload[0]==0: payload[2:4]=[ref(payload[2]),ref(payload[3])]
                    elif payload[0]==1: payload[2]=ref(payload[2])
                events.append(event)
            admission=copy.deepcopy(shard['admission'])
            for actor in admission['actors']: actor[0]=ref(actor[0])
            admission['geometry'][1:4]=[ref(r) for r in admission['geometry'][1:4]]
            admissions[proc]=admission
            snapshots.extend(copy.deepcopy(shard['snapshots']))
        events.sort(key=lambda e:(e[2],e[0],e[1]))
        snapshots.sort(key=lambda s:s['sequence'])
        if len({s['sequence'] for s in snapshots})!=len(snapshots): fail()
        return contexts,events,snapshots,admissions


def read_public(path, limit, *, owner=None):
    """Read one owned bounded regular inode without following links or blocking."""
    import os
    import stat
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=(os.geteuid() if owner is None else owner) or info.st_size>limit:
            fail()
        raw=stream.read(limit+1)
        if len(raw)!=info.st_size or len(raw)>limit: fail()
        return raw


def atomic_public(path, raw, cap):
    import os
    if not isinstance(raw,bytes) or len(raw)>cap: fail()
    temporary=path.with_name(path.name+'.tmp')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class Budget:
    def __init__(self):
        self.counts=dict(commands=0,flush=0,snapshots=0,zone_starts=0,processes=0)

    def take(self,name):
        limits=dict(commands=24,flush=24,snapshots=12,zone_starts=16,processes=24)
        self.counts[name]+=1
        if self.counts[name]>limits[name]: fail()
        return self.counts[name]


class Mailbox:
    """One read-only request in flight. Timeouts stop the run without a retry."""
    def __init__(self,population,process,run,budget,collection,guard):
        self.population=Path(population)
        self.process=process
        self.run=run
        self.budget=budget
        self.collection=collection
        self.guard=guard
        self.session=None
        self.request=0
        self.inflight=False
        self.failed=False
        self.directory=self.population/'integration'/('p'+str(process['index']))

    def status(self):
        name='status.json' if self.process['zone']==2 else 'status-zone-4.json'
        status=decode(read_public(self.population/name,65536))
        session=status.get('session')
        if not isinstance(session,str) or not re.fullmatch('[A-Za-z0-9-]{1,48}',session): fail()
        if self.session is not None and self.session!=session: fail()
        return status

    def startup(self):
        import time
        end=time.monotonic()+10
        while time.monotonic()<end:
            self.guard()
            try:
                status=self.status()
                self.session=status['session']
                ack=decode(read_public(self.directory/'ack.json',1024))
                self.validate_ack(ack,0,0,0)
                if ack['result']!=0 or ack['last_seq']!=0 or ack['shard_sha256']!='0'*64 or ack['snapshot_sequence']!=0: fail()
                return status
            except FileNotFoundError:
                time.sleep(.05)
        raise ValueError('integration-startup-timeout')

    def validate_ack(self,ack,request,op,barrier):
        expected=dict(schema=1,run=self.run,process_index=self.process['index'],session=self.session,request=str(request),op=op,barrier=barrier)
        if (not isinstance(ack,dict) or set(ack)!=set(expected)|{'result','last_seq','shard_sha256','snapshot_sequence'}
                or any(ack.get(k)!=v or type(ack.get(k)) is not type(v) for k,v in expected.items())): fail()
        bounded_int(ack['result'],0,9);bounded_int(ack['last_seq'],0,4096);hex_string(ack['shard_sha256'],64)
        bounded_int(ack['snapshot_sequence'],0,12)

    def observe(self,snapshot=False):
        if self.inflight or self.failed: fail()
        self.inflight=True
        try: return self._observe(snapshot)
        except BaseException:
            self.failed=True
            raise
        finally: self.inflight=False

    def _observe(self,snapshot=False):
        import time
        if self.session is None: fail()
        barrier=self.budget.take('snapshots') if snapshot else 0
        if not snapshot: self.budget.take('flush')
        self.request+=1
        request=dict(schema=1,run=self.run,process_index=self.process['index'],session=self.session,request=str(self.request),op=int(snapshot),barrier=barrier)
        atomic_public(self.directory/'request',encoded(request),256)
        end=time.monotonic()+10
        while time.monotonic()<end:
            self.guard()
            try:
                ack=decode(read_public(self.directory/'ack.json',1024))
                if ack.get('request')==str(self.request):
                    self.validate_ack(ack,self.request,int(snapshot),barrier)
                    if ack['result']!=(2 if snapshot else 1) or ack['snapshot_sequence']!=(barrier if snapshot else 0):
                        raise ValueError('integration-observation-refused')
                    raw=read_public(self.directory/(SELECTION+'.json'),CAP)
                    if hashlib.sha256(raw).hexdigest()!=ack['shard_sha256']: fail()
                    shard=decode(raw)
                    if shard.get('process',{}).get('last_seq')!=ack['last_seq']: fail()
                    self.collection.accept(shard,self.process)
                    return shard
            except FileNotFoundError:
                pass
            time.sleep(.05)
        raise ValueError('integration-observation-timeout')

    def terminal(self,native):
        from actor_runtime import group_live
        if (not native.closed or native.process.returncode!=0 or group_live(native.process.pid)
                or native.descriptor['exit_kind']!=1):
            fail()
        ack=decode(read_public(self.directory/'ack.json',1024))
        self.validate_ack(ack,0,0,65535)
        if ack['result']!=1 or ack['snapshot_sequence']!=0: fail()
        raw=read_public(self.directory/(SELECTION+'.json'),CAP)
        if hashlib.sha256(raw).hexdigest()!=ack['shard_sha256']: fail()
        shard=decode(raw)
        if shard.get('process',{}).get('last_seq')!=ack['last_seq']: fail()
        self.collection.accept(shard,self.process)
        return shard

    def command(self,verb,actor=None,*,expect_recovery=False):
        """Use only the existing population command authority, with native session ACK."""
        import time
        if verb not in ('start','stop','drain') or actor not in (None,'hunter-1','hunter-2','hunter-3','all') or (verb=='drain' and actor is not None) or (verb!='drain' and actor is None): fail()
        number=self.budget.take('commands')
        text=verb+' '+self.session+' '+str(number)+((' '+actor) if actor else '')+'\n'
        name='command' if self.process['zone']==2 else 'command-zone-4'
        atomic_public(self.population/name,text.encode(),128)
        end=time.monotonic()+10
        while time.monotonic()<end:
            self.guard();status=self.status()
            if status.get('last_request')==number:
                if expect_recovery:
                    if status.get('command_result')!='recovery_required' or status.get('phase')!='recovery_required': fail()
                elif status.get('command_result') not in ('start_accepted','stop_queued','drain_queued'): fail()
                return status
            time.sleep(.05)
        raise ValueError('integration-command-timeout')


def launch_spec(role, binary_dir, server, population, run, case, index, origin_us, *, recovery=False):
    """Exact agreed native argv/environment, with no caller-selected commands."""
    import os
    if role not in ('world','source','destination') or case not in ('A','B','C'):
        fail()
    bounded_int(index,0,23);scalar(str(origin_us),'u64');hex_string(run,32)
    if recovery and (role!='destination' or case!='C'): fail()
    executable=Path(binary_dir)/('world' if role=='world' else 'zone')
    args=[str(executable)] + ([] if role=='world' else ['qeynos2' if role=='source' else 'qeytoqrg' if recovery else 'dynamic_cdau4','cdau','0'])
    env={k:v for k,v in os.environ.items() if not k.startswith(('EQEMU_','ASAN_','UBSAN_','LSAN_','LD_'))}
    if role!='world':
        env.update(EQEMU_STAGING_ACTOR_DEMO='1',EQEMU_STAGING_ACTOR_SCENARIO='population-hunt-v1',
                   EQEMU_STAGING_ACTOR_POPULATION_DIR=str(population),EQEMU_CDAU_INTEGRATION=SELECTION,
                   EQEMU_CDAU_RUN=run,EQEMU_CDAU_CASE=case,EQEMU_CDAU_PROCESS_INDEX=str(index),
                   EQEMU_CDAU_ORIGIN_US=str(origin_us))
    return args,env


class Native:
    """Own one exact native process group, including post-Popen initialization failure."""
    def __init__(self,role,binary_dir,server,population,run,case,index,origin_us,on_started=None,*,recovery=False):
        import os
        import subprocess
        from actor_runtime import group_live
        self.group_live=group_live
        self.process=None
        self.log=None
        self.closed=False
        self.cleanup_complete=False
        self.index=index
        self.descriptor=None
        args,env=launch_spec(role,binary_dir,server,population,run,case,index,origin_us,recovery=recovery)
        self.log=Path(server)/('integration-'+str(index)+'.log')
        try:
            with self.log.open('xb') as stream:
                self.process=subprocess.Popen(args,cwd=server,env=env,stdin=subprocess.DEVNULL,stdout=stream,
                                              stderr=subprocess.STDOUT,start_new_session=True,close_fds=True)
            if on_started is not None: on_started(self)
            fields=Path('/proc',str(self.process.pid),'stat').read_text().rsplit(')',1)[1].split()
            start=fields[19]
            with Path('/proc',str(self.process.pid),'exe').open('rb') as image:
                digest=hashlib.file_digest(image,'sha256').hexdigest()
            with Path(args[0]).open('rb') as image:
                if hashlib.file_digest(image,'sha256').hexdigest()!=digest: fail()
            self.descriptor=dict(index=index,native_pid=self.process.pid,process_start_identity=start,
                                 role_world_source_destination=role,zone={'world':0,'source':2,'destination':4}[role],
                                 binary_sha256=digest,first_seq=0,last_seq=0,exit_kind=0,complete_prefix=True)
            validate_process(self.descriptor)
            if self.process.poll() is not None: fail()
        except BaseException:
            if self.process is not None: self.stop()
            raise

    def stop(self,expected_fault=False):
        import os
        import signal
        import subprocess
        group_live=self.group_live
        if self.closed: return self.stop_acceptable
        clean=True
        try:
            was_live=self.process.poll() is None
            if was_live:
                try: os.killpg(self.process.pid,signal.SIGKILL if expected_fault else signal.SIGTERM)
                except ProcessLookupError: pass
            try: code=self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid,signal.SIGKILL)
                code=self.process.wait(timeout=5);clean=False
            if group_live(self.process.pid):
                os.killpg(self.process.pid,signal.SIGKILL);clean=False
            if self.descriptor is not None:
                self.descriptor['exit_kind']=2 if expected_fault and was_live and code==-signal.SIGKILL else 1 if was_live and code==0 and clean else 3
            self.cleanup_complete=self.process.poll() is not None and not group_live(self.process.pid)
            self.stop_acceptable=clean and self.cleanup_complete and ((expected_fault and was_live and code==-signal.SIGKILL) or (not expected_fault and was_live and code==0))
            self.closed=self.cleanup_complete
            return self.stop_acceptable
        except BaseException:
            self.cleanup_complete=False
            raise

# Existing quest bindings only. Geometry and awards are accepted from native
# observation, never these timers or fixture phase markers.
ZONE_QUEST = r'''use strict;
our ($timer,$entity_list);
my $stage=0;
sub EVENT_SPAWN { if (($ENV{EQEMU_CDAU_CASE}//'') eq 'A') { quest::settimer('cdau',1); } }
sub EVENT_TIMER {
 return unless $timer eq 'cdau';
 my $actor=$entity_list->GetMob('Hunter_1');
 return unless $actor && $actor->GetLevel()==2 && !$actor->IsMoving();
 my $hostile=$entity_list->GetNPCByNPCTypeID(2014);
 if ($stage==0) {
  my ($x,$y)=($actor->GetX(),$actor->GetY());
  my $hz=$actor->FindGroundZ($x+24,$y);
  my $fz=$actor->FindGroundZ($x+8,$y);
  return unless $hz > -100000 && $fz > -100000;
  quest::spawn2(2014,0,0,$x+24,$y,$hz,0);
  quest::spawn2(2021,0,0,$x+8,$y,$fz,0);
  $stage=1;
 } elsif ($stage==1 && !$hostile) {
  my ($x,$y)=($actor->GetX(),$actor->GetY());
  my $z=$actor->FindGroundZ($x+24,$y);
  return unless $z > -100000;
  open(my $phase,'>','cdau-live-flip') or return;
  print $phase '1'; close($phase);
  quest::spawn2(2014,0,0,$x+24,$y,$z,0);
  $stage=2;
 }
}
'''
HOSTILE_QUEST = r'''use strict;
our ($npc,$timer);
my $scheduled=0;
sub EVENT_DAMAGE_TAKEN {
 return if $scheduled || !-f 'cdau-live-flip';
 $scheduled=1; quest::settimer('cdau-flip',1);
}
sub EVENT_TIMER {
 return unless $timer eq 'cdau-flip';
 quest::stoptimer('cdau-flip');
 $npc->WipeHateList(); $npc->SetNPCFactionID(1425);
 open(my $done,'>','cdau-flipped') or return; print $done '1'; close($done);
}
'''


def install_quests(server):
    directory=Path(server)/'quests/qeynos2'
    directory.mkdir(parents=True,exist_ok=True)
    for name,script in (('zone_controller.pl',ZONE_QUEST),('2014.pl',HOSTILE_QUEST)):
        # Overlay only this selected private quest fixture, never public media.
        path=directory/name
        path.write_text(script)
        path.chmod(0o600)
    destination=Path(server)/'quests/qeytoqrg'
    destination.mkdir(parents=True,exist_ok=True)
    (destination/'zone_controller.pl').write_text('sub EVENT_SPAWN {}\n')
    (destination/'zone_controller.pl').chmod(0o600)


def validate_result(value, *, database_required=True):
    fields={'scope','exit_code','binaries','fixture_sha256','process_outcomes','native_cleanup','database_cleanup','summary'}
    if not isinstance(value,dict) or set(value)!=fields or len(encoded(value))>8192 or value['scope']!=SELECTION or value['fixture_sha256']!=FIXTURE_SHA:
        fail()
    bounded_int(value['exit_code'],0,2)
    for key in ('native_cleanup','database_cleanup'):
        if type(value[key]) is not bool and value[key] not in ('not-run','unknown'): fail()
    if not isinstance(value['binaries'],dict) or set(value['binaries'])!={'world','zone','shared_memory'}: fail()
    for digest in value['binaries'].values(): hex_string(digest,64)
    if not isinstance(value['process_outcomes'],list) or len(value['process_outcomes'])>24: fail()
    for outcome in value['process_outcomes']:
        if not isinstance(outcome,list) or len(outcome)!=3: fail()
        bounded_int(outcome[0],0,23);bounded_int(outcome[1],0,4);bounded_int(outcome[2],-255,255)
    validate_summary(value['summary'])
    if value['exit_code']==0 and (value['native_cleanup'] is not True or (database_required and value['database_cleanup'] is not True) or value['summary']['outcome']!=1): fail()
    return value


def initial_summary():
    return dict(outcome=0,failure_cause=0,case_outcomes=[0]*3,check_results=[0]*12,event_counts=[0]*8,
                process_count=0,context_count=0,snapshot_count=0,credited_kills=0,attack_decisions=0,
                transfer_intents=0,boot_attempts=0,zone_starts=0,commands=0,complete_prefixes=0)


def counters(events):
    counts=[sum(e[3]==kind for e in events) for kind in KINDS]
    return dict(event_counts=counts,credited_kills=sum(e[3]==8 and e[6][0]==2 for e in events),
                attack_decisions=counts[1],transfer_intents=sum(e[3]==5 and e[6][0]==6 for e in events),
                boot_attempts=sum(e[3]==12 and e[6][0]==1 and e[6][3]==100 for e in events))


FAILURE_PHASES = ('runtime-directory','mount-runtime','runtime-inputs','runtime-packages',
                  'database-initialize','database-import','server-configure','fixture-quests',
                  'fixture-config','fixture-plan','fixture-ownership','shared-memory','shared-files',
                  'controller','controller-result','final-inputs','binary-identity',
                  'database-cleanup','artifact-read','artifact-validate')


def failure_text(phase, cause):
    """Only fixed source vocabulary enters the existing bounded guest error string."""
    if phase not in FAILURE_PHASES: fail()
    kind = 'nonpass' if cause is None else 'other'
    for error_type, name in ((TimeoutError,'timeout'),(OSError,'os'),(ValueError,'value'),
                             (TypeError,'type'),(RuntimeError,'runtime')):
        if isinstance(cause,error_type):
            kind=name
            break
    return 'integration-nonpass:'+phase+':'+kind


def run(build, identity):
    """Enter only the disposable guest's existing full build/fixture lifecycle."""
    import os
    import pwd
    import signal
    import time
    from actor_runtime import Runtime,ROOT,MEDIA
    from integration_artifacts import frames,wire
    if (os.geteuid()!=0 or not Path('/opt/eqemu-worker-build-guest').is_file()
            or identity.get('integration')!=SELECTION or build.DEADLINE-time.monotonic()<1800):
        raise RuntimeError('integration-guest-or-budget')
    start=time.monotonic()
    ROOT.mkdir(mode=0o755)
    additive=ROOT/'integration-input'
    verify_fixture('/media/eqemu-input/integration-fixture.tar',additive)
    fixture=decode(Path('/opt/runtime-fixture.json').read_bytes())
    runtime=Runtime(build,None,fixture,integration=additive)
    runtime.deadline=min(build.DEADLINE,start+1800)
    prior={sig:signal.signal(sig,lambda *_:setattr(runtime,'cancelled',True)) for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
    binaries={name:build.sha(build.WORK/'build/bin'/name) for name in ('world','zone','shared_memory')}
    result=dict(scope=SELECTION,exit_code=2,binaries=binaries,fixture_sha256=FIXTURE_SHA,process_outcomes=[],
                native_cleanup='not-run',database_cleanup='not-run',summary=initial_summary())
    artifact=b'';error=True;server=None;account=pwd.getpwnam('nobody');failure=None
    stage='runtime-directory'
    try:
        MEDIA.mkdir()
        stage='mount-runtime'
        runtime.command('integration-mount-runtime',['mount','-o','loop,ro,nosuid,nodev,noexec','/media/eqemu-input/runtime.iso',str(MEDIA)])
        stage='runtime-inputs';runtime.verify_inputs()
        stage='runtime-packages';runtime.install_packages()
        stage='database-initialize';runtime.initialize_database()
        stage='database-import';runtime.import_database()
        stage='server-configure';server=runtime.configure()
        stage='fixture-quests';install_quests(server)
        stage='fixture-config'
        config=decode((server/'eqemu_config.json').read_bytes())
        config['server']['world']['loginserver']=dict(host='127.0.0.1',port='5998',account='',password='')
        (server/'eqemu_config.json').write_bytes(encoded(config))
        stage='fixture-plan'
        run_id=Path('/opt/eqemu-worker-nonce').read_text().strip()
        plan=dict(run=run_id,server_commit=identity['candidate'],server_tree=identity['tree'],stack_commit=identity['stack_commit'],binaries=binaries)
        (server/'integration-plan.json').write_bytes(encoded(plan));(server/'integration-plan.json').chmod(0o600)
        stage='fixture-ownership'
        for path in (server,*server.rglob('*')):
            if not path.is_symlink(): os.chown(path,account.pw_uid,account.pw_gid)
        prefix=['/usr/bin/setpriv','--reuid='+str(account.pw_uid),'--regid='+str(account.pw_gid),'--clear-groups','--no-new-privs']
        stage='shared-memory'
        runtime.command('integration-shared-memory',[*prefix,str(build.WORK/'build/bin/shared_memory')],cwd=server,timeout=180)
        stage='shared-files'
        for name in ('items','spells'):
            path=server/'shared'/name
            if not path.is_file() or path.is_symlink() or not 0<path.stat().st_size<=768*1024**2: fail()
        stage='controller'
        output=runtime.command('actor-population-integration',[*prefix,'/usr/bin/python3','/opt/actor_integration.py',str(build.WORK/'build/bin'),str(server)],cwd=server,timeout=max(1,runtime.deadline-time.monotonic()-30))
        stage='controller-result'
        lines=[line[len('CDAU_RESULT '):] for line in output.splitlines() if line.startswith('CDAU_RESULT ')]
        if len(lines)!=1: fail()
        observed=decode(lines[0]);validate_result(observed,database_required=False)
        if observed['binaries']!=binaries or observed['fixture_sha256']!=FIXTURE_SHA: fail()
        result=observed
        error=False
        if result['exit_code']: failure=(stage,None)
        stage='final-inputs'
        runtime.verify_inputs()
        stage='binary-identity'
        if any(build.sha(build.WORK/'build/bin'/name)!=digest for name,digest in binaries.items()): fail()
    except Exception as cause:
        failure=failure or (stage,cause)
        result['exit_code']=2
        result['summary']['outcome']=2
        result['summary']['failure_cause']=11
    finally:
        try:
            result['database_cleanup']=runtime.cleanup()
            if result['database_cleanup'] is not True: failure=failure or ('database-cleanup',None)
        except Exception as cause:
            result['database_cleanup']=False
            failure=failure or ('database-cleanup',cause)
        for sig,handler in prior.items(): signal.signal(sig,handler)
        if server is not None:
            stage='artifact-read'
            try:
                artifact=read_public(server/(SELECTION+'.json'),CAP,owner=account.pw_uid)
                stage='artifact-validate'
                public_artifact(artifact,runtime.secrets)
            except Exception as cause:
                artifact=b''
                failure=failure or (stage,cause)
        if error or result['database_cleanup'] is not True or not artifact:
            result['exit_code']=2;result['summary']['outcome']=2
            if not result['summary']['failure_cause']: result['summary']['failure_cause']=11
        for frame in frames(artifact,identity['candidate'],Path('/opt/eqemu-worker-nonce').read_text().strip(),
                            complete=bool(artifact) and decode(artifact)['complete'],
                            gaps=not bool(artifact) or bool(decode(artifact)['gaps']),
                            overflow=bool(artifact) and decode(artifact)['overflow']):
            sys_stdout_write(wire(frame))
    validate_result(result)
    if result['exit_code']:
        phase,cause=failure or ('controller-result',None)
        error=RuntimeError(failure_text(phase,cause));error.result=result
        raise error from cause
    return result





def public_artifact(raw,secrets):
    value=validate_artifact(raw)
    def contains(item):
        if isinstance(item,str): return any(secret and secret in item for secret in secrets)
        if isinstance(item,list): return any(contains(v) for v in item)
        if isinstance(item,dict): return any(contains(k) or contains(v) for k,v in item.items())
        return False
    if contains(value): raise ValueError('integration-private-artifact-refused')
    for snapshot in value['snapshots']:
        if any(contains(decode(record)) for record in snapshot['raw_json_by_actor']):
            raise ValueError('integration-private-artifact-refused')
    return value


def local_contract(name):
    path=Path(__file__).with_name(name)
    if not path.exists(): path=Path(__file__).parents[1]/name
    return decode(path.read_bytes())



def validate_build_binding(value):
    expected=local_contract('actor-integration-fixture.json')['server_source']
    if expected['status']!='reviewed-source-only-unrun': raise ValueError('integration-server-source-provisional')
    if value.get('candidate')!=expected['commit'] or value.get('tree')!=expected['tree']:
        raise ValueError('integration-selected-server-source-mismatch')


def validate_input_identity(value):
    fields={'version','candidate','tree','files','world_control','integration','stack_commit'}
    names={'eqemu.tar','websocketpp.tar','native.iso','rust-inputs.tar','runtime.iso','integration-fixture.tar'}
    integration='integration' in value
    if not integration:
        fields.remove('integration');names.remove('integration-fixture.tar')
    if (not isinstance(value,dict) or set(value)!=fields or type(value['version']) is not int or value['version']!=1
            or (integration and value['integration']!=SELECTION) or value['world_control'] is not None
            or not isinstance(value['files'],dict) or set(value['files'])!=names): fail()
    for key in ('candidate','tree','stack_commit'): hex_string(value[key],40)
    validate_build_binding(value)
    for item in value['files'].values():
        if not isinstance(item,dict) or set(item)!={'bytes','sha256'}: fail()
        bounded_int(item['bytes'],1,1024**3);hex_string(item['sha256'],64)
    expected=dict(native_iso=dict(bytes=469000192,sha256='02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4'),
                  runtime_iso={k:local_contract('runtime-fixture.json')['iso'][k] for k in ('bytes','sha256')},
                  integration_fixture_tar=dict(bytes=FIXTURE_BYTES,sha256=FIXTURE_SHA))
    if not integration: expected.pop('integration_fixture_tar')
    for key,item in expected.items():
        name=key.replace('_','.') if key.endswith('_iso') else 'integration-fixture.tar'
        if value['files'][name]!=item: fail()
    verify_dependencies(value)


def dependency_contract():
    path=Path(__file__).with_name('actor-integration-fixture.json')
    if not path.exists(): path=Path(__file__).parents[1]/'actor-integration-fixture.json'
    contract=decode(path.read_bytes())['rust_input']
    if contract['status']!='sealed-data-only-source-pin':
        raise ValueError('integration-rust-input-provisional')
    return contract


def verify_dependencies(identity,source=None):
    contract=dependency_contract()
    expected={key:contract[key] for key in ('bytes','sha256')}
    if identity['files'].get('rust-inputs.tar')!=expected: fail()
    if source is not None:
        raw=read_public(Path(source)/contract['lock_path'],65536,owner=0)
        if len(raw)!=contract['lock_bytes'] or hashlib.sha256(raw).hexdigest()!=contract['lock_sha256']: fail()


def sys_stdout_write(raw):
    import sys
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()



def native_inventory_baseline(shard,counts,earned=None):
    records=[decode(raw) for raw in shard['snapshots'][-1]['raw_json_by_actor']]
    for actor,(record,count) in enumerate(zip(records,counts)):
        actual=shard['admission']['actors'][actor]
        items=record['saved']['inventory']
        context=shard['contexts'][actual[0]][1]
        if (len(items)!=count or actual[2]!=count or actual[1]!=hashlib.sha256(encoded(items)).hexdigest()
                or actual[3]!=record['saved']['level'] or actual[5]!=2 or context[1]!=actor+1 or context[13]!=1): fail()
    if earned is not None and records[0]['saved']['max_hp']!=decode(earned)['saved']['max_hp']+13: fail()
    return records


class Controller:
    """Three fixed fixture sets, with shared caps and exhaustive native ownership."""
    def __init__(self,binary_dir,server,plan,*,clock=None):
        import time
        self.clock=clock or time.monotonic
        self.binary_dir=Path(binary_dir);self.server=Path(server);self.plan=plan
        self.origin_us=int(self.clock()*1000000)
        self.deadline=self.clock()+1440
        self.case_deadline=self.deadline
        self.natives=[];self.mailboxes={};self.budget=Budget();self.collection=Collection(plan['run'])
        self.summary=initial_summary();self.case=None;self.population=None
        self.clean=True;self.cancelled=False;self.earned=None
        self.admission_roles=[[None,None] for _ in range(3)]

    def guard(self):
        if self.cancelled or self.clock()>=min(self.deadline,self.case_deadline):
            raise ValueError('integration-deadline')
        for native in self.natives:
            if not native.closed and (native.process.poll() is not None or native.log.stat().st_size>1024**2):
                raise ValueError('integration-native-failure')

    def wait(self,predicate,seconds=480):
        import time
        end=min(self.clock()+seconds,self.deadline,self.case_deadline)
        while self.clock()<end:
            self.guard()
            try:
                value=predicate()
                if value: return value
            except FileNotFoundError: pass
            time.sleep(.05)
        raise ValueError('integration-condition-timeout')

    def pause(self,seconds):
        end=self.clock()+seconds
        self.wait(lambda:self.clock()>=end,seconds+1)

    def launch(self,role,*,recovery=False):
        index=len(self.natives);self.budget.take('processes')
        if role!='world': self.budget.take('zone_starts')
        if sum(not n.closed for n in self.natives)>=3: fail()
        native=Native(role,self.binary_dir,self.server,self.population,self.plan['run'],self.case,index,self.origin_us,
                      on_started=self.natives.append,recovery=recovery)
        if role=='world': return native,None
        mailbox=Mailbox(self.population,native.descriptor,self.plan['run'],self.budget,self.collection,self.guard)
        self.mailboxes[index]=mailbox
        return native,mailbox

    def collect(self,mailbox,*,snapshot=False):
        shard=mailbox.observe(snapshot)
        case=ord(self.case)-ord('A');role=0 if mailbox.process['zone']==2 else 1
        candidate=(mailbox.process['index'],shard['admission'])
        old=self.admission_roles[case][role]
        def score(entry):
            admission=entry[1]
            return (100000 if admission['geometry'][0] and admission['geometry'][13]==255 else 0) + admission['native_route_flags']*1000 + sum(a[2]+(10 if a[3] else 0) for a in admission['actors'])
        if old is None or score(candidate)>score(old):
            import copy
            self.admission_roles[case][role]=copy.deepcopy(candidate)
        return shard

    def begin(self,case,*,items=False):
        self.case=case;self.case_deadline=min(self.deadline,self.clock()+480)
        self.population=self.server/('population-'+case)
        self.population.mkdir(mode=0o700)
        records=self.population/'actors-v3';records.mkdir(mode=0o700)
        for actor,raw in enumerate(seed_records(self.earned if items else None,inventory=items)):
            with (records/('actor-'+str(actor+1)+'.json')).open('xb') as stream: stream.write(raw)
            (records/('actor-'+str(actor+1)+'.json')).chmod(0o600)
        world,_=self.launch('world');source,mailbox=self.launch('source');mailbox.startup()
        from normal_world import world_connected
        self.wait(lambda:world_connected(world.process.pid,source.process.pid),10)
        return world,source,mailbox

    def finish_native(self,native,*,fault=False):
        clean=native.stop(expected_fault=fault);self.clean=clean and self.clean
        if native.descriptor is None:
            raise ValueError('integration-native-identity-unavailable')
        terminal_error=False
        if not fault and clean and native.descriptor['zone']:
            try: self.mailboxes[native.descriptor['index']].terminal(native)
            except Exception:
                terminal_error=True
                native.descriptor['complete_prefix']=False
        shard=self.collection.shards.get(native.descriptor['index'])
        if shard is not None:
            native.descriptor.update(first_seq=shard['process']['first_seq'],last_seq=shard['process']['last_seq'],
                                     complete_prefix=native.descriptor['complete_prefix'] and shard['complete'])
            shard['process']=dict(native.descriptor)
        elif native.descriptor['zone']:
            native.descriptor['complete_prefix']=False
        if not clean: raise ValueError('integration-native-cleanup')
        if terminal_error: raise ValueError('integration-terminal-incomplete')

    def drain(self,mailbox):
        mailbox.command('drain')
        self.wait(lambda:mailbox.status().get('restart_safe') is True,30)

    def fault_and_refuse(self,native,mailbox,actor,*,destination=False):
        status=mailbox.status();state=status['actors'][actor]
        if not state['body_present'] or not state['runtime_alive'] or not state['owned_here']: fail()
        self.collect(mailbox)
        self.finish_native(native,fault=True)
        path=self.population/'actors-v3'/('actor-'+str(actor+1)+'.json')
        dirty=read_public(path,8192)
        record=decode(dirty)
        if record['clean'] is not False: fail()
        replacement,recovery=self.launch('destination' if destination else 'source',recovery=destination)
        recovery.startup()
        recovery.command('start','hunter-'+str(actor+1),expect_recovery=True)
        shard=self.collect(recovery,snapshot=True)
        if read_public(path,8192)!=dirty: fail()
        if any(e[3]==11 and e[6][0]==0 for e in shard['events']): fail()
        refusals=[e for e in shard['events'] if e[3]==12 and e[6]==[3,ord(self.case)-65,'0',0,5,'0',str(record['revision']),'0']]
        if not refusals or not any(e[5]==str(record['revision']) for e in refusals): fail()
        return replacement,recovery

    def case_a(self):
        world,source,mailbox=self.begin('A')
        self.collect(mailbox,snapshot=True)
        mailbox.command('start','all')
        self.wait(lambda:all(actor['body_present'] for actor in mailbox.status()['actors']),10)
        admitted=self.collect(mailbox)
        if any(actor[1]!=hashlib.sha256(b'[]').hexdigest() or actor[2]!=0 or actor[3]!=1 for actor in admitted['admission']['actors']): fail()
        for actor in (1,2):
            if mailbox.status()['actors'][actor]['phase']!='resting': fail()
            mailbox.command('stop','hunter-'+str(actor+1))
        self.wait(lambda:mailbox.status()['actors'][0]['level']==2 and mailbox.status()['actors'][0]['completed']>=2)
        self.collect(mailbox)
        self.wait(lambda:mailbox.status()['actors'][0]['completed']>=3)
        self.collect(mailbox)
        self.wait(lambda:(self.server/'cdau-flipped').is_file(),30)
        self.pause(2)
        self.collect(mailbox)
        mailbox.command('stop','hunter-1')
        self.wait(lambda:mailbox.status()['actors'][0]['drained'] is True,30)
        self.collect(mailbox,snapshot=True)
        self.drain(mailbox)
        shard=self.collect(mailbox,snapshot=True)
        raw_set=shard['snapshots'][-1]['raw_json_by_actor']
        if any(decode(raw)['saved']['experience']!=0 or decode(raw)['saved']['completed']!=0 or decode(raw)['saved']['level']!=1 for raw in raw_set[1:]): fail()
        self.earned=raw_set[0]
        earned=decode(self.earned)
        if earned['clean'] is not True or earned['saved']['level']!=2 or earned['saved']['experience']<1000: fail()
        self.finish_native(source);self.finish_native(world)
        self.summary['case_outcomes'][0]=1

    def case_b(self):
        world,source,mailbox=self.begin('B',items=True)
        mailbox.command('start','all')
        self.wait(lambda:all(a['body_present'] is True for a in mailbox.status()['actors']),30)
        mailbox.command('stop','all')
        self.wait(lambda:all(a['drained'] is True for a in mailbox.status()['actors']),30)
        baseline=self.collect(mailbox,snapshot=True)
        native_inventory_baseline(baseline,[8,0,0],self.earned)
        self.drain(mailbox);self.collect(mailbox,snapshot=True)
        self.finish_native(source);self.finish_native(world)
        world,_=self.launch('world');source,mailbox=self.launch('source');mailbox.startup()
        destination,target=self.launch('destination')
        mailbox.command('start','hunter-1');mailbox.command('start','hunter-2')
        self.wait(lambda:mailbox.status()['actors'][0]['owner_zone']==4)
        target.startup()
        self.wait(lambda:target.status()['actors'][0]['body_present'] is True,30)
        self.collect(mailbox,snapshot=True);self.collect(target,snapshot=True)
        source,recovery=self.fault_and_refuse(source,mailbox,1)
        target.command('stop','hunter-1');self.drain(target)
        self.collect(target)
        self.finish_native(source);self.finish_native(destination);self.finish_native(world)
        self.summary['case_outcomes'][1]=1

    def case_c(self):
        world,source,mailbox=self.begin('C',items=True)
        mailbox.command('start','hunter-1')
        self.wait(lambda:mailbox.status()['actors'][0]['body_present'] is True,30)
        mailbox.command('stop','hunter-1')
        self.wait(lambda:mailbox.status()['actors'][0]['drained'] is True,30)
        baseline=self.collect(mailbox,snapshot=True)
        actual=baseline['admission']['actors'][0]
        record=decode(baseline['snapshots'][-1]['raw_json_by_actor'][0])
        if actual[2]!=8 or actual[1]!=hashlib.sha256(encoded(record['saved']['inventory'])).hexdigest() or actual[3]!=2 or actual[5]!=2: fail()
        mailbox.command('start','hunter-1')
        self.wait(lambda:mailbox.status()['actors'][0]['phase']=='preparing_transfer')
        self.pause(2.2)
        shard=self.collect(mailbox)
        boot=sum(e[3]==12 and e[6][0]==1 and e[6][3]==100 for e in shard['events'])
        if not 2<=boot<=12: fail()
        destination,target=self.launch('destination');target.startup()
        self.wait(lambda:target.status()['actors'][0]['body_present'] is True,30)
        self.collect(mailbox);self.collect(target,snapshot=True);self.collect(target,snapshot=True)
        destination,recovery=self.fault_and_refuse(destination,target,0,destination=True)
        self.drain(mailbox);self.collect(mailbox)
        self.finish_native(destination);self.finish_native(source);self.finish_native(world)
        self.summary['case_outcomes'][2]=1


def qualify(value):
    """Twelve fixed evidence checks. Status polling never supplies these verdicts."""
    contexts=value['contexts'];events=value['events'];processes=value['processes'];snapshots=value['snapshots']
    identity_ok=all(c[9:12]==[1,1,140] and c[12] in (2,4) and c[14] in (1,2) for c in contexts if c[13]==1 and c[1] in (1,2,3))
    cases={}
    for event in events:
        if event[3]==12:
            previous=cases.setdefault(event[0],event[6][1])
            if previous!=event[6][1]: fail()
    def selected(case,kind=None):
        return [e for e in events if cases.get(e[0])==case and (kind is None or e[3]==kind)]
    def logical(event,index): return contexts[event[4]][1]==index+1
    def publication(proc,seq): return next((e for e in events if e[0]==proc and e[1]==int(seq) and e[3]==5),None)
    credits=selected(0,8)
    latches={};commits={};valid_credit=True
    for event in credits:
        payload=event[6];key=(event[0],payload[1])
        target=latches if payload[0]==1 else commits if payload[0]==2 else None
        if target is not None:
            if key in target: valid_credit=False
            target[key]=event
    starter=[e for e in latches.values() if contexts[e[4]][14]==1 and logical(e,0)]
    earned=(valid_credit and len(starter)==2 and all(e[6][5:7]==['500','1000'] and int(e[6][3])>0 and int(e[6][4])>0 for e in starter)
            and all((e[0],e[6][1]) in commits for e in starter))
    for event in commits.values():
        p=event[6];pub=publication(p[2],p[3])
        if (pub is None or pub[6][0]!=4 or pub[6][4]!=p[5] or pub[6][5]!=p[7]
                or int(p[5])<int(p[4]) or int(p[7])!=int(p[6])+1): earned=False
    faction=selected(0,7)
    earned=earned and bool(faction) and len({(e[0],e[6][0],e[6][1]) for e in faction})==len(faction) and all((e[0],e[6][0]) in commits for e in faction)
    levels=selected(0,9)
    applied=[e for e in levels if e[6][0]==1 and e[6][1:3]==[1,2] and int(e[6][4])>=1000 and logical(e,0)]
    ack=any(observed[0]==native[0] and observed[1]>native[1] and observed[6][0]==2
            and observed[6][1:4]==native[6][1:4] and int(observed[6][4])>=1000
            and contexts[observed[4]][2:5]==contexts[native[4]][2:5]
            for native in applied for observed in levels)
    admission=value['manifest']['admission_by_case']
    geometry=admission[0][0]['geometry']
    geometry_ok=False;hostility=False;flip=False
    if geometry[0] and geometry[13]==255:
        actor,hostile,friendly=geometry[1:4]
        points=[[float(v) for v in geometry[start:start+3]] for start in (4,7,10)]
        distances=[sum((a-b)**2 for a,b in zip(points[0],p)) for p in points[1:]]
        geometry_ok=0<distances[1]<distances[0]
        reactions=selected(0,10);attacks=selected(0,6)
        hostility=(geometry_ok and any(e[6][0]==hostile and e[6][5]>=8 for e in reactions)
                   and any(e[6][0]==friendly and 1<=e[6][5]<=7 for e in reactions)
                   and any(e[6][0]==hostile and e[6][1]==0 and e[6][2] is True for e in attacks)
                   and not any(e[6][0]==friendly and e[6][2] is True for e in attacks))
        for before in attacks:
            if before[6][1]!=0 or not before[6][2]: continue
            flipped_target=before[6][0]
            if not any(e[6][0]==flipped_target and e[6][1]==306 and e[6][5]>=8 and e[0]==before[0] and e[1]<before[1] for e in reactions): continue
            for after in reactions:
                if after[0]!=before[0] or after[1]<=before[1] or after[6][0]!=flipped_target or after[6][1]!=309 or not 1<=after[6][5]<=7 or after[6][6]&1: continue
                later=[e for e in attacks if e[0]==after[0] and e[1]>after[1] and e[6][0]==flipped_target]
                if all(not e[6][2] and e[6][5]==e[6][6] for e in later): flip=True
    bsnaps=[s for s in snapshots if cases.get(s['process_index'])==1]
    inventory=False;split=False
    if len(bsnaps)==5:
        inventories=[decode(s['raw_json_by_actor'][0])['saved']['inventory'] for s in bsnaps]
        baseline=inventories[0]
        native=admission[1][0]['actors'][0]
        inventory=(len(baseline)==8 and {item['id'] for item in baseline}=={1074,41085,2947,17005,1115,11602,1001,7007}
                   and all(items==baseline for items in inventories)
                   and native[1]==hashlib.sha256(encoded(baseline)).hexdigest() and native[2]==8
                   and admission[1][1]['actors'][0][1]==native[1]
                   and all(any(e[3]==12 and e[6][3]==103 and logical(e,actor) for e in selected(1)) for actor in (0,1,2)))
        split=any((lambda records:records[0]['saved']['zone']==4 and records[1]['saved']['zone']==2 and not records[0]['clean'] and not records[1]['clean'])([decode(r) for r in s['raw_json_by_actor']]) for s in bsnaps)
        split=split and all(any(e[3]==11 and e[6][0]==0 and logical(e,actor) and contexts[e[4]][12]==zone for e in selected(1)) for actor,zone in ((0,4),(1,2)))
    connection=admission[1][0]['connection']
    travel=(connection[0] is True and connection[1:4]==[9,2,4] and admission[1][0]['native_route_flags']==127
            and float(connection[4])==73 and float(connection[5])==1272 and float(connection[7])==float(connection[4])
            and float(connection[7])!=999999
            and any(e[3]==11 and e[6][0]==0 and logical(e,0) and contexts[e[4]][12]==4 for e in selected(1)))
    custody=False
    for pub in selected(1,5):
        if pub[6][0]!=7 or not logical(pub,0): continue
        source=[e for e in selected(1,11) if e[0]==pub[0] and logical(e,0)]
        ready=[e for e in source if e[6][0]==3 and e[1]<pub[1]]
        drains=[e for e in source if e[6][0]==2 and e[1]<pub[1]]
        release=[e for e in source if e[6][0]==7 and e[1]>pub[1]]
        acquired=[e for e in selected(1,11) if e[0]!=pub[0] and e[6][0]==6 and logical(e,0) and e[5]==pub[5]]
        for released in release:
            matched=[e for e in acquired if contexts[e[4]][2]==contexts[released[4]][2]==contexts[pub[4]][2] and released[5]==pub[5]]
            # Same actor/revision/owner epoch at real unlock/acquire boundaries
            # supplies the cross-process edge. Wall-clock order is insufficient.
            if matched and any(r[1]<d[1]<pub[1]<released[1] for r in ready for d in drains): custody=True
    boots=[e for e in selected(2,12) if e[6][0]==1 and e[6][3]==100 and logical(e,0)]
    unavailable=len(boots)>=2
    normal_destination=[p for p in processes if p['role_world_source_destination']=='destination' and cases.get(p['index'])==2 and p['exit_kind']==2]
    duplicates=False
    if len(normal_destination)==1:
        proc=normal_destination[0]['index']
        bodies=[e for e in selected(2,11) if e[0]==proc and logical(e,0) and e[6][0]==0]
        acquires=[e for e in selected(2,11) if e[0]==proc and logical(e,0) and e[6][0]==6]
        duplicates=unavailable and len(bodies)==len(acquires)==1
    def recovery(case,actor,role):
        failures=[e for e in selected(case,12) if e[6][0]==3 and e[6][4]==5 and contexts[e[4]][13]==3]
        for event in failures:
            process=processes[event[0]]
            if process['role_world_source_destination']!=role or process['exit_kind']!=1: continue
            if any(e[3]==11 and e[0]==event[0] and e[6][0]==0 for e in selected(case)): continue
            for snapshot in snapshots:
                if snapshot['process_index']!=event[0]: continue
                record=decode(snapshot['raw_json_by_actor'][actor])
                if not record['clean'] and str(record['revision'])==event[5]==event[6][6]:
                    return any(p['exit_kind']==2 and p['role_world_source_destination']==role and cases.get(p['index'])==case for p in processes)
        return False
    return [identity_ok and bool(v) for v in (earned,ack,hostility,flip,inventory,travel,custody,split,unavailable,duplicates,recovery(1,1,'source'),recovery(2,0,'destination'))]


def final_artifact(controller):
    import copy
    contexts,events,snapshots,_=controller.collection.merged()
    if not contexts: return None
    processes=[dict(n.descriptor) for n in controller.natives if n.descriptor is not None]
    absent=next((i for i,c in enumerate(contexts) if c[13]==3),None)
    if absent is None: fail()
    empty=dict(actors=[[absent,'0'*64,0,0,'0',0] for _ in range(3)],
               connection=[False,0,0,0,*(['0']*6)],native_route_flags=0,
               geometry=[False,absent,absent,absent,*(['0']*9),0])
    offsets={};offset=0
    for proc,shard in sorted(controller.collection.shards.items()):
        offsets[proc]=offset;offset+=len(shard['contexts'])
    admissions=[]
    for case in controller.admission_roles:
        roles=[]
        for entry in case:
            if entry is None: roles.append(copy.deepcopy(empty));continue
            proc,admission=entry;admission=copy.deepcopy(admission)
            for actor in admission['actors']: actor[0]+=offsets[proc]
            admission['geometry'][1:4]=[ref+offsets[proc] for ref in admission['geometry'][1:4]]
            roles.append(admission)
        admissions.append(roles)
    summary=controller.summary
    summary.update(counters(events),process_count=len(processes),context_count=len(contexts),snapshot_count=len(snapshots),
                   commands=controller.budget.counts['commands'],zone_starts=controller.budget.counts['zone_starts'],
                   complete_prefixes=sum(p['complete_prefix'] for p in processes))
    value=dict(schema=SELECTION,contract_sha256=CONTRACT_SHA,fixture_sha256=FIXTURE_SHA,processes=processes,contexts=contexts,
               events=events,snapshots=snapshots,manifest=dict(server_commit=controller.plan['server_commit'],server_tree=controller.plan['server_tree'],
               stack_commit=controller.plan['stack_commit'],fixture_selection_sha256='cec8c281604549b7c4d54259ff7760ffe37dae26dc09e5fa4462ef2823c86871',
               public_fixture_sha256=FIXTURE_SHA,event_contract_sha256=CONTRACT_SHA,interface_sha256=INTERFACE_SHA,
               run=controller.plan['run'],admission_by_case=admissions),summary=summary,
               complete=len(processes)==len(controller.natives) and all(p['complete_prefix'] for p in processes) and not controller.collection.failed,
               overflow=controller.collection.overflow,gaps=controller.collection.gaps)
    checks=qualify(value)
    summary['check_results']=[1 if passed else 2 for passed in checks]
    summary['outcome']=1 if all(checks) and controller.clean and summary['case_outcomes']==[1]*3 else 2
    if summary['outcome']==2 and summary['failure_cause']==0: summary['failure_cause']=11
    validate_artifact(encoded(value))
    return value


def observe(binary_dir,server):
    """Unprivileged guest-only controller; every native exit remains independent."""
    import os
    import resource
    import signal
    import sys
    if os.geteuid()==0 or not Path('/opt/eqemu-worker-build-guest').is_file():
        raise RuntimeError('integration-observer-guest-only')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE,(1024**2,1024**2))
    plan=decode(read_public(Path(server)/'integration-plan.json',2048))
    if set(plan)!={'run','server_commit','server_tree','stack_commit','binaries'}: fail()
    controller=Controller(binary_dir,server,plan)
    prior={sig:signal.signal(sig,lambda *_:setattr(controller,'cancelled',True)) for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
    try:
        controller.case_a();controller.case_b();controller.case_c()
    except Exception:
        controller.summary['outcome']=2;controller.summary['failure_cause']=11
        if controller.case is not None: controller.summary['case_outcomes'][ord(controller.case)-65]=2
    finally:
        for native in reversed(controller.natives):
            if not native.closed:
                try: controller.finish_native(native)
                except Exception: controller.clean=False
        for sig,handler in prior.items(): signal.signal(sig,handler)
    value=None
    try:
        value=final_artifact(controller)
        if value is not None: atomic_public(Path(server)/(SELECTION+'.json'),encoded(value),CAP)
    except Exception:
        controller.summary['outcome']=2;controller.summary['failure_cause']=8
    result=dict(scope=SELECTION,exit_code=0 if value is not None and controller.summary['outcome']==1 else 2,
                binaries=plan['binaries'],fixture_sha256=FIXTURE_SHA,
                process_outcomes=[[n.index,n.descriptor['exit_kind'] if n.descriptor else 4,n.process.returncode if n.process.returncode is not None else 255] for n in controller.natives],
                native_cleanup=all(n.cleanup_complete for n in controller.natives) if controller.natives else 'not-run',database_cleanup='not-run',summary=controller.summary)
    validate_result(result,database_required=False)
    print('CDAU_RESULT '+encoded(result).decode(),flush=True)


if __name__=='__main__':
    import sys
    if len(sys.argv)!=3: raise SystemExit(2)
    observe(Path(sys.argv[1]),Path(sys.argv[2]))
