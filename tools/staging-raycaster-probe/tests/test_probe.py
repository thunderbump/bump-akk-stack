"""Harmless host tests. No native Server, DB, container, SSH, or scheduler."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('probe', HERE/'probe.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class ProbeTests(unittest.TestCase):
    def test_import_never_connects_or_launches(self):
        with patch('subprocess.Popen', side_effect=AssertionError), patch('socket.socket', side_effect=AssertionError):
            spec.loader.exec_module(p)

    def test_vendor_matches_pinned_source(self):
        comparator = p.load_comparator()
        self.assertTrue(callable(comparator.parse_route))
        pins = json.loads((HERE/'vendor/pins.json').read_text())
        self.assertEqual(pins['commit'], '6a037f008f9398df5967fa70ded0de32a9e83335')
        self.assertEqual(p.digest(HERE/'vendor/runtime-support-pins.json'),p.SUPPORT_MANIFEST_SHA)

    def test_config_overrides_scalar_and_array_fallbacks(self):
        original = {'server': {'directories': {'quest_paths':['/public'], 'plugins':'/public'},
                               'files': {'plugin.pl':'/public/plugin.pl'}}}
        before = copy.deepcopy(original)
        config = p.private_config(original, Path('/private'), {'maps':'/maps'})
        self.assertEqual(original, before)
        dirs = config['server']['directories']
        self.assertEqual(dirs['quest_paths'], ['/private/quests'])
        self.assertEqual(dirs['plugin_paths'], ['/private/plugins'])
        self.assertEqual(dirs['lua_module_paths'], ['/private/modules'])
        self.assertEqual(config['server']['auto_database_updates'], 'false')
        self.assertNotIn('/public', json.dumps(config))

    def test_private_quests_keep_fixed_calls_and_runtime_overrides(self):
        for name in ('2011.pl','pok-2011.pl'):
            text = p.quest(HERE/'vendor'/name)
            self.assertNotIn('quest::debug', text)
            self.assertNotIn('/runtime/', text)
            self.assertIn('probe_emit', text)
            self.assertIn('$npc->ChangeSize(6)', text)
            self.assertIn('$npc->SetNPCFactionID(0)', text)
            self.assertIn('quest::processmobswhilezoneempty(1)', text)
            for stat in ('aggro','assist','runspeed'):
                self.assertIn('ModifyNPCStat("'+stat+'"', text)
            self.assertEqual(text.count('->MoveTo('), 1)
            self.assertIn(',0,1);', text)
            self.assertEqual(text.count('->GMMove('), 2)
            self.assertIn('"stop-map-validation"', text)

    def test_delete_is_exact_and_rejects_changed_row(self):
        store = object.__new__(p.Store)
        store.names = {'game':'peq'}
        store.db = MagicMock()
        store.rows = MagicMock(return_value=[])
        with self.assertRaises(p.Refusal):
            store.delete_exact('game','respawn_times',{'id':7,'instance_id':12})
        store.db.cursor.assert_not_called()
        store.rows.return_value = [{'id':7,'instance_id':12}]
        cursor = store.db.cursor.return_value.__enter__.return_value
        cursor.rowcount = 1
        store.delete_exact('game','respawn_times',{'id':7,'instance_id':12})
        sql, args = cursor.execute.call_args.args
        self.assertIn('`id` <=> %s AND `instance_id` <=> %s LIMIT 1', sql)
        self.assertEqual(args, (7,12))
        cursor.rowcount = 0
        with self.assertRaises(p.Refusal):
            store.delete_exact('game','respawn_times',{'id':7,'instance_id':12})

    def test_cleanup_never_deletes_player_state(self):
        store = object.__new__(p.Store)
        store.contract = {'zones':{z[0]:{'instance':n+1} for n,z in enumerate(p.ZONES)}}
        store.protected_empty = MagicMock(side_effect=p.Refusal('player state'))
        store.delete_exact = MagicMock()
        store.db = MagicMock()
        with self.assertRaises(p.Refusal):
            store.cleanup()
        store.delete_exact.assert_not_called()
        store.db.commit.assert_not_called()

    def test_bootstrap_uses_only_inserts_and_unchanged_npc_type(self):
        store = object.__new__(p.Store)
        store.contract = {'zones':{z[0]:{'instance':n+1,'version':240,'spawn':100+n,'group':200+n} for n,z in enumerate(p.ZONES)}}
        store.insert = MagicMock()
        store.bootstrap()
        self.assertEqual(len(store.insert.call_args_list), 8)
        for call in store.insert.call_args_list:
            role, table, values, identity = call.args
            self.assertNotEqual(table,'npc_types')
            if table == 'instance_list':
                self.assertEqual(values['is_global'],0)
                self.assertEqual(values['never_expires'],0)
                self.assertEqual(values['duration'],600)
            if table == 'spawnentry':
                self.assertEqual(values['npcID'],2011)

    def test_missing_nan_wrong_backend_entity_teleport_budget_fail(self):
        comparator = p.load_comparator()
        with self.assertRaises(ValueError):
            comparator.parse_queries('')
        query = 'SERVER_COLLISION_QUERY id={id} time=1 npc=2011 entity=1 from=1,2,3 size=6 origin=1,2,3 adjusted=1,2,4 eyes=1,2,6 to=1,2,3 target_size=6 target_eyes=1,2,5 ground={ground} los={los}\n'
        text = ''.join(query.format(id=i, ground='3', los='0' if i=='blocked' else '1') for i in ('start','clear','blocked'))
        self.assertEqual(len(comparator.parse_queries(text)),3)
        with self.assertRaises(ValueError):
            comparator.parse_queries(text.replace('ground=3','ground=NaN',1))
        base = 'SERVER_COLLISION_NATIVE caller=GetGroundZ entity={entity} backend={backend} kind={kind} from=1,2,3 to=1,2,3 result=3 remaining={remaining}\n'
        for override in ({'backend':'OFF'}, {'entity':'2'}, {'kind':'teleport'}, {'remaining':'0'}):
            values = dict(entity='1',backend='ON',kind='FindBestZ',remaining='4095')
            values.update(override)
            with self.assertRaises(ValueError):
                comparator.parse_route(text+base.format(**values),'ON',json.loads((HERE/'vendor/route.json').read_text()))

    def test_real_harmless_child_stop_reap_and_redaction(self):
        # This harmless Python fixture exercises native-child lifecycle handling.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = root/'child.py'
            child.write_text('import signal,time\nfrom pathlib import Path\nsignal.signal(signal.SIGTERM,lambda *_:exit(0))\nprint("secret native boot text",flush=True)\nprint("SERVER_COLLISION_ROUTE_DONE",flush=True)\nwhile not Path("stop-map-validation").exists():time.sleep(.01)\nprint("MAP_SERVER_PROBE_STOPPED",flush=True)\ntime.sleep(20)\n')
            real_popen = subprocess.Popen
            def launch(*args, **kwargs):
                return real_popen([sys.executable,str(child)], **kwargs)
            receipt = {}
            with patch.object(p.subprocess,'Popen',side_effect=launch), patch.object(p,'digest',return_value=p.ZONE_SHA):
                text = p.run_child(Path('/unused'),root,'qeynos2',{'port':12345,'instance':42},receipt)
            self.assertEqual(receipt['exit'],0)
            self.assertTrue(receipt['reaped'])
            self.assertTrue(receipt['quiesced'])
            self.assertNotIn('secret',text)
            self.assertNotIn('secret',json.dumps(receipt))
            self.assertLess(receipt['seconds'],10)

    def test_unqualified_schema_refuses_before_any_fixture_write(self):
        store = object.__new__(p.Store)
        store.schema = MagicMock(side_effect=p.Refusal('unknown schema'))
        store.sql = MagicMock()
        store.insert = MagicMock()
        with self.assertRaises(p.Refusal):
            store.preflight()
        store.sql.assert_not_called()
        store.insert.assert_not_called()

    def test_partial_bootstrap_failure_rolls_back_without_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'run'
            config = Path(tmp)/'config.json'
            contract = Path(tmp)/'contract.json'
            config.write_text(json.dumps({'server':{'world':{'tcp':{'ip':'127.0.0.1'}}}}))
            contract.write_text(json.dumps({'world_pid':1,'assets':{'maps':'/maps'},'zones':{z[0]:{
                'version':250+n,'reference':str(HERE/'vendor/route.json'),'reference_sha256':p.ZONE_SHA,
                'reference_backend':'OFF','port':17901+n} for n,z in enumerate(p.ZONES)}}))
            store = MagicMock()
            store.manifest = {}
            store.bootstrap.side_effect = RuntimeError('sensitive database password')
            argv = ['probe','--config',str(config),'--contract',str(contract),'--root',str(root),'--zone-binary','/unused']
            with patch.object(sys,'argv',argv), patch.object(p,'validate_contract'), patch.object(p,'load_comparator'), patch.object(p,'digest',side_effect=[p.ZONE_SHA,p.WORLD_SHA,p.ZONE_SHA,p.ZONE_SHA]), patch.object(p,'runtime_inputs',return_value=[]), patch.object(p,'prepare_runtime'), patch.object(p,'Store',return_value=store), patch.object(p,'run_child') as launch:
                self.assertEqual(p.main(),1)
            store.db.rollback.assert_called_once()
            store.db.commit.assert_not_called()
            launch.assert_not_called()
            receipt = json.loads((root/'receipt.json').read_text())
            self.assertFalse(receipt['passed'])
            self.assertTrue(receipt['cleanup'])
            self.assertNotIn('sensitive',json.dumps(receipt))

    def test_pinned_driver_import_and_corrupt_wheel_refusal(self):
        driver = p.load_driver()
        self.assertTrue(driver.__file__.startswith(str(HERE/'vendor/pymysql-1.1.2-py3-none-any.whl')+'/'))
        self.assertTrue(callable(driver.connect))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'vendor').mkdir()
            (root/'vendor/pymysql-1.1.2-py3-none-any.whl').write_bytes(b'unapproved')
            with patch.object(p,'HERE',root), self.assertRaises(p.Refusal):
                p.load_driver()

    def test_one_zone_window_never_bootstraps_other_zone(self):
        store = object.__new__(p.Store)
        store.contract = {'only_zone':'qeynos2', 'zones':{'qeynos2':{'instance':42,'version':240,'spawn':100,'group':200}}}
        store.insert = MagicMock()
        store.bootstrap()
        self.assertEqual(len(store.insert.call_args_list),4)
        self.assertEqual(p.selected_zones(store.contract), (p.ZONES[0],))
        with self.assertRaises(p.Refusal):
            p.selected_zones({'only_zone':'public'})

    def test_ambiguous_commit_attempts_exact_cleanup_never_launches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'run'
            config = Path(tmp)/'config.json'
            contract = Path(tmp)/'contract.json'
            config.write_text(json.dumps({'server':{'world':{'tcp':{'ip':'127.0.0.1'}}}}))
            contract.write_text(json.dumps({'world_pid':1,'assets':{'maps':'/maps'},'zones':{z[0]:{
                'version':250+n,'reference':str(HERE/'vendor/route.json'),'reference_sha256':p.ZONE_SHA,
                'reference_backend':'OFF','port':17901+n} for n,z in enumerate(p.ZONES)}}))
            store = MagicMock()
            store.manifest = {}
            store.db.commit.side_effect = OSError('private DB connection lost')
            store.db.rollback.side_effect = OSError('private rollback also lost')
            store.db.close.side_effect = OSError('private close lost')
            store.cleanup.side_effect = OSError('private failed compensation')
            argv = ['probe','--config',str(config),'--contract',str(contract),'--root',str(root),'--zone-binary','/unused']
            with patch.object(sys,'argv',argv), patch.object(p,'validate_contract'), patch.object(p,'load_comparator'), patch.object(p,'digest',side_effect=[p.ZONE_SHA,p.WORLD_SHA,p.ZONE_SHA,p.ZONE_SHA]), patch.object(p,'runtime_inputs',return_value=[]), patch.object(p,'prepare_runtime'), patch.object(p,'Store',return_value=store), patch.object(p,'run_child') as launch:
                self.assertEqual(p.main(),1)
            launch.assert_not_called()
            store.cleanup.assert_called_once()
            store.db.close.assert_called_once()
            receipt = json.loads((root/'receipt.json').read_text())
            self.assertFalse(receipt['passed'])
            self.assertFalse(receipt['cleanup'])
            self.assertIn('cleanup_error',receipt)
            self.assertNotIn('private',json.dumps(receipt))

    def test_postspawn_faults_always_reap_real_harmless_child(self):
        for fault in ('register','touch'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                child = root/'child.py'
                child.write_text('import time\nprint("SERVER_COLLISION_ROUTE_DONE",flush=True)\ntime.sleep(60)\n')
                real_popen = subprocess.Popen
                children = []
                def launch(*args, **kwargs):
                    proc = real_popen([sys.executable,str(child)], **kwargs)
                    children.append(proc)
                    return proc
                receipt = {}
                context = patch.object(p.selectors.EpollSelector,'register',side_effect=OSError('register')) if fault=='register' else patch.object(Path,'touch',side_effect=OSError('touch'))
                try:
                    with patch.object(p.subprocess,'Popen',side_effect=launch), patch.object(p,'digest',return_value=p.ZONE_SHA), context:
                        with self.assertRaises((p.Refusal,OSError)):
                            p.run_child(Path('/unused'),root,'qeynos2',{'port':12345,'instance':42},receipt)
                    self.assertIsNotNone(children[0].poll(), 'child leaked')
                    self.assertTrue(receipt.get('reaped'), 'child not reaped')
                finally:
                    for proc in children:
                        if proc.poll() is None:
                            proc.kill()
                        proc.wait(timeout=3)

    def test_native_auth_rejects_initial_and_switch_plugins(self):
        driver = p.load_driver()
        connection_class = getattr(p,'native_connection_class',lambda d:d.connections.Connection)(driver)
        conn = object.__new__(connection_class)
        conn._closed = True
        for name in ('caching_sha2_password','sha256_password','client_ed25519'):
            conn._auth_plugin_name = name
            with patch.object(driver.connections.Connection,'_request_authentication',return_value=None), self.assertRaises(p.Refusal):
                conn._request_authentication()
            with patch.object(driver.connections.Connection,'_process_auth',return_value=None), self.assertRaises(p.Refusal):
                conn._process_auth(name.encode(),None)

    def test_native_default_plus_zone_rules_and_absent_variable(self):
        defaults = [{'rule_name':k,'rule_value':v} for k,v in sorted({**p.RULES,'Instances:ReservedInstances':'100'}.items())]
        zone_rules = [{'rule_name':'Map:FindBestZHeightAdjust','rule_value':'1'}]
        def sha(rows):
            return p.hashlib.sha256(p.encoded(rows).encode()).hexdigest()
        for bad in (False,True,"event","other_zone_event"):
            with self.subTest(override_mismatch=bad):
                selected = copy.deepcopy(zone_rules)
                if bad is True:
                    selected[0]['rule_value'] = '20'
                store = object.__new__(p.Store)
                store.names = {'game':'game','content':'content'}
                store.contract = {'ruleset_id':1,'ruleset_name':'default','default_rule_rows_sha256':sha(defaults),
                  'zones':{z[0]:{'instance':90+n,'version':250+n,'spawn':1000+n,'group':1000+n,'ruleset_id':1+n,
                      'rule_rows_sha256':sha(defaults if n==0 else selected)} for n,z in enumerate(p.ZONES)}}
                if bad=='other_zone_event':store.contract['only_zone']='qeynos2'
                store.manifest = {'originals':{}}
                store.schema = MagicMock()
                store.timer_snapshot = MagicMock(return_value={'captured_unix':1,'rows':[]})
                def sql(query,args=()):
                    if 'GET_LOCK' in query:return [{'locked':1}]
                    if 'SELECT rule_name,rule_value' in query:
                        return defaults if args==(1,) else selected
                    if 'SELECT ruleset_id' in query:return [{'ruleset_id':1}]
                    return []
                def rows(role,table,where,args=()):
                    if table=='rule_sets':return [{'ruleset_id':1,'name':'default'}]
                    if table=='zone':return [{'zoneidnumber':args[0],'ruleset':1 if args[0]==2 else 2}]
                    if table=='npc_types':return [{'id':2011}]
                    if table=='spawn_events' and (bad=='event' or (bad=='other_zone_event' and args==('poknowledge',))):return [{'id':7}]
                    return []
                store.sql = MagicMock(side_effect=sql)
                store.rows = MagicMock(side_effect=rows)
                if bad:
                    with self.assertRaises(p.Refusal):store.preflight()
                else:
                    store.preflight()
                    self.assertEqual(store.manifest['zone_rules']['poknowledge']['effective_fixed'],p.RULES)
                self.assertFalse(any('INSERT' in call.args[0] for call in store.sql.call_args_list))

    def test_float_ownership_uses_locked_integer_identity(self):
        store = object.__new__(p.Store)
        store.names = {'content':'peq'}
        row = {'id':123,'x':263.037598,'y':214.493774,'name':'Private'}
        # Model the documented FLOAT-to-DOUBLE predicate mismatch. The returned
        # row is unchanged; only a predicate containing coordinates is unreliable.
        store.rows = MagicMock(side_effect=lambda role,table,where,args: [] if '`x`' in where else [dict(row)])
        store.db = MagicMock()
        store.db.cursor.return_value.__enter__.return_value.rowcount = 1
        store.delete_exact('content','spawn2',row)
        sql,args = store.db.cursor.return_value.__enter__.return_value.execute.call_args.args
        self.assertNotIn('`x`',sql)
        self.assertEqual(args,(123,))

    def test_collation_equivalent_changed_text_is_not_owned(self):
        store = object.__new__(p.Store)
        store.names = {'content':'peq'}
        store.db = MagicMock()
        store.db.cursor.return_value.__enter__.return_value.rowcount = 1
        original = {'id':123,'name':'Private'}
        for changed in ('PRIVATE','Private '):
            with self.subTest(changed=changed):
                store.rows = MagicMock(return_value=[{'id':123,'name':changed}])
                with self.assertRaises(p.Refusal):
                    store.delete_exact('content','spawngroup',original)
                store.db.cursor.assert_not_called()

    def test_cross_database_incoming_fk_refuses_before_writes(self):
        # Execute the actual predicate against harmless metadata-shaped rows.
        # The source schema is game.audit; its target is content.spawn2.
        db = sqlite3.connect(':memory:')
        db.execute('CREATE TABLE fks(CONSTRAINT_NAME TEXT,CONSTRAINT_SCHEMA TEXT,UNIQUE_CONSTRAINT_SCHEMA TEXT,TABLE_NAME TEXT,REFERENCED_TABLE_NAME TEXT)')
        db.execute("INSERT INTO fks VALUES('external','game','content','audit','spawn2')")
        store = object.__new__(p.Store)
        store.names = {'game':'game','content':'content'}
        store.db = MagicMock()
        store.manifest = {'schemas':{}}
        ddl = 'CREATE TABLE example(id INT) ENGINE=InnoDB'
        tables = {'game':('instance_list',*p.STATE,*p.PROTECTED,'rule_values','rule_sets','variables','spawn_events'),
                  'content':('spawn2','spawngroup','spawnentry','npc_types','zone')}
        sha = p.hashlib.sha256(ddl.encode()).hexdigest()
        store.contract = {'schemas':{r+'.'+t:sha for r,ts in tables.items() for t in ts}}
        def sql(query,args=()):
            if query.startswith('SHOW CREATE TABLE'):return [{'Table':'example','Create Table':ddl}]
            if 'REFERENTIAL_CONSTRAINTS' in query:
                query=query.replace('information_schema.REFERENTIAL_CONSTRAINTS','fks').replace('%s','?')
                return db.execute(query,args).fetchall()
            return []
        store.sql = MagicMock(side_effect=sql)
        try:
            with self.assertRaises(p.Refusal):store.schema()
            store.db.rollback.assert_not_called()
        finally:
            db.close()

    def test_timer_snapshot_never_clips_rows_or_bytes(self):
        store = object.__new__(p.Store)
        store.names = {'game':'peq'}
        for rows,ok in (([{'id':1,'instance_id':0,'expire_at':1}],True),
                        ([{'id':n} for n in range(p.TIMER_ROWS+1)],False),
                        ([{'id':1,'payload':'x'*(p.TIMER_BYTES+1)}],False)):
            store.sql = MagicMock(side_effect=[[{'captured_unix':123}],rows])
            if ok:
                snap=store.timer_snapshot()
                self.assertEqual(snap,{'captured_unix':123,'rows':rows})
            else:
                with self.assertRaises(p.Refusal):store.timer_snapshot()
            self.assertIn('LIMIT '+str(p.TIMER_ROWS+1),store.sql.call_args_list[1].args[0])

    def test_timer_after_failure_invalidates_pass_without_losing_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'run'
            config = Path(tmp)/'config.json'
            contract = Path(tmp)/'contract.json'
            config.write_text(json.dumps({'server':{'world':{'tcp':{'ip':'127.0.0.1','port':9001}}}}))
            contract.write_text(json.dumps({'world_pid':1,'assets':{'maps':'/maps'},'zones':{z[0]:{
                'version':250+n,'reference':str(HERE/'vendor/route.json'),'reference_sha256':p.ZONE_SHA,
                'reference_backend':'OFF','port':17901+n} for n,z in enumerate(p.ZONES)}}))
            store = MagicMock()
            store.manifest = {'respawn_timers_before':{'captured_unix':1,'rows':[]}}
            store.timer_snapshot.side_effect = OSError('private timer failure')
            def completed(*args,**kwargs):
                args[4]['reaped']=True
                return 'evidence'
            argv = ['probe','--config',str(config),'--contract',str(contract),'--root',str(root),'--zone-binary','/unused']
            with patch.object(sys,'argv',argv), patch.object(p,'validate_contract'), patch.object(p,'load_comparator'), patch.object(p,'digest',side_effect=[p.ZONE_SHA,p.WORLD_SHA,p.ZONE_SHA,p.ZONE_SHA]), patch.object(p,'runtime_inputs',return_value=[]), patch.object(p,'prepare_runtime'), patch.object(p,'Store',return_value=store), patch.object(p,'run_child',side_effect=completed) as launch, patch.object(p,'verify_evidence',return_value={}):
                self.assertEqual(p.main(),1)
            store.cleanup.assert_called_once()
            store.db.close.assert_called_once()
            self.assertEqual(launch.call_count,2)
            receipt=json.loads((root/'receipt.json').read_text())
            self.assertTrue(receipt['cleanup'])
            self.assertFalse(receipt['passed'])
            self.assertIn('housekeeping_snapshot_error',receipt)
            self.assertNotIn('private',json.dumps(receipt))

    def make_runtime_inputs(self, root, large=False):
        # Harmless byte fixtures test pin/copy semantics only, not native plugins.
        support=root/'support';support.mkdir()
        entries=[]
        for dest in sorted(p.SUPPORT_FILES):
            name=Path(dest).name;data=b'# CheckHandin harmless unit fixture\n'
            (support/name).write_bytes(data)
            entries.append({'destination':dest,'name':name,'bytes':len(data),'sha256':p.hashlib.sha256(data).hexdigest()})
        (support/'MANIFEST.json').write_text(json.dumps({'files':entries}))
        (root/'vendor').mkdir()
        (root/'vendor/runtime-support-pins.json').write_bytes((support/'MANIFEST.json').read_bytes())
        seeds=root/'seeds';seeds.mkdir();blobs={}
        for name in ('items','spells'):
            data=(b'x'*(5*1024*1024) if large and name=='items' else b'original '+name.encode())
            f=seeds/name;f.write_bytes(data);f.chmod(0o400)
            blobs[name]={'bytes':len(data),'sha256':p.digest(f)}
        return {'support_root':str(support),'support_manifest_sha256':p.digest(support/'MANIFEST.json'),
                'shared_blobs':blobs,'assets':{'shared_memory':str(seeds)}}

    def test_private_rw_shared_copy_matches_native_syscall_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);c=self.make_runtime_inputs(root,large=True)
            with patch.object(p,'HERE',root), patch.object(p,'SUPPORT_MANIFEST_SHA',c['support_manifest_sha256']):
                entries=p.runtime_inputs(c)
            private=root/'private';private.mkdir()
            for name in ('plugins','modules'):(private/name).mkdir()
            record={};p.prepare_runtime(private,c,entries,record)
            self.assertEqual({x['file'] for x in record['support']},p.SUPPORT_FILES)
            self.assertTrue(all((private/dest).is_file() for dest in p.SUPPORT_FILES))
            # Same O_RDWR/ftruncate/MAP_SHARED pattern as MemoryMappedFile(existing),
            # under the unchanged native 4MiB output-file limit. No Server binary.
            script='import os,resource,mmap,sys;resource.setrlimit(resource.RLIMIT_FSIZE,(4194304,4194304));f=os.open(sys.argv[1],os.O_RDWR);n=os.fstat(f).st_size;os.ftruncate(f,n);m=mmap.mmap(f,n,access=mmap.ACCESS_WRITE);m.close();os.close(f)'
            subprocess.run([sys.executable,'-I','-c',script,str(private/'shared/items')],check=True,timeout=5)
            p.release_shared_copy(record,c)
            self.assertFalse((private/'shared').exists())
            self.assertTrue(record['shared']['removed'])
            for name,spec in c['shared_blobs'].items():self.assertEqual(p.digest(Path(c['assets']['shared_memory'])/name),spec['sha256'])
            self.assertTrue((private/'plugins/check_handin.pl').exists())

    def test_changed_runtime_utility_refuses_before_db_or_native(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);c=self.make_runtime_inputs(root)
            (Path(c['support_root'])/'items.lua').write_text('unapproved replacement')
            with patch.object(p,'Store',side_effect=AssertionError('DB must not open')), patch.object(p,'run_child',side_effect=AssertionError('native must not start')):
                with patch.object(p,'HERE',root), patch.object(p,'SUPPORT_MANIFEST_SHA',c['support_manifest_sha256']):
                    with self.assertRaises(p.Refusal):p.runtime_inputs(c)

    def test_replaced_private_blob_is_retained_not_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);c=self.make_runtime_inputs(root)
            with patch.object(p,'HERE',root), patch.object(p,'SUPPORT_MANIFEST_SHA',c['support_manifest_sha256']):
                entries=p.runtime_inputs(c)
            private=root/'private';private.mkdir()
            for name in ('plugins','modules'):(private/name).mkdir()
            record={};p.prepare_runtime(private,c,entries,record)
            f=private/'shared/items';replacement=private/'replacement';replacement.write_bytes(b'changed owner')
            os.replace(replacement,f)
            with self.assertRaises(p.Refusal):p.release_shared_copy(record,c)
            self.assertTrue(f.exists())
            self.assertFalse(record['shared']['removed'])

    def test_identifier_rejects_sql(self):
        for value in ('a;b','`bad`','x.y',''):
            with self.assertRaises(p.Refusal):
                p.identifier(value)


class TiedPerlOutputTests(unittest.TestCase):
    """Real Perl I/O, with fake NPC methods only. No Server or DB execution."""
    TIES = r'''
package Capture;
our @seen;
sub TIEHANDLE { bless {},shift }
sub PRINT { my $self=shift;push @seen,join('',@_);1 }
package main;
tie *STDOUT,'Capture';tie *STDERR,'Capture';
'''

    def perl(self, code, cwd=None, stdout=subprocess.PIPE):
        return subprocess.run(['/usr/bin/perl','-'], input=code.encode(),
                              stdout=stdout, stderr=subprocess.PIPE, cwd=cwd, timeout=5)

    def test_both_generated_quests_emit_complete_records_with_tied_stdout(self):
        mocks = r'''
package FakeNPC;
sub new { bless {x=>0,y=>0,z=>0},shift }
sub GMMove { my $s=shift;@{$s}{qw(x y z)}=@_[0..2] }
sub MoveTo { my $s=shift;$s->GMMove(@_) }
sub GetX { $_[0]->{x} } sub GetY { $_[0]->{y} } sub GetZ { $_[0]->{z} }
sub GetSize { 6 } sub GetNPCTypeID { 2011 } sub GetID { 2 }
sub FindGroundZ { 0 } sub CheckLoSToLoc { 1 } sub IsMoving { 0 }
our $AUTOLOAD;sub AUTOLOAD { } sub DESTROY { }
package quest;
sub settimer { } sub stoptimer { } sub processmobswhilezoneempty { }
package main;
our $npc=FakeNPC->new;our $timer='server_collision';
'''
        for name in ('2011.pl','pok-2011.pl'):
            with self.subTest(quest=name), tempfile.TemporaryDirectory() as tmp:
                tail = r'''
EVENT_SPAWN();EVENT_TIMER();EVENT_TIMER();EVENT_TIMER();EVENT_TIMER();
open(my $stop,'>','stop-map-validation') or die 'stop control';close($stop);
EVENT_TIMER();die 'global ties removed' unless tied(*STDOUT) && tied(*STDERR);
'''
                result = self.perl(self.TIES+mocks+p.quest(HERE/'vendor'/name)+tail,cwd=tmp)
                self.assertEqual(result.returncode,0,result.stderr)
                lines = result.stdout.decode().splitlines()
                self.assertEqual(sum(s.startswith('SERVER_COLLISION_QUERY ') for s in lines),3)
                self.assertEqual(sum(s.startswith('SERVER_COLLISION_FLOOR ') for s in lines),3)
                self.assertEqual(lines.count('SERVER_COLLISION_QUERIES_DONE'),1)
                self.assertEqual(lines.count('SERVER_COLLISION_ROUTE_DONE'),1)
                self.assertEqual(lines.count('MAP_SERVER_PROBE_STOPPED'),1)

    def test_duplicate_close_leaves_original_fd_and_ties_usable(self):
        tail = r'''
probe_emit('PRIVATE_VISIBLE');close($probe_output) or die 'private close';
open(my $still,'>&',1) or die 'original descriptor closed';
syswrite($still,"ORIGINAL_STILL_OPEN\n")==20 or die 'original write';
print STDOUT "TIED_HIDDEN\n";
die 'tie changed' unless tied(*STDOUT) && tied(*STDERR) && $Capture::seen[-1] eq "TIED_HIDDEN\n";
'''
        result=self.perl(self.TIES+p.quest(HERE/'vendor/2011.pl')+tail)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,b'PRIVATE_VISIBLE\nORIGINAL_STILL_OPEN\n')

    def test_closed_output_and_oversize_are_sticky_failures(self):
        for fault in ('close($probe_output);', "eval { probe_emit('x' x 4096); };die 'overflow accepted' unless $@;"):
            tail=fault+r'''
eval { probe_emit('SERVER_COLLISION_ROUTE_DONE'); };die 'write accepted' unless $@;
open($probe_output,'>&',1) or die 'reopen control';
eval { probe_emit('SERVER_COLLISION_ROUTE_DONE'); };die 'failure not sticky' unless $@;
'''
            result=self.perl(self.TIES+p.quest(HERE/'vendor/2011.pl')+tail)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,b'')

    def test_open_short_write_and_broken_pipe_refuse(self):
        text=p.quest(HERE/'vendor/2011.pl')
        result=self.perl('use POSIX ();POSIX::close(1);'+self.TIES+text)
        self.assertNotEqual(result.returncode,0)
        result=self.perl('BEGIN { *CORE::GLOBAL::syswrite = sub { return 0; }; }'+self.TIES+text+r'''
eval { probe_emit('SERVER_COLLISION_ROUTE_DONE'); };die 'short write accepted' unless $@;
''')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,b'')
        read_fd,write_fd=os.pipe()
        os.close(read_fd)
        try:
            result=self.perl(self.TIES+text+r'''
eval { probe_emit('SERVER_COLLISION_ROUTE_DONE'); };die 'broken pipe accepted' unless $@;
''',stdout=write_fd)
        finally:
            os.close(write_fd)
        self.assertEqual(result.returncode,0,result.stderr)


if __name__ == '__main__':
    unittest.main()
