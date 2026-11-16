"""Harmless host tests. No native Server, DB, container, SSH, or scheduler."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
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
            self.assertIn('print STDOUT', text)
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
        # This Python fixture is the only process launched by this suite.
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
            contract.write_text(json.dumps({'world_pid':1,'zones':{z[0]:{
                'reference':str(HERE/'vendor/route.json'),'reference_sha256':p.ZONE_SHA,
                'reference_backend':'OFF','port':17901+n} for n,z in enumerate(p.ZONES)}}))
            store = MagicMock()
            store.manifest = {}
            store.bootstrap.side_effect = RuntimeError('sensitive database password')
            argv = ['probe','--config',str(config),'--contract',str(contract),'--root',str(root),'--zone-binary','/unused']
            with patch.object(sys,'argv',argv), patch.object(p,'validate_contract'), patch.object(p,'load_comparator'), patch.object(p,'digest',side_effect=[p.ZONE_SHA,p.WORLD_SHA,p.ZONE_SHA,p.ZONE_SHA]), patch.object(p,'Store',return_value=store), patch.object(p,'run_child') as launch:
                self.assertEqual(p.main(),1)
            store.db.rollback.assert_called_once()
            store.db.commit.assert_not_called()
            launch.assert_not_called()
            receipt = json.loads((root/'receipt.json').read_text())
            self.assertFalse(receipt['passed'])
            self.assertTrue(receipt['cleanup'])
            self.assertNotIn('sensitive',json.dumps(receipt))

    def test_identifier_rejects_sql(self):
        for value in ('a;b','`bad`','x.y',''):
            with self.assertRaises(p.Refusal):
                p.identifier(value)


if __name__ == '__main__':
    unittest.main()
