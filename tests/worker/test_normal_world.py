"""Trusted Python/fake server controls only; no candidate binaries or VM launched."""
import contextlib
import io
import itertools
import json
import sqlite3
import types
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'validation/worker'))
import normal_world as normal
import guest
import staging


def baseline():
    return dict(exit_code=0, cleanup_complete=True, control=None, ready_seconds=1.0,
                baseline_seconds=5.1, responsive_samples=40, cpu_ticks=[1, 4], clock_ticks_per_second=100,
                fixture_manifest_sha256='a'*64, binaries={n: 'b'*64 for n in ('world', 'zone', 'shared_memory')},
                database_cleanup=True)


class Completion(unittest.TestCase):
    def test_success_requires_independent_observation_and_complete_cleanup(self):
        self.assertEqual(normal.validate(baseline()), baseline())
        for field, value in [('exit_code', True), ('control', 'assertion'), ('control', 'startup'),
                             ('control', 'cancel'), ('cleanup_complete', False), ('database_cleanup', False),
                             ('ready_seconds', float('nan')), ('baseline_seconds', 4.9),
                             ('responsive_samples', 0), ('cpu_ticks', [1, 0]), ('cpu_ticks', [0, True]),
                             ('binaries', {}), ('fixture_manifest_sha256', 'unknown')]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                normal.validate(dict(baseline(), **{field: value}))
        for field in baseline():
            changed = baseline(); del changed[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                normal.validate(changed)

    def test_seed_and_staging_include_every_guest_helper(self):
        config = json.loads(guest.build_user_data('a'*32).split('\n', 1)[1])
        files = {item['path']: item for item in config['write_files']}
        for name in ('normal_world.py', 'actor.py', 'actor_runtime.py', 'debugger.py', 'runtime-fixture.json'):
            self.assertIn('/opt/' + name, files)
        self.assertIn('normal-world', guest.BUILD_CHECKS)
        for name in ('validation/worker/normal_world.py', 'validation/actor_runtime.py', 'validation/runtime-fixture.json'):
            self.assertIn(name, staging.FILES)


class ActivityConfiguration(unittest.TestCase):
    def test_run_configures_native_zone_row_before_boot_and_refuses_bad_state(self):
        # Execute the production SQL against a small relational fixture, not a
        # mock returning the exact string the implementation wants to see.
        cases = ('valid', 'missing', 'wrong-id', 'wrong-version', 'wrong-name', 'duplicate',
                 'null-readback', 'ignored-write', 'write-error', 'missing-column')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp, sqlite3.connect(':memory:') as db:
                columns = 'zoneidnumber INTEGER, version INTEGER, short_name TEXT'
                if case != 'missing-column':
                    columns += ', idle_when_empty INTEGER, seconds_before_idle INTEGER'
                db.execute('CREATE TABLE zone (' + columns + ')')
                row = (203 if case == 'wrong-id' else 202, 1 if case == 'wrong-version' else 0,
                       'other' if case == 'wrong-name' else 'poknowledge', 1, 60)
                if case == 'missing-column':
                    row = row[:3]
                if case != 'missing':
                    db.execute('INSERT INTO zone VALUES (' + ','.join('?' for _ in row) + ')', row)
                if case == 'duplicate':
                    db.execute("INSERT INTO zone VALUES (202,0,'poknowledge',1,60)")
                # An unrelated version must never be modified.
                if case != 'missing-column':
                    db.execute("INSERT INTO zone VALUES (202,2,'poknowledge',1,90)")
                runtime = Mock()
                def query(label, sql):
                    if label == 'normal-activity':
                        if case == 'write-error':
                            raise RuntimeError('write refused')
                        if case in ('ignored-write', 'null-readback'):
                            if case == 'null-readback':
                                db.execute('UPDATE zone SET idle_when_empty=NULL')
                            return ''
                    cursor = db.execute(sql)
                    return '\n'.join('\t'.join('NULL' if v is None else str(v) for v in r) for r in cursor.fetchall())
                runtime.query.side_effect = query
                runtime.configure.side_effect = RuntimeError('configuration reached after readback')
                runtime.cleanup.return_value = True
                runtime.scrub.side_effect = str
                fake = types.SimpleNamespace(Runtime=Mock(return_value=runtime),
                    ROOT=Path(tmp)/'runtime', MEDIA=Path(tmp)/'media')
                build = Mock(DEADLINE=normal.time.monotonic()+10000, WORK=Path(tmp)/'build')
                with patch.dict(sys.modules, actor_runtime=fake), \
                        patch.object(normal.os, 'geteuid', return_value=0), \
                        patch.object(normal.Path, 'is_file', return_value=True), \
                        patch.object(normal.Path, 'read_text', return_value='{}'):
                    with self.assertRaises(RuntimeError):
                        normal.run(build, {})
                runtime.initialize_database.assert_called_once()
                runtime.import_database.assert_called_once()
                runtime.cleanup.assert_called_once()
                self.assertEqual(runtime.configure.call_count, int(case == 'valid'))
                # Neither shared_memory nor the observer/native children can run
                # after a refused write/readback. Mounting is the sole command.
                self.assertEqual([c.args[0] for c in runtime.command.call_args_list], ['normal-mount-runtime'])
                build.emit.assert_not_called()
                if case == 'valid':
                    self.assertEqual(db.execute('SELECT idle_when_empty,seconds_before_idle FROM zone ORDER BY version').fetchall(),
                                     [(0, 60), (1, 90)])


class Readiness(unittest.TestCase):
    def test_udp_socket_or_wrong_session_is_not_application_readiness(self):
        stream = Mock()
        stream.__enter__ = Mock(return_value=stream); stream.__exit__ = Mock(return_value=False)
        challenge = b'abcd'
        for response, expected in [(b'', False), (b'\x00\x02xxxx', False), (b'\x00\x01abcd', False),
                                   (b'\x00\x02abcd', True)]:
            with self.subTest(response=response), patch.object(normal.os, 'urandom', return_value=challenge), \
                    patch.object(normal.socket, 'socket', return_value=stream):
                stream.recv.return_value = response
                self.assertIs(normal.probe(), expected)
        with patch.object(normal.socket, 'socket', return_value=stream):
            stream.recv.side_effect = TimeoutError
            self.assertFalse(normal.probe())

    def test_established_connection_must_belong_to_both_owned_native_pids(self):
        rows = ('header\n0: 0100007F:C001 0100007F:2328 01 0 0 0 0 0 11\n'
                '1: 0100007F:2328 0100007F:C001 01 0 0 0 0 0 22\n')
        with patch.object(normal.Path, 'read_text', return_value=rows), \
                patch.object(normal, 'socket_inodes', side_effect=[{'22'}, {'11'}]):
            self.assertTrue(normal.world_connected(1, 2))
        with patch.object(normal.Path, 'read_text', return_value=rows), \
                patch.object(normal, 'socket_inodes', side_effect=[{'99'}, {'11'}]):
            self.assertFalse(normal.world_connected(1, 2))


    def test_cleanup_checks_descendants_and_forced_rescue_is_not_success(self):
        process = Mock(pid=101)
        with patch.object(normal, 'owned_members', return_value=[]), patch.object(normal.os, 'kill') as kill:
            self.assertTrue(normal.stop([process]))
            kill.assert_not_called()
        with patch.object(normal, 'owned_members', return_value=[101, 102]), \
                patch.object(normal.os, 'kill') as kill, \
                patch.object(normal.time, 'monotonic', side_effect=itertools.count(0, 20)), \
                patch.object(normal.time, 'sleep'):
            self.assertFalse(normal.stop([process]))
            self.assertTrue(any(call.args[0] == 102 for call in kill.call_args_list))
            self.assertTrue(any(call.args[1] == normal.signal.SIGKILL for call in kill.call_args_list))

    def run_observer(self, control=None, died=False, interrupt=False):
        with tempfile.TemporaryDirectory() as tmp:
            server = Path(tmp)
            world, zone = Mock(pid=101), Mock(pid=102)
            world.poll.return_value = 1 if died else None
            zone.poll.return_value = None
            output = io.StringIO()
            probes = [True, RuntimeError('cancelled')] if interrupt else None
            with patch.object(normal.os, 'geteuid', return_value=65534), \
                    patch.object(normal.resource, 'setrlimit'), patch.object(normal.Path, 'is_file', return_value=True), \
                    patch.object(normal.subprocess, 'Popen', side_effect=[world, zone]) as launch, \
                    patch.object(normal, 'world_connected', return_value=True), \
                    patch.object(normal, 'probe', side_effect=probes, return_value=True), \
                    patch.object(normal, 'cpu_ticks', side_effect=[0, 0, 1, 4]), \
                    patch.object(normal, 'stop', return_value=True) as stop, \
                    patch.object(normal.time, 'monotonic', side_effect=itertools.count(0, .1)), \
                    patch.object(normal.time, 'sleep'), contextlib.redirect_stdout(output):
                normal.observe(Path('/never-execute-candidate'), server, control)
                stop.assert_called_once_with([world, zone])
                for call in launch.call_args_list:
                    self.assertNotIn('start_new_session', call.kwargs)
            lines = output.getvalue().splitlines()
            frames = [json.loads(line.removeprefix('NORMAL_WORLD_RESULT ')) for line in lines
                      if line.startswith('NORMAL_WORLD_RESULT ')]
            self.assertEqual(len(frames), 1)
            return frames[0]

    def test_positive_and_assertion_startup_and_interruption_are_nonpass_with_cleanup(self):
        self.assertEqual(self.run_observer()['exit_code'], 0)
        self.assertEqual(self.run_observer('assertion')['exit_code'], 1)
        for value in (self.run_observer('startup', died=True), self.run_observer('cancel', interrupt=True)):
            self.assertEqual(value['exit_code'], 2)
            self.assertTrue(value['cleanup_complete'])


if __name__ == '__main__':
    unittest.main()
