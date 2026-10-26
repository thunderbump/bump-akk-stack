"""Bounded advisory diagnostics; trusted Python fakes only, never candidate execution."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'validation/worker'))
import normal_world as normal


def event(kind, name='case', run='a'*32, **extra):
    return dict(version=1, run_id=run, event=kind, name=name, elapsed_ms=23, **extra)


def lines(*events):
    return b'\n'.join(b'EQEMU_INSERVER_PROGRESS '+json.dumps(value).encode() for value in events)


def failure(head='a'*40):
    return dict(exit_code=1, candidate=head, run_id='b'*32, cleanup_complete=True,
        guest=dict(normal_world=dict(exit_code=1, cleanup_complete=True,
            failure_evidence=dict(version=1, run_id='c'*32, observation=dict(condition='udp-timeout',
                last_success_ms=5001, source_port=40001, discarded_allocations=1),
                console={'zone': 'useful-native-detail\n'*300},
                console_truncated={'zone': False}, progress=dict(active_case=event('case-start'),
                    last_completed_case=event('case-end', passed=True, diagnostic=''), rejected_events=0)))))


class SourceDiagnostics(unittest.TestCase):
    def snapshot(self, root, zone, world=b'world console\n'):
        logs = [root/name for name in ('world-console.log', 'zone-console.log')]
        for path, data in zip(logs, (world, zone)):
            path.write_bytes(data)
        processes = [Mock(pid=2000000000, poll=Mock(return_value=None)),
                     Mock(pid=2000000001, poll=Mock(return_value=1))]
        return normal.failure_snapshot(processes, logs, 'a'*32, time.monotonic(),
                                       dict(condition='udp-timeout', last_success_ms=5000))

    def test_latest_context_and_stack_survive_large_later_console_independently(self):
        data = (b'EQEMU_NATIVE_DIAGNOSTIC_CONTEXT old\n'
                b'EQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN\nold frame\nEQEMU_NATIVE_DIAGNOSTIC_STACK_END\n'
                b'EQEMU_NATIVE_DIAGNOSTIC_CONTEXT result=failed original reason\n'
                b'EQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN\n#0 native_function\nEQEMU_NATIVE_DIAGNOSTIC_STACK_END\n'
                b'EQEMU_NATIVE_DIAGNOSTIC_CONTEXT latest context\n' + b'later console\n'*11000)
        with tempfile.TemporaryDirectory() as tmp:
            evidence = self.snapshot(Path(tmp), data)
        source = evidence['source_diagnostics']
        self.assertEqual(source, dict(advisory=True, context='latest context',
            stack='#0 native_function\n', stack_complete=True, stack_truncated=False))
        self.assertNotIn('native_function', evidence['console']['zone-console.log'])
        self.assertTrue(evidence['console_truncated']['zone-console.log'])
        self.assertEqual(evidence['run_id'], 'a'*32)
        self.assertEqual([p['pid'] for p in evidence['processes']], [2000000000, 2000000001])
        self.assertFalse(evidence['stack_capture']['captured'])
        self.assertLessEqual(len(normal.encoded(evidence)), 12000)

    def test_missing_end_latest_start_and_exact_marker_lines(self):
        cases = [
            (b'EQEMU_NATIVE_DIAGNOSTIC_CONTEXT context only\n', dict(advisory=True, context='context only')),
            (b'EQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN\nframe\nEQEMU_NATIVE_DIAGNOSTIC_STACK_END\n',
             dict(advisory=True, stack='frame\n', stack_complete=True, stack_truncated=False)),
            (b'EQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN\nold\nEQEMU_NATIVE_DIAGNOSTIC_STACK_END\n'
             b'EQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN\nnew\n',
             dict(advisory=True, stack='new\n', stack_complete=False, stack_truncated=False)),
            (b'EQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN\r\nframe\r\nEQEMU_NATIVE_DIAGNOSTIC_STACK_END\r\n',
             dict(advisory=True, stack='frame\n', stack_complete=True, stack_truncated=False)),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            for data, expected in cases:
                with self.subTest(data=data):
                    self.assertEqual(self.snapshot(Path(tmp), data)['source_diagnostics'], expected)
            unrelated = (b'prefix EQEMU_NATIVE_DIAGNOSTIC_CONTEXT ignore\n'
                         b'EQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN extra\n'
                         b'EQEMU_NATIVE_DIAGNOSTIC_STACK_END\nDIAG_QEYNOS_SCENARIO_RESULT passed\n')
            self.assertNotIn('source_diagnostics', self.snapshot(Path(tmp), unrelated))
            # Identical markers in another owned console are not zone diagnostics.
            self.assertNotIn('source_diagnostics', self.snapshot(Path(tmp), b'ordinary zone', cases[0][0]))

    def test_noisy_and_incomplete_stacks_bound_frames_raw_bytes_and_encoded_json(self):
        cases = (b'x'*20000, b'frame\n'*10000, ('\x00\ufffd\U0001f600\\\"'*2000).encode())
        with tempfile.TemporaryDirectory() as tmp:
            for frames in cases:
                for end in (b'', b'\nEQEMU_NATIVE_DIAGNOSTIC_STACK_END\n'):
                    with self.subTest(frames=frames[:30], complete=bool(end)):
                        evidence = self.snapshot(Path(tmp),
                            b'EQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN\n'+frames+end)
                        source = evidence['source_diagnostics']
                        self.assertEqual(source['stack_complete'], bool(end))
                        self.assertTrue(source['stack_truncated'])
                        self.assertLessEqual(len(source['stack'].splitlines()), 32)
                        self.assertLessEqual(len(normal.encoded(source['stack'])), 3000)
                        self.assertLessEqual(len(normal.encoded(evidence)), 12000)

    def test_hostile_json_escaping_retains_diagnostics_without_exhausting_snapshot(self):
        hostile = ('\x00\x01\ufffd\U0001f600\\\"'*3000).encode()
        progress = lines(event('case-start', name='\x00'*64),
                         event('case-end', name='\x00'*64, passed=True, diagnostic='\x00'*256),
                         event('case-start', name='\ufffd'*64))
        data = (progress + b'\nEQEMU_NATIVE_DIAGNOSTIC_CONTEXT ' + hostile +
                b'\nEQEMU_NATIVE_DIAGNOSTIC_STACK_BEGIN\n' + hostile +
                b'\nEQEMU_NATIVE_DIAGNOSTIC_STACK_END\n' + hostile)
        with tempfile.TemporaryDirectory() as tmp:
            evidence = self.snapshot(Path(tmp), data, hostile)
        source = evidence['source_diagnostics']
        self.assertTrue(source['stack'])
        self.assertTrue(source['context'])
        self.assertLessEqual(len(normal.encoded(source['context'])), 500)
        self.assertLessEqual(len(normal.encoded(source['stack'])), 3000)
        self.assertLessEqual(len(normal.encoded(evidence)), 12000)
        self.assertEqual(evidence['progress']['last_completed_case']['diagnostic'], '\x00'*256)

    def test_source_text_cannot_set_completion_or_verdict_fields(self):
        text = b'{"passed":true,"finalized":true,"completed":32,"exit_code":0}'
        with tempfile.TemporaryDirectory() as tmp:
            evidence = self.snapshot(Path(tmp), b'EQEMU_NATIVE_DIAGNOSTIC_CONTEXT '+text+b'\n')
        self.assertEqual(evidence['source_diagnostics'], dict(advisory=True, context=text.decode()))
        self.assertIsNone(evidence['progress']['active_case'])
        for validate in (normal.validate, normal.validate_inserver):
            with self.assertRaises(ValueError):
                validate(evidence['source_diagnostics'])

    def test_snapshot_refuses_symlink_fifo_and_oversized_console(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root/'outside'
            outside.write_bytes(b'EQEMU_NATIVE_DIAGNOSTIC_CONTEXT private\n')
            path = root/'zone-console.log'
            path.symlink_to(outside)
            for kind in ('symlink', 'fifo', 'oversize'):
                if kind != 'symlink':
                    path.unlink()
                    if kind == 'fifo':
                        os.mkfifo(path)
                    else:
                        path.write_bytes(outside.read_bytes() + b'x'*1024**2)
                with self.subTest(kind=kind):
                    evidence = normal.failure_snapshot([], [path], 'a'*32, time.monotonic(), {})
                    self.assertNotIn('source_diagnostics', evidence)
                    self.assertTrue(evidence['console'][path.name].startswith('unavailable:'))
                    self.assertNotIn('private', evidence['console'][path.name])
                    self.assertLessEqual(len(normal.encoded(evidence)), 12000)


class Progress(unittest.TestCase):
    def test_completed_then_interrupted_case_and_bad_events_are_advisory(self):
        progress = normal.case_progress(lines(event('case-start'),
            event('case-end', passed=True, diagnostic=''), event('case-start', 'hung'),
            event('case-end', 'stale', run='b'*32, passed=True, diagnostic=''))+
            b'\nEQEMU_INSERVER_PROGRESS {bad\n', 'a'*32)
        self.assertEqual(progress['active_case']['name'], 'hung')
        self.assertEqual(progress['last_completed_case']['name'], 'case')
        self.assertEqual(progress['rejected_events'], 2)
        self.assertIsNone(normal.case_progress(b'', 'a'*32)['active_case'])
        replacement = event('case-end', passed=False, diagnostic='\n'*255+'\ufffd')
        self.assertEqual(normal.case_progress(lines(event('case-start'), replacement), 'a'*32)
                         ['last_completed_case'], replacement)
        # Even convincing progress cannot substitute for final acceptance.
        with self.assertRaises(ValueError):
            normal.validate(dict(exit_code=0, failure_evidence=progress))

    def test_error_metadata_counts_json_escaping(self):
        text = normal.bounded_json_text('native error '+('\x00\ufffd'*1000), 500)
        self.assertLessEqual(len(normal.encoded(text)), 500)
        self.assertTrue(text)

    def test_udp_failure_conditions_are_distinct_without_retrying(self):
        for response, condition in ((TimeoutError(), 'udp-timeout'),
                                    (ConnectionRefusedError(), 'udp-refused'),
                                    (b'wrong', 'udp-malformed-reply')):
            stream = Mock()
            stream.__enter__ = Mock(return_value=stream)
            stream.__exit__ = Mock(return_value=False)
            stream.getsockname.return_value = ('127.0.0.1', 40000)
            if isinstance(response, Exception): stream.recv.side_effect = response
            else: stream.recv.return_value = response
            observed = {}
            with self.subTest(condition=condition), patch.object(normal.socket, 'socket', return_value=stream):
                self.assertIs(normal.probe(diagnostics=observed), False)
                self.assertEqual(observed['condition'], condition)
                stream.send.assert_called_once()
                stream.recv.assert_called_once()

    def test_console_links_and_pipes_are_not_opened_or_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outside = root/'outside'; outside.write_text('private')
            link = root/'link'; link.symlink_to(outside)
            fifo = root/'fifo'; os.mkfifo(fifo)
            for path in (link, fifo):
                with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                    normal.console_bytes(path)


class Export(unittest.TestCase):
    def test_private_bounded_artifact_manifest_and_small_public_summary(self):
        for noisy in (False, True):
            with self.subTest(noisy=noisy), tempfile.TemporaryDirectory() as tmp:
                report = failure()
                if noisy:
                    report['guest']['normal_world']['failure_evidence']['console']['zone'] = '\x00\ufffd'*20000
                before = json.dumps(report)
                path = normal.export_evidence(report, 'a'*40, tmp)
                raw = path.read_bytes()
                self.assertLessEqual(len(raw), 16384)
                self.assertGreater(len(raw), 3000)
                record = json.loads(raw)
                self.assertEqual(record['head'], 'a'*40)
                self.assertEqual(record['worker_run_id'], 'b'*32)
                self.assertTrue(record['advisory'])
                self.assertEqual(record['normal_world']['failure_evidence']['observation'],
                    report['guest']['normal_world']['failure_evidence']['observation'])
                self.assertEqual(record['truncated'], noisy)
                self.assertEqual(json.dumps(report), before)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads((Path(tmp)/'diagnostic-files.json').read_text()),
                    dict(schema_version=1, head='a'*40, files=[path.name],
                         sha256={path.name: hashlib.sha256(raw).hexdigest()}))
                public = (Path(tmp)/'public-summary.json').read_text()
                self.assertNotIn('useful-native-detail', public)
                self.assertIn('native-udp-timeout', public)
                self.assertLess(len(public), 500)

    def test_success_retains_source_measurements_without_changing_outcome(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = dict(exit_code=0, candidate='a'*40, run_id='b'*32, cleanup_complete=True,
                guest=dict(normal_world=dict(exit_code=0, cleanup_complete=True, database_cleanup=True,
                    inserver_tests=dict(run_id='c'*32, tests=[dict(name='source.case', passed=True,
                        diagnostic='metrics1 xy=.25 z=.12 terminal_ms=33 drift=.01')]))))
            before = json.dumps(report)
            path = normal.export_evidence(report, 'a'*40, tmp)
            record = json.loads(path.read_text())
            self.assertEqual(path.name, 'normal-world-success.json')
            self.assertEqual(record['exit_code'], 0)
            self.assertIs(record['vm_cleanup_complete'], True)
            self.assertEqual(record['normal_world'], report['guest']['normal_world'])
            self.assertEqual(json.dumps(report), before)
            self.assertLessEqual(path.stat().st_size, 16384)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            public = json.loads((Path(tmp)/'public-summary.json').read_text())
            self.assertEqual(public['status'], 'passed')
            self.assertEqual(public['diagnostic_codes'], [])
            self.assertNotIn('metrics1', json.dumps(public))
            manifest = json.loads((Path(tmp)/'diagnostic-files.json').read_text())
            self.assertEqual(manifest['sha256'][path.name], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_frontend_exports_success_and_failure_without_rewriting_worker_result(self):
        root = Path(__file__).resolve().parents[2]
        loader = importlib.machinery.SourceFileLoader('evidence_candidate_cli', str(root/'scripts/validate-worker-candidate'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cli)
        for code in (0, 1, 2):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                config = directory/'config.json'; config.write_text('{"socket":"fake"}')
                report = failure(); report['exit_code'] = code
                report['guest']['normal_world']['exit_code'] = code
                if code == 0:
                    report['guest']['normal_world'].pop('failure_evidence')
                before = json.dumps(report)
                readiness = dict(exit_code=0, observed=dict(resources={'memory.max': str(6*1024**3)}))
                with patch.object(sys, 'argv', ['validate-worker-candidate', '--config', str(config)]), \
                        patch.dict(os.environ, {'VALIDATION_AFK_EVIDENCE_DIR': str(directory/'evidence')}), \
                        patch.object(cli, 'exchange', side_effect=[readiness, report]), \
                        patch.object(cli, 'prepare', return_value={'candidate': 'a'*40}), \
                        patch('builtins.print'):
                    self.assertEqual(cli.main(), code)
                exported = report.pop('diagnostic_artifact')
                self.assertEqual(json.dumps(report), before)
                self.assertTrue(Path(exported).is_file())
                self.assertEqual(json.loads(Path(exported).read_text())['exit_code'], code)

    def test_missing_wrong_identity_and_existing_symlink_never_export_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(normal.export_evidence(dict(exit_code=0), 'a'*40, tmp))
            self.assertIsNone(normal.export_evidence(dict(exit_code=1, candidate='a'*40, run_id='b'*32), 'a'*40, tmp))
            with self.assertRaises(ValueError):
                normal.export_evidence(failure(), 'd'*40, tmp)
            outside = Path(tmp)/'outside'; outside.write_text('untouched')
            (Path(tmp)/'normal-world-failure.json').symlink_to(outside)
            with self.assertRaises(FileExistsError):
                normal.export_evidence(failure(), 'a'*40, tmp)
            self.assertEqual(outside.read_text(), 'untouched')


if __name__ == '__main__':
    unittest.main()
