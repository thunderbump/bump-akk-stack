"""Bounded advisory diagnostics; trusted Python fakes only, never candidate execution."""
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
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
                last_success_ms=5001), console={'zone': 'useful-native-detail\n'*300},
                console_truncated={'zone': False}, progress=dict(active_case=event('case-start'),
                    last_completed_case=event('case-end', passed=True, diagnostic=''), rejected_events=0)))))


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
