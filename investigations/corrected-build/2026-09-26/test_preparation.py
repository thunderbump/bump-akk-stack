"""Small contract checks. No candidate code, package, VM, or guest filesystem runs here."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE))
from outcomes import control_result


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


LOCAL = Path('/home/bump/.local/state/eqemu-vm-proof/corrected-build-inputs-01')
W = load('prepared_worker', LOCAL/'build-worker.py')
G = load('prepared_guest', LOCAL/'guest.py')
NONCE = '1'*32
PASS = {'version': 1, 'selected': 3, 'started': 3, 'completed': 3,
        'failed': 0, 'finalized': True, 'passed': True}


class Outcomes(unittest.TestCase):
    def test_failed_assertion_and_crash_cannot_be_positive(self):
        output = 'EQEMU_TEST_RESULT ' + json.dumps(PASS)
        for rc in [1, -11]:
            with self.assertRaises(ValueError): G.utility_result(output, rc)
        failed = dict(PASS, failed=1)
        with self.assertRaises(ValueError): G.utility_result('EQEMU_TEST_RESULT '+json.dumps(failed), 0)

    def test_empty_incomplete_and_duplicate_completion_rejected(self):
        for result in [dict(PASS, selected=0), dict(PASS, completed=2), dict(PASS, finalized=False)]:
            with self.assertRaises(ValueError): G.utility_result('EQEMU_TEST_RESULT '+json.dumps(result), 0)
        output = 'EQEMU_TEST_RESULT '+json.dumps(PASS)
        for text in ['', output+'\n'+output, output.replace('"version": 1', '"version":1,"version":1')]:
            with self.assertRaises(ValueError): G.utility_result(text, 0)

    def test_negative_requires_exact_cause_and_exit(self):
        failed = dict(PASS, selected=1, started=1, completed=1, failed=1, passed=False)
        output = 'EQEMU_TEST_RESULT '+json.dumps(failed)
        self.assertEqual(control_result(output, 1, 'fail')['exit_code'], 1)
        for rc in [0, -11, 2]:
            with self.assertRaises(ValueError): control_result(output, rc, 'fail')
        with self.assertRaises(ValueError): control_result(output, 1, 'setup-exception')

    def test_command_checks_actual_process_exit_and_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            G.LOGS = Path(directory); G.DEADLINE = time.monotonic()+10
            G.command('expected', [sys.executable, '-c', 'raise SystemExit(1)'], expected_exit=1)
            with self.assertRaisesRegex(RuntimeError, 'exit 0'):
                G.command('wrong', [sys.executable, '-c', 'pass'], expected_exit=1)
            with self.assertRaisesRegex(RuntimeError, 'deadline'):
                G.command('timeout', [sys.executable, '-c', 'import time; time.sleep(60)'], timeout=.1)

    def test_malformed_completion_preserves_stage_and_bounded_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'runner-fail.log'
            path.write_text('x'*6000+'\nEQEMU_TEST_RESULT {broken}\x1b')
            with self.assertRaises(RuntimeError) as error:
                G.completed_output(path, control_result, 1, 'fail')
            message = str(error.exception)
            self.assertIn('runner-fail', message)
            self.assertIn('EQEMU_TEST_RESULT {broken}', message)
            self.assertNotIn('\x1b', message)
            self.assertLess(len(message.encode()), 3600)

    def test_control_fields_have_strict_types(self):
        record = dict(PASS, selected=True, started=1, completed=1)
        with self.assertRaises(ValueError): control_result('EQEMU_TEST_RESULT '+json.dumps(record), 0, 'pass')


class Protocol(unittest.TestCase):
    def ready(self):
        protocol = W.BuildProtocol(NONCE)
        protocol.accept({'kind':'ready','nonce':None,'manifest_sha256':W.MANIFEST_SHA,
                         'experiment_sha256':W.EXPERIMENT_SHA})
        return protocol

    def test_generated_domain_meets_actual_admission_rule(self):
        self.assertRegex(W.NAME, r'^[a-z0-9-]{1,20}$')

    def test_wrong_recipe_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'recipe'):
            W.BuildProtocol(NONCE).accept({'kind':'ready','nonce':None,
                'manifest_sha256':W.MANIFEST_SHA,'experiment_sha256':'0'*64})

    def test_legacy_success_cannot_pass(self):
        with self.assertRaisesRegex(RuntimeError, 'Incomplete corrected'):
            self.ready().accept({'kind':'result','nonce':NONCE,'ok':True})

    def test_observation_cannot_choose_host_action(self):
        for name, value in [('run', {'cmd':'anything'}), ('candidate', {})]:
            with self.assertRaises(RuntimeError):
                self.ready().accept({'kind':'observation','nonce':NONCE,'name':name,'value':value})

    def test_completion_wrong_nonce_and_duplicate_rejected(self):
        record = {'kind':'observation','nonce':NONCE,'name':'utility','value':PASS}
        protocol = self.ready(); protocol.accept(record)
        with self.assertRaises(RuntimeError): protocol.accept(record)
        with self.assertRaises(RuntimeError): self.ready().accept(dict(record, nonce='2'*32))

    def test_failed_guest_result_retained_without_success_evidence(self):
        protocol = self.ready()
        protocol.accept({'kind':'result','nonce':NONCE,'ok':False,'error':'control did not match'})
        self.assertFalse(protocol.result['ok'])


if __name__ == '__main__': unittest.main()
