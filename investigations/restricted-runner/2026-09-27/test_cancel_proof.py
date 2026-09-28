import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('cancel_proof', Path(__file__).with_name('cancel_proof.py'))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
RUN = '0123456789'
UID = 997


def evidence():
    result = dict(run_id=RUN, owner_uid=UID, terminal=True, cleanup_complete=True,
                  accepted=False, diagnostic_only=True, diagnostic_complete=False)
    worker = dict(uuid='identity', ok=False, workload_ok=False, error='Controller interrupted',
                  scenario_events_untrusted=[dict(name='ready', value=dict(zone_connection=True))])
    suite = dict(suite_passed=False, error='Supervisor interrupted')
    cleanup = dict(complete=True, rescued=[], controller_budget={'memory.events': 'oom 0\noom_kill 0\n'})
    wc = dict(uuid='identity', **{key: True for key in ('complete', 'domain_absent', 'profile_absent',
              'slice_file_absent', 'cgroup_absent', 'data_absent', 'readonly_inputs_unchanged', 'artifact_input_unchanged')})
    return result, worker, suite, cleanup, wc


class CancellationProof(unittest.TestCase):
    def test_real_cancellation_shape_is_accepted_without_promoting_workload(self):
        result, worker, suite, cleanup, wc = evidence()
        P.check_cancel(result, worker, suite, cleanup, wc, RUN, UID)
        self.assertFalse(result['accepted'])
        self.assertFalse(suite['suite_passed'])

    def test_unrelated_failure_or_success_cannot_qualify(self):
        for target, key, value in [(0, 'owner_uid', 123), (0, 'diagnostic_complete', True),
                                   (1, 'error', 'Unexpected crash'), (1, 'guest_report_untrusted', {'ok': True}),
                                   (2, 'error', 'Timed out'), (3, 'rescued', ['consumer']),
                                   (4, 'uuid', 'other'), (4, 'data_absent', False)]:
            values = evidence()
            values[target][key] = value
            with self.subTest(target=target, key=key), self.assertRaises(RuntimeError):
                P.check_cancel(*values, RUN, UID)

    def test_cancel_happens_only_after_ready_then_receipts_verified(self):
        final, worker, suite, cleanup, wc = evidence()
        records = {'worker.json': worker, 'suite.json': suite, 'cleanup.json': cleanup, 'worker-cleanup.json': wc}
        calls = []
        def request(op, **fields):
            calls.append(op)
            if op == 'run': return dict(started=True, run_id=RUN)
            if op == 'status': return dict(run_id=RUN, owner_uid=UID, terminal=False)
            return final
        with patch.object(P, 'request', side_effect=request), \
             patch.object(P, 'read_report', side_effect=lambda root, name: (records[name], 'hash')):
            result = P.prove(UID, lambda: False, lambda _: None)
        self.assertTrue(result['cancellation_checks_passed'])
        self.assertEqual(calls, ['run', 'status', 'cancel'])
        self.assertIn('ready', result)

    def test_failed_cancel_request_gets_one_cleanup_attempt_without_a_pass(self):
        final, worker, _, _, _ = evidence()
        calls = []
        def request(op, **fields):
            calls.append(op)
            if op == 'run': return dict(started=True, run_id=RUN)
            if op == 'status': return dict(run_id=RUN, owner_uid=UID, terminal=False)
            if calls.count('cancel') == 1: raise RuntimeError('Request busy')
            return final
        with patch.object(P, 'request', side_effect=request), \
             patch.object(P, 'read_report', return_value=(worker, 'hash')):
            result = P.prove(UID, lambda: False, lambda _: None)
        self.assertFalse(result['cancellation_checks_passed'])
        self.assertEqual(calls, ['run', 'status', 'cancel', 'cancel'])
        self.assertEqual(result['error'], 'Request busy')

    def test_early_terminal_result_is_not_a_cancellation_pass(self):
        calls = []
        def request(op, **fields):
            calls.append(op)
            return dict(started=True, run_id=RUN) if op == 'run' else dict(run_id=RUN, owner_uid=UID, terminal=True)
        with patch.object(P, 'request', side_effect=request):
            result = P.prove(UID, lambda: False, lambda _: None)
        self.assertFalse(result['cancellation_checks_passed'])
        self.assertEqual(calls, ['run', 'status', 'cancel'])

    def test_interrupted_driver_still_cancels_its_admitted_run(self):
        calls = []
        def request(op, **fields):
            calls.append(op)
            return dict(started=True, run_id=RUN)
        with patch.object(P, 'request', side_effect=request):
            result = P.prove(UID, lambda: True, lambda _: None)
        self.assertFalse(result['cancellation_checks_passed'])
        self.assertEqual(calls, ['run', 'cancel'])


if __name__ == '__main__':
    unittest.main()
