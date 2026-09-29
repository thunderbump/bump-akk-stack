"""Public command checks. Set AFK_CHECKOUT to include the real AFK seam."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
COMMAND = HERE.parents[1] / 'scripts/validate'
RUN_ID = '0123456789'


class CommandTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='eqemu-command-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.report = self.root / RUN_ID
        self.report.mkdir()
        (self.report / 'worker.json').write_text(json.dumps({
            'error': 'Synthetic actionable DB warning',
            'guest_report_untrusted': {'first_failure': None}}))
        (self.report / 'diagnostics.jsonl').write_text('Synthetic bounded diagnostic excerpt\n')

    def argv(self, case):
        (self.root / 'case').write_text(case)
        return [sys.executable, '-B', str(HERE / 'fixture.py'), 'launch', str(self.root)]

    def check_result(self, result, expected=2):
        self.assertEqual(result.returncode, expected, result.stderr)
        self.assertLess(len((result.stdout + result.stderr).encode()), 128 * 1024)
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(events[-1]['event'], 'final')
        self.assertIs(events[-1]['accepted'], False)
        return events[-1]

    def run_case(self, case):
        return subprocess.run(self.argv(case), text=True, capture_output=True, timeout=8)

    def test_default_refuses_without_runner(self):
        result = subprocess.run([str(COMMAND)], text=True, capture_output=True, timeout=3)
        self.assertIsNone(self.check_result(result)['run_id'])
        self.assertFalse((self.root / 'calls').exists())

    def test_completed_diagnostic_contains_context_but_never_passes(self):
        result = self.run_case('normal')
        final = self.check_result(result)
        self.assertTrue(final['cleanup_complete'])
        self.assertIsNone(final['candidate_revision'])
        self.assertIn('Synthetic actionable DB warning', result.stdout)
        self.assertIn('Synthetic bounded diagnostic excerpt', result.stdout)
        self.assertEqual((self.root / 'calls').read_text().splitlines(), ['run', 'status'])

    def test_refusal_preserves_reason_and_unknown_cleanup(self):
        final = self.check_result(self.run_case('refused'))
        self.assertIn('disk reserve', final['reason'])
        self.assertIsNone(final['cleanup_complete'])

    def test_invalid_reports_cancel_only_owned_run(self):
        for case in ('invalid', 'false-acceptance', 'request-error'):
            with self.subTest(case=case):
                final = self.check_result(self.run_case(case))
                self.assertTrue(final['cleanup_complete'])
                self.assertEqual((self.root / 'calls').read_text().splitlines()[-1], 'cancel')
                self.assertNotEqual(final['reason'], 'Synthetic database warning')

    def test_cleanup_failure_preserves_first_error(self):
        final = self.check_result(self.run_case('cancel-error'))
        self.assertIn('status unavailable', final['reason'])
        self.assertIn('cancel unavailable', final['secondary_error'])
        self.assertIsNone(final['cleanup_complete'])
        final = self.check_result(self.run_case('cleanup-incomplete'))
        self.assertFalse(final['cleanup_complete'])

    def test_missing_or_nonregular_diagnostics_never_pass(self):
        path = self.report / 'diagnostics.jsonl'
        path.unlink()
        final = self.check_result(self.run_case('normal'))
        self.assertIn('Diagnostic capture failed', final['secondary_error'])
        self.assertEqual(final['reason'], 'Synthetic database warning')
        os.mkfifo(path)
        final = self.check_result(self.run_case('normal'))
        self.assertIn('regular file', final['secondary_error'])

    def test_output_is_bounded(self):
        (self.report / 'diagnostics.jsonl').write_bytes(b'\x00' * (1024 * 1024))
        self.check_result(self.run_case('normal'))

    def test_internal_deadline_cancels(self):
        final = self.check_result(self.run_case('deadline'))
        self.assertIn('deadline', final['reason'])
        self.assertTrue(final['cleanup_complete'])

    def test_process_group_interruption_preserves_inflight_request_and_cancels(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig):
                marker = self.root / 'in-request'
                marker.unlink(missing_ok=True)
                process = subprocess.Popen(self.argv('interrupt'), stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True, start_new_session=True)
                try:
                    deadline = time.monotonic() + 3
                    while not marker.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(marker.exists())
                    os.killpg(process.pid, sig)
                    stdout, stderr = process.communicate(timeout=5)
                    result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
                    final = self.check_result(result, 128 + sig)
                    self.assertTrue(final['cleanup_complete'])
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()

    @unittest.skipUnless(os.environ.get('AFK_CHECKOUT'), 'Set AFK_CHECKOUT for actual AFK integration')
    def test_real_afk_capture_and_repair_policy(self):
        afk = Path(os.environ['AFK_CHECKOUT'])
        sys.path.insert(0, str(afk))
        self.addCleanup(sys.path.remove, str(afk))
        from afk_validate.evidence import validate_repairable_failure
        workspace = self.root / 'workspace'
        workspace.mkdir()
        for args in [('init', '-q'), ('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid',
                                     'commit', '--allow-empty', '-qm', 'Synthetic clean workspace')]:
            subprocess.run(['git', '-C', str(workspace), *args], check=True, capture_output=True)
        for case in ('normal', 'refused', 'invalid', 'cancel-error', 'timeout'):
            with self.subTest(case=case):
                policy = dict(schema_version=1, workspace=str(workspace), command=self.argv('interrupt' if case == 'timeout' else case),
                              timeout_seconds=1 if case == 'timeout' else 15, termination_grace_seconds=5, repairable_exit_codes=[1])
                path = self.root / 'input.json'
                path.write_text(json.dumps(policy))
                output = self.root / ('afk-' + case)
                result = subprocess.run([sys.executable, '-B', '-m', 'afk_validate', str(path), str(output)],
                                        cwd=afk, text=True, capture_output=True, timeout=20)
                self.assertNotEqual(result.returncode, 0)
                sealed = json.loads((output / 'output.json').read_text())
                self.assertEqual(sealed['outcome'], 'timed_out' if case == 'timeout' else 'failed')
                self.assertEqual(sealed['process']['exit_code'], 143 if case == 'timeout' else 2)
                if case == 'timeout':
                    final = json.loads((output / 'stdout.log').read_text().splitlines()[-1])
                    self.assertTrue(final['cleanup_complete'])
                self.assertIn('"event": "final"', (output / 'stdout.log').read_text())
                with self.assertRaises(ValueError):
                    validate_repairable_failure(output, workspace, expected_policy=policy)


if __name__ == '__main__':
    unittest.main()
