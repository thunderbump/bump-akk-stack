"""Execute generated cloud-init shell with trusted fixture commands, never a VM."""
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'validation/worker'))
import guest


class Launcher(unittest.TestCase):
    def test_abrupt_python_exit_reports_infrastructure_and_requests_poweroff(self):
        self.run_launcher('import os,signal; os.write(1,b"partial package output"); os.kill(os.getpid(),signal.SIGKILL)', 2)

    def test_nonzero_exit_after_partial_line_keeps_result_framing(self):
        self.run_launcher('import sys; sys.stdout.write("partial diagnostic"); raise SystemExit(3)', 2)

    def test_existing_results_are_not_duplicated_or_reclassified(self):
        for code in (0, 1, 2):
            with self.subTest(code=code):
                result = dict(version=1, nonce='a'*32, scope='worker-build', exit_code=code,
                              stage='rust-tests', selected_checks=list(guest.BUILD_CHECKS), completed_checks=[])
                self.run_launcher('print(' + repr('EQEMU_WORKER_RESULT '+json.dumps(result)) + ')', code)

    def test_serial_getty_is_stopped_before_python_opens_its_console(self):
        result = dict(version=1, nonce='a'*32, scope='worker-build', exit_code=0,
                      selected_checks=list(guest.BUILD_CHECKS), completed_checks=[])
        fixture = ('from pathlib import Path; '
                   'assert Path(__file__).with_name("getty-stopped").read_text().strip() '
                   '== "mask --runtime --now serial-getty@ttyS0.service"; '
                   'print(' + repr('EQEMU_WORKER_RESULT '+json.dumps(result)) + ')')
        self.run_launcher(fixture, 0)

    def test_getty_stop_failure_refuses_before_running_python(self):
        config = json.loads(guest.build_user_data('a'*32).split('\n', 1)[1])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); marker = root / 'python-ran'
            script = config['runcmd'][0][2].replace('/usr/bin/systemctl', '/bin/false').replace(
                '/usr/bin/python3 -u /opt/eqemu-worker-build-guest', '/usr/bin/touch ' + shlex.quote(str(marker))).replace(
                '/dev/ttyS0', shlex.quote(str(root / 'console'))).replace('/usr/sbin/poweroff', '/bin/true')
            result = subprocess.run(['/bin/sh', '-c', script], timeout=3, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(marker.exists())

    def test_startup_traceback_reports_infrastructure_and_requests_poweroff(self):
        self.run_launcher('raise RuntimeError("trusted startup failure")', 2)

    def run_launcher(self, fixture, expected):
        config = json.loads(guest.build_user_data('a'*32).split('\n', 1)[1])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            python = root / 'fixture.py'; python.write_text(fixture)
            console = root / 'console.log'; poweroff = root / 'poweroff'
            poweroff.write_text('#!/bin/sh\ntouch ' + shlex.quote(str(root / 'powered-off')) + '\n')
            poweroff.chmod(0o700)
            systemctl = root / 'systemctl'
            systemctl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > '
                                 + shlex.quote(str(root / 'getty-stopped')) + '\n')
            systemctl.chmod(0o700)
            script = config['runcmd'][0][2].replace(
                '/usr/bin/python3 -u /opt/eqemu-worker-build-guest',
                shlex.quote(sys.executable) + ' -u ' + shlex.quote(str(python))).replace(
                '/dev/ttyS0', shlex.quote(str(console))).replace(
                '/usr/sbin/poweroff', shlex.quote(str(poweroff))).replace(
                '/usr/bin/systemctl', shlex.quote(str(systemctl)))
            subprocess.run(['/bin/sh', '-c', script], timeout=3, check=False)
            lines = [line for line in console.read_text().splitlines() if line.startswith('EQEMU_WORKER_RESULT ')]
            self.assertEqual(len(lines), 1, console.read_text())
            result = json.loads(lines[0].removeprefix('EQEMU_WORKER_RESULT '))
            self.assertEqual(result['exit_code'], expected)
            self.assertEqual(result['nonce'], 'a'*32)
            self.assertEqual(result['selected_checks'], list(guest.BUILD_CHECKS))
            self.assertTrue((root / 'powered-off').exists())
