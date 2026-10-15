"""Execute symbol filtering with large/failing fake nm streams, never a native candidate."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'validation'))
import rust_guest
import test_reporting_coverage as reporting


class NativeSymbols(unittest.TestCase):
    def inspect(self, mode):
        root = Path(self.temporary.name)/mode; root.mkdir()
        binary = root/'zone'; binary.write_bytes(b'identified native binary fixture')
        tool = root/'nm tool; not shell code'
        tool.write_text('#!'+sys.executable+'\n'+'''import os,sys,time
mode=os.environ['SYMBOL_CONTROL']
marker=b'0000000000000001 T eqemu_rust_bridge_v1\\n'
if mode in ('early','failure','timeout'):
    sys.stdout.buffer.write(marker);sys.stdout.buffer.flush()
if mode == 'timeout':time.sleep(30)
if mode == 'failure':raise SystemExit(7)
if mode in ('early','late'):
    row=b'0000000000000002 t unrelated_'+b'x'*1024+b'\\n'
    for _ in range(10000):sys.stdout.buffer.write(row)
if mode == 'late':sys.stdout.buffer.write(marker)
if mode == 'local':sys.stdout.buffer.write(marker.replace(b' T ',b' t '))
if mode == 'wrong-type':sys.stdout.buffer.write(marker.replace(b' T ',b' D '))
if mode == 'missing':sys.stdout.buffer.write(marker.replace(b'bridge_v1',b'bridge_v10'))
''')
        tool.chmod(0o700)
        guest = reporting.recipe('producer-guest.py')
        guest.LOGS = root/'logs'; guest.LOGS.mkdir()
        guest.DEADLINE = time.monotonic()+10
        guest.ENV = dict(os.environ, SYMBOL_CONTROL=mode)
        self.events = []; self.log = guest.LOGS/'rust-native-symbols.log'
        def command(stage, args, **options):
            self.assertEqual(options['timeout'], 30)
            self.assertLessEqual(options['cap'], 8*1024**2)
            args = list(args)
            # Replace only the fixed tool executable, keeping the real pipeline/supervisor.
            index = args.index('/usr/bin/nm'); args[index] = str(tool)
            if mode == 'timeout':options['timeout'] = 0.2
            return guest.command(stage, args, **options)
        with patch.object(rust_guest, 'guard'), patch.object(rust_guest, 'verify_protected'):
            rust_guest.native_link({'link_symbol':'eqemu_rust_bridge_v1'}, binary,
                                   command, self.events.append, root, {})
        return hashlib.sha256(binary.read_bytes()).hexdigest()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def test_large_early_and_late_symbols_complete_with_bounded_retained_output(self):
        for mode in ('early','late','local'):
            with self.subTest(mode=mode):
                expected = self.inspect(mode)
                self.assertEqual(self.events[0]['name'], 'rust-native-link')
                self.assertEqual(self.events[0]['value']['binary_sha256'], expected)
                self.assertLess(self.log.stat().st_size, 1024)

    def test_missing_prefix_only_or_data_symbols_are_evidenced_policy_failures(self):
        for mode in ('missing','wrong-type','empty'):
            with self.subTest(mode=mode), self.assertRaisesRegex(RuntimeError, 'missing required symbol'):
                self.inspect(mode)
            self.assertEqual(self.events[0]['name'], 'rust-failure')
            self.assertEqual(self.events[0]['value']['tool_exit_code'], 0)
            self.assertEqual(self.events[0]['value']['finding'], 'link')

    def test_nm_failure_or_timeout_after_a_marker_never_emits_link_evidence(self):
        for mode, error in (('failure','exit 7'), ('timeout','deadline exceeded')):
            with self.subTest(mode=mode), self.assertRaisesRegex(RuntimeError, error):
                self.inspect(mode)
            self.assertEqual(self.events, [])


if __name__ == '__main__':unittest.main()
