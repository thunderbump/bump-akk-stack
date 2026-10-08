"""Real GDB against a trusted tiny fixture, not acquired game binaries."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'validation'))
import debugger


@unittest.skipUnless(shutil.which('gcc') and Path('/usr/bin/gdb').is_file(), 'needs gcc and gdb')
class Debugger(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.addClassCleanup(cls.temp.cleanup)
        source = cls.root/'crash.c'
        source.write_text('''#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
static void inherited_handler(int signal) { puts("UNBOUNDED_HANDLER_ENTERED"); sleep(90); }
__attribute__((noinline)) static void fail(const char *private_argument) {
    volatile int *p = 0;
    *p = 1;
}
int main(int argc, char **argv) {
    signal(SIGSEGV, inherited_handler);
    if (argc > 1 && !strcmp(argv[1], "pass")) return 0;
    if (argc > 1 && !strcmp(argv[1], "assertion")) return 1;
    if (argc > 1 && !strcmp(argv[1], "wait")) {
        printf("PID %d\\n", getpid()); fflush(stdout); sleep(90); return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "child")) {
        int child = fork();
        if (!child) { sleep(90); return 0; }
        printf("PID %d\\n", child); fflush(stdout); sleep(90); return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "flood")) { for (;;) puts("overflow"); }
    if (argc > 1 && !strcmp(argv[1], "redaction")) puts("known-guest-credential");
    fail("PRIVATE_ARGUMENT_SENTINEL");
}
''')
        cls.binary = cls.root/'crash'
        subprocess.run(['gcc', '-g', '-O0', '-Wl,--build-id', '-o', str(cls.binary), str(source)],
                       check=True, timeout=30)
        cls.digest = hashlib.sha256(cls.binary.read_bytes()).hexdigest()

    def capture(self, mode='crash', seconds=5, **kwargs):
        return debugger.capture([str(self.binary), mode], self.root,
                                {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
                                ['known-guest-credential'], self.digest,
                                time.monotonic()+seconds, **kwargs)

    def test_crash_trace_has_function_file_line_and_identity_without_private_values(self):
        text = self.capture()
        self.assertIn('EQEMU_CRASH_TRACE signal SIGSEGV', text)
        self.assertRegex(text, r'fail at .+crash.c:\d+')
        self.assertIn(self.digest, text)
        self.assertNotIn('PRIVATE_ARGUMENT_SENTINEL', text)
        self.assertNotIn('UNBOUNDED_HANDLER_ENTERED', text)
        self.assertNotEqual(text.find('debugger exit 2'), -1)
        self.assertFalse(list(self.root.glob('core*')))

    def test_positive_and_assertion_replay_preserve_noncrash_exits(self):
        self.assertIn('debugger exit 0', self.capture('pass'))
        self.assertIn('debugger exit 1', self.capture('assertion'))

    def test_timeout_cancellation_and_overflow_are_explicit_and_bounded(self):
        start = time.monotonic()
        for mode in ('wait', 'child'):
            text = self.capture(mode, seconds=.4)
            self.assertIn('replay timeout', text)
            self.assertLess(time.monotonic()-start, 3)
            import re
            pid = int(re.search(r'PID (\d+)', text)[1])
            path = Path('/proc')/str(pid)/'stat'
            for _ in range(50):
                if not path.exists() or path.read_text().rsplit(')',1)[1].split()[0] == 'Z': break
                time.sleep(.02)
            else: self.fail('Debugger inferior survived timeout')
        self.assertIn('skipped', self.capture(cancelled=lambda: True))
        end = time.monotonic()+.3
        self.assertIn('replay cancelled', self.capture('wait', cancelled=lambda: time.monotonic() >= end))
        text = self.capture('flood')
        self.assertIn('replay truncated', text)
        self.assertLess(len(text.encode()), 3000)

    def test_init_and_executable_auto_load_are_disabled(self):
        marker = self.root/'UNTRUSTED_SCRIPT_RAN'
        command = 'shell touch '+str(marker)+'\n'
        (self.root/'.gdbinit').write_text(command)
        Path(str(self.binary)+'-gdb.gdb').write_text(command)
        self.assertIn('signal SIGSEGV', self.capture())
        self.assertFalse(marker.exists())

    def test_changed_binary_refuses_before_execution_and_redaction_is_total(self):
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            debugger.capture([str(self.binary)], self.root, {}, [], '0'*64, time.monotonic()+5)
        text = self.capture('redaction')
        self.assertNotIn('known-guest-credential', text)
        self.assertEqual(debugger.scrub('known-guest-credential\x1b', ['known-guest-credential']), '[redacted]?')


if __name__ == '__main__':
    unittest.main()
