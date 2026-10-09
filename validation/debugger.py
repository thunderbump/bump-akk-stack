"""Bounded diagnostic replay inside a disposable guest, never acceptance evidence."""
import hashlib
import os
from pathlib import Path
import resource
import selectors
import signal
import subprocess
import time

SCRIPT = Path(__file__).with_name('debugger-gdb.py')
SECONDS = 30
OUTPUT_BYTES = 128 * 1024
PUBLIC_BYTES = 2400


def scrub(text, secrets):
    for secret in secrets:
        if secret:
            text = text.replace(secret, '[redacted]')
    return ''.join(c if c in '\n\t' or ord(c) >= 32 and not 127 <= ord(c) <= 159 else '?' for c in text)


def capture(args, cwd, env, secrets, expected_sha256, deadline, cancelled=lambda: False, guard=lambda: None):
    """Replay the same executable with a fixed debugger; preserve the triggering failure.

    The caller owns fixture state. Replay can change disposable state and never
    substitutes for the original scenario result. No core or arbitrary GDB command.
    """
    start = time.monotonic()
    guard()
    end = min(deadline, start + SECONDS)
    binary = Path(args[0])
    with binary.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != expected_sha256 or binary.is_symlink():
        raise ValueError('Diagnostic executable identity changed')
    if end <= start or cancelled():
        return 'Debugger capture skipped: deadline or cancellation'
    # -iex runs before executable loading, so even executable auto-load scripts
    # are disabled. The explicitly sealed Python command file is our only script.
    command = ['/usr/bin/gdb', '--batch', '--nx', '--quiet', '--return-child-result',
               '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
               '-iex', 'set print frame-arguments none', '-iex', 'set print frame-info location',
               '-x', str(SCRIPT), '--args', *args]
    def no_core():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    proc = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            start_new_session=True, preexec_fn=no_core)
    output = bytearray()
    state = 'complete'
    try:
        os.set_blocking(proc.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            eof = False
            while not eof or proc.poll() is None:
                guard()
                if cancelled():
                    state = 'cancelled'; break
                if time.monotonic() >= end:
                    state = 'timeout'; break
                for key, _ in selector.select(.1):
                    block = os.read(key.fd, 16384)
                    if not block:
                        eof = True; selector.unregister(key.fileobj); continue
                    remaining = OUTPUT_BYTES - len(output)
                    output.extend(block[:remaining])
                    if len(block) > remaining:
                        state = 'truncated'; break
                if state != 'complete':
                    break
        if state == 'complete':
            proc.wait(timeout=2)
    finally:
        # GDB and its inferior share this owned session. Reap both even on error.
        try: os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        proc.wait(timeout=5)
        proc.stdout.close()
    text = scrub(output.decode(errors='replace'), secrets)
    # Keep the trace first. Later inferior chatter must not displace useful frames.
    marker = text.find('EQEMU_CRASH_TRACE ')
    if marker >= 0:
        text = text[marker:]
    encoded = text.encode()
    if len(encoded) > PUBLIC_BYTES:
        text = encoded[:PUBLIC_BYTES-30].decode('utf-8', 'ignore')+'\n[public trace truncated]'
    return ('Debugger replay '+state+'; debugger exit '+str(proc.returncode)
            +'; executable sha256 '+digest+'\n'+text)


def inventory(command):
    """Verify tools actually present in this runtime, including embedded GDB Python."""
    versions = {}
    for name in ('gdb', 'addr2line', 'readelf'):
        versions[name] = command('actor-debugger-'+name, ['/usr/bin/'+name, '--version']).splitlines()[0]
    value = command('actor-debugger-python', ['/usr/bin/gdb', '--batch', '--nx',
                    '-iex', 'set auto-load off', '-iex', 'set debuginfod enabled off',
                    '-ex', 'python print("EQEMU_GDB_PYTHON_OK")'])
    if 'EQEMU_GDB_PYTHON_OK' not in value.splitlines():
        raise RuntimeError('GDB Python unavailable')
    return versions
