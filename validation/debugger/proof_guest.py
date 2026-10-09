"""Trusted tiny offline provisioning proof; no EQEmu source build or world startup."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path('/opt/eqemu-proof')
sys.path.insert(0, str(ROOT))


def proof():
    if os.geteuid() != 0 or not (ROOT/'BUILD_GUEST_ONLY').is_file():
        raise RuntimeError('Proof is guest-only')
    if sorted(p.name for p in Path('/sys/class/net').iterdir()) != ['lo']:
        raise RuntimeError('Guest has unexpected NIC')
    spec = importlib.util.spec_from_file_location('build', ROOT/'guest_build.py')
    build = importlib.util.module_from_spec(spec); spec.loader.exec_module(build)
    build.DEADLINE = time.monotonic()+1200
    build.EMIT = lambda _: None
    build.emit = lambda _: None
    build.WORK.mkdir(); build.LOGS.mkdir()
    build.MEDIA.mkdir()
    build.command('mount-build', ['mount', '-o', 'ro,nosuid,nodev,noexec',
                                '/dev/disk/by-label/EQEMUBUILD', str(build.MEDIA)])
    build.verify_inputs(); build.apt_preflight()
    # Mount and use the exact same runtime verifier/installer as fresh consumers.
    import actor_runtime
    import debugger
    actor_runtime.ROOT.mkdir()
    actor_runtime.MEDIA.mkdir()
    fixture = json.loads((ROOT/'runtime-fixture.json').read_text())
    runtime = actor_runtime.Runtime(build, None, fixture)
    runtime.command('actor-mount-input', ['mount', '-o', 'ro,nosuid,nodev,noexec',
                    '/dev/disk/by-label/EQEMURUNTIME', str(actor_runtime.MEDIA)])
    runtime.verify_inputs(); package_plan = runtime.install_packages()
    versions = runtime.debugger_versions
    wanted = ['gdb', 'libc6', 'libc6-dbg', 'libstdc++6', 'libstdc++6-14-dbg']
    installed = runtime.command('debugger-matching-symbols', ['dpkg-query', '-W',
                                '-f=${Package}\t${Version}\n', *wanted])
    identities = dict(line.split('\t') for line in installed.splitlines())
    if (identities['libc6'] != identities['libc6-dbg']
            or identities['libstdc++6'] != identities['libstdc++6-14-dbg']):
        raise RuntimeError('System debug package mismatch')
    source = build.WORK/'trace-fixture.c'
    source.write_text('''#include <signal.h>
#include <unistd.h>
static void legacy(int number) { sleep(90); }
__attribute__((noinline)) static void proof_crash(const char *secret) {
    volatile int *p=0; *p=1;
}
int main(void) { signal(SIGSEGV,legacy); proof_crash("PRIVATE_ARGUMENT_SENTINEL"); }
''')
    binary = build.WORK/'trace-fixture'
    build.command('compile-trace-fixture', ['gcc', '-g', '-O0', '-Wl,--build-id',
                  '-o', str(binary), str(source)], timeout=60)
    digest = build.sha(binary)
    elf = runtime.command('fixture-elf', ['readelf', '-W', '-n', '-S', '-s', str(binary)])
    build_ids = re.findall(r'Build ID: ([a-f0-9]+)', elf)
    address = re.search(r'\d+: ([a-f0-9]+)\s+\d+ FUNC\s+LOCAL\s+DEFAULT\s+\d+ proof_crash', elf)
    if len(build_ids) != 1 or '.debug_info' not in elf or address is None:
        raise RuntimeError('Fixture lacks exact identity/symbols')
    location = runtime.command('fixture-addr2line', ['addr2line', '-f', '-e', str(binary), address[1]])
    if 'proof_crash' not in location or 'trace-fixture.c:' not in location:
        raise RuntimeError('Source symbolization failed')
    trace = debugger.capture([str(binary)], build.WORK, build.ENV, [], digest, runtime.deadline)
    if ('EQEMU_CRASH_TRACE signal SIGSEGV' not in trace or 'proof_crash at ' not in trace
            or 'trace-fixture.c:' not in trace or 'PRIVATE_ARGUMENT_SENTINEL' in trace
            or 'debugger exit 2' not in trace):
        raise RuntimeError('Crash trace proof failed')
    # These controls compile only their own tiny trusted C fixture.
    result = subprocess.run(['python3', '-B', str(ROOT/'test_debugger.py')],
                            capture_output=True, text=True, timeout=60, env=build.ENV)
    if result.returncode != 0 or 'Ran 5 tests' not in result.stderr or 'skipped' in result.stderr:
        raise RuntimeError('Debugger controls failed: '+result.stderr[-2000:])
    if list(build.WORK.glob('core*')):
        raise RuntimeError('Unexpected core retention')
    runtime.verify_inputs()
    return dict(schema=1, kind='debugger-provisioning-trial', ok=True,
                checks={name: True for name in ('guest_root','no_virtual_nic','approved_inputs',
                    'runtime_install','matching_debug_packages','gdb_python','source_trace',
                    'no_private_values','bounded_controls','no_cores')},
                versions=versions, package_identities=identities, package_plan_sha256=package_plan,
                fixture_manifest_sha256=fixture['manifest_sha256'], fixture_binary_sha256=digest,
                fixture_build_id=build_ids[0], trace=trace)


if __name__ == '__main__':
    try:
        value = proof()
    except Exception as error:
        value = dict(schema=1, kind='debugger-provisioning-trial', ok=False, error=str(error)[-3000:])
    # Serial output is just a bounded scrubbed proof. Disks are removed by the controller.
    data = ('\nEQEMU_TRIAL_RESULT '+json.dumps(value)+'\n').encode()
    with open('/dev/ttyS0', 'wb', buffering=0) as serial:
        serial.write(data)
    subprocess.run(['systemctl', 'poweroff'], check=False, timeout=20)
