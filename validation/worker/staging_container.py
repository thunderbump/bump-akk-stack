"""Fixed commands inside the pinned guest-only builder container, never on the host."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import tarfile
import time

from staging_release import binding, canonical, contract, sha

ROOT = Path('/opt/eqemu-build')
TARGETS = ('world', 'zone', 'shared_memory', 'eqlaunch', 'ucs', 'queryserv')
PERL = '/opt/eqemu-perl/lib/5.32.1/x86_64-linux-thread-multi/CORE'
CHECKS = ('rust-format', 'rust-dependencies', 'rust-clippy', 'rust-tests', 'rust-doctests',
          'native-configure', 'native-build', 'artifact-checks')
RESULT = {'checks': {}, 'failed_check': None, 'failed_exit_code': None}


class CommandFailure(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__('release-command-failed')


def run(args, *, log=None, seconds=900, cwd=None):
    """Drain bounded command output, then reap the owned command group even on failure."""
    process = subprocess.Popen(args, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    try:
        raw = bytearray(); deadline = time.monotonic() + seconds
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                if time.monotonic() >= deadline: raise TimeoutError('release-command-timeout')
                for key, _ in selector.select(.1):
                    block = os.read(key.fd, 65536)
                    if not block: selector.unregister(key.fileobj); continue
                    raw.extend(block)
                    if len(raw) > 8 * 1024**2: raise ValueError('release-command-output-limit')
        process.wait(timeout=10)
        if log:
            with Path(log).open('ab') as stream:
                if stream.tell() + len(raw) > 2 * 1024**2: raise ValueError('release-log-limit')
                stream.write(raw)
        if process.returncode: raise CommandFailure(process.returncode)
        return bytes(raw)
    finally:
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait(timeout=10)
        process.stdout.close()


def check(name, args, **kwargs):
    RESULT['failed_check'] = name
    run(args, **kwargs)
    RESULT['checks'][name] = 0
    RESULT['failed_check'] = None


def readelf_facts(text):
    """Parse fixed readelf -h/-l/-d/-V/--dyn-syms output; unresolved facts refuse."""
    if 'ELF64' not in text or 'Advanced Micro Devices X86-64' not in text:
        raise ValueError('release-architecture')
    needed = re.findall(r'\(NEEDED\).*?\[(.*?)\]', text)
    paths = re.findall(r'\((?:RUNPATH|RPATH)\).*?\[(.*?)\]', text)
    versions = {}; provider = None; in_needs = False
    for line in text.splitlines():
        if line.startswith('Version needs section'): in_needs = True
        elif line.startswith('Version ') and 'needs section' not in line: in_needs = False
        if not in_needs: continue
        found = re.search(r'File: (\S+)\s+Cnt:', line)
        if found: provider = found.group(1); versions.setdefault(provider, [])
        found = re.search(r'Name: (\S+)\s+Flags:', line)
        if found and provider: versions[provider].append(found.group(1))
    undefined = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].rstrip(':').isdigit() and fields[4] == 'GLOBAL' and fields[6] == 'UND':
            undefined.append(fields[7].split('@')[0])
    interpreter = re.findall(r'Requesting program interpreter: ([^\]]+)\]', text)
    return dict(needed=needed, runpath=paths, version_needs=versions, undefined=undefined, interpreter=interpreter)


def check_abi(facts, inventory):
    if facts['interpreter'] != ['/lib64/ld-linux-x86-64.so.2']:
        raise ValueError('release-interpreter')
    libraries = inventory['runtime_libraries']
    providers = {}
    symbols = set()
    for path, entry in libraries.items():
        for name in (*entry['elf']['soname'], Path(path).name, '/' + path): providers[name] = entry
        symbols.update(entry['elf']['defined_dynamic_symbols'])
    if not facts['needed'] or any(name not in providers for name in facts['needed']):
        raise ValueError('release-needed-library')
    allowed = {PERL, '/usr/lib/x86_64-linux-gnu', '/lib/x86_64-linux-gnu', '/usr/local/lib'}
    if any(part not in allowed for row in facts['runpath'] for part in row.split(':')):
        raise ValueError('release-rpath')
    for name, versions in facts['version_needs'].items():
        if name not in providers or not set(versions) <= set(providers[name]['elf']['version_definitions']):
            raise ValueError('release-symbol-version')
    if not set(facts['undefined']) <= symbols:
        raise ValueError('release-unresolved-symbol')


def check_configuration(cache, commands):
    if ('CMAKE_BUILD_TYPE:STRING=RelWithDebInfo' not in cache.splitlines()
            or not all('EQEMU_BUILD_' + name + ':BOOL=ON' in cache.splitlines() for name in ('LUA', 'PERL'))
            or '-fsanitize' in cache or '-fsanitize' in json.dumps(commands)):
        raise ValueError('release-native-flags')
    population = [entry for entry in commands if entry.get('file', '').endswith('/zone/actor_population.cpp')]
    if not population or any('-DEQEMU_RUST_BOOTSTRAP_BRIDGE' not in (entry.get('arguments') or shlex.split(entry['command'])) for entry in population):
        raise ValueError('release-native-rust-feature')


def make_tar(directory, destination, fixed):
    from release_artifacts import file_caps, validate_tar
    caps = file_caps()
    if {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()} != set(caps) - {'MANIFEST.json', 'SHA256SUMS'}:
        raise ValueError('release-output-inventory')
    records = {name: dict(bytes=(directory / name).stat().st_size, sha256=sha(directory / name))
               for name in sorted(caps) if name not in ('MANIFEST.json', 'SHA256SUMS')}
    (directory / 'MANIFEST.json').write_bytes(canonical(dict(binding=fixed, files=records)))
    names = sorted(set(caps) - {'SHA256SUMS'})
    (directory / 'SHA256SUMS').write_text(''.join(sha(directory / name) + '  ' + name + '\n' for name in names))
    with tarfile.open(destination, mode='x:', format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(caps):
            path = directory / name
            if (path.is_symlink() or not path.is_file() or path.stat().st_size < (0 if name.startswith('logs/') else 1)
                    or path.stat().st_size > caps[name]):
                raise ValueError('release-output-type-or-size')
            entry = tarfile.TarInfo(name); entry.size = path.stat().st_size
            entry.mode = 0o755 if name.startswith('bin/') else 0o600
            with path.open('rb') as source: archive.addfile(entry, source)
    validate_tar(destination, fixed)


def main():
    run_id = (ROOT / 'run-id').read_text().strip(); fixed = binding(run_id)
    source = ROOT / 'source'; output = ROOT / 'build'; release = Path('/opt/release-output/release')
    release.mkdir(); (release / 'bin').mkdir(); (release / 'metadata').mkdir(); (release / 'logs').mkdir()
    logs = release / 'logs'; metadata = release / 'metadata'
    for name in ('configure', 'build', 'rust-checks', 'artifact-checks'): (logs / (name + '.log')).touch()
    inventory = json.loads((ROOT / 'media/RUNTIME-ABI-AND-LIBRARY-INVENTORY.json').read_bytes())
    # Every runtime provider/Perl XS file must match the sealed target filesystem.
    for path, entry in inventory['runtime_libraries'].items():
        if sha('/' + path) != entry['sha256']: raise ValueError('release-runtime-library-bytes')
    for entry in inventory['perl_config_and_xs_inventory']:
        if entry['type'] == 'file' and sha('/' + entry['path']) != entry['sha256']:
            raise ValueError('release-perl-xs-bytes')
    perl = '/opt/eqemu-perl/bin/perl'
    keys = sorted(inventory['perl_config'])
    perl_code = 'use Config; use JSON::PP; print encode_json({map {$_=>$Config{$_}} @ARGV});'
    perl_config = json.loads(run([perl, '-e', perl_code, *keys]).decode())
    if perl_config != inventory['perl_config']: raise ValueError('release-perl-config')
    (metadata / 'PerlConfig.json').write_bytes(canonical(perl_config))
    (metadata / 'PerlXS.json').write_bytes(canonical(inventory['perl_config_and_xs_inventory']))
    identity = {name: run(argv).decode() for name, argv in (
        ('rustc', ['rustc', '-vV']), ('cargo', ['cargo', '--version']), ('clang', ['clang++', '--version']),
        ('cmake', ['cmake', '--version']), ('perl', [perl, '-V']))}
    identity['binary_sha256'] = {name: sha(path) for name, path in (
        ('rustc', ROOT / 'rust/toolchain/bin/rustc'), ('cargo', ROOT / 'rust/toolchain/bin/cargo'),
        ('clang++', '/usr/bin/clang++'), ('perl', perl), ('cmake', '/usr/bin/cmake'))}
    if '1.99.0' not in identity['rustc'] or '14.0.6' not in identity['clang']:
        raise ValueError('release-toolchain-version')
    (metadata / 'toolchain-identity.json').write_bytes(canonical(identity))
    workspace = source / 'rust/actors'; checks = {}
    for name, argv in (
        ('rust-format', ['fmt', '--all', '--check']),
        ('rust-dependencies', ['metadata', '--format-version=1', '--locked', '--offline']),
        ('rust-clippy', ['clippy', '--workspace', '--all-targets', '--frozen', '--offline', '--', '-D', 'warnings']),
        ('rust-tests', ['test', '--workspace', '--frozen', '--offline', '--lib', '--tests']),
        ('rust-doctests', ['test', '--workspace', '--frozen', '--offline', '--doc'])):
        check(name, ['cargo', *argv], cwd=workspace, log=logs / 'rust-checks.log', seconds=3600); checks[name] = 0
    configure = ['cmake', '-S', str(source), '-B', str(output), '-G', 'Ninja',
        '-DCMAKE_BUILD_TYPE=RelWithDebInfo', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
        '-DCMAKE_C_COMPILER=clang', '-DCMAKE_CXX_COMPILER=clang++',
        '-DCMAKE_C_COMPILER_LAUNCHER=', '-DCMAKE_CXX_COMPILER_LAUNCHER=',
        '-DVCPKG_INSTALLED_DIR=/opt/eqemu-deps', '-DVCPKG_MANIFEST_INSTALL=OFF',
        '-DEQEMU_BUILD_LOGIN=ON', '-DEQEMU_BUILD_TESTS=OFF', '-DEQEMU_BUILD_CLIENT_FILES=OFF',
        '-DEQEMU_BUILD_PERL=ON', '-DEQEMU_BUILD_LUA=ON', '-DPERL_EXECUTABLE=' + perl,
        '-DPERL_LIBRARY=' + PERL + '/libperl.so', '-DPERL_INCLUDE_PATH=' + PERL]
    check('native-configure', configure, log=logs / 'configure.log', seconds=3600); checks['native-configure'] = 0
    check('native-build', ['cmake', '--build', str(output), '--parallel', '1', '--target', *TARGETS], log=logs / 'build.log', seconds=14400)
    checks['native-build'] = 0; abi = {}
    RESULT['failed_check'] = 'artifact-checks'
    if (output / 'compile_commands.json').stat().st_size > 8 * 1024**2:
        raise ValueError('release-compile-commands-limit')
    check_configuration((output / 'CMakeCache.txt').read_text(), json.loads((output / 'compile_commands.json').read_bytes()))
    for name in TARGETS:
        binary = output / 'bin' / name
        text = run(['readelf', '-W', '-h', '-l', '-d', '-V', '--dyn-syms', str(binary)]).decode()
        facts = readelf_facts(text); check_abi(facts, inventory); abi[name] = facts
        (metadata / (name + '.readelf.txt')).write_text(text)
        shutil.copyfile(binary, release / 'bin' / name)
    run(['/bin/bash', '-o', 'pipefail', '-c',
         'nm --defined-only "$1" | awk \'$2 ~ /^[Tt]$/ && $3 == "eqemu_rust_bridge_v1" {found=1} END {exit !found}\'',
         'zone-symbol', str(output / 'bin/zone')])
    # These source controls are independent of the ordinary 26-case/ABC workload.
    for name in ('actor_demo_controls', 'actor_hunt_controls'):
        target = output / name
        run(['clang++', '-std=c++20', '-Wall', '-Wextra', '-Werror', '-pedantic', str(source / 'tests' / (name + '.cpp')), '-o', str(target)], log=logs / 'artifact-checks.log')
        run([str(target)], log=logs / 'artifact-checks.log')
    checks['artifact-checks'] = 0
    RESULT['checks']['artifact-checks'] = 0; RESULT['failed_check'] = None
    for name in ('CMakeCache.txt', 'compile_commands.json'): shutil.copyfile(output / name, metadata / name)
    shutil.copyfile(workspace / 'Cargo.lock', metadata / 'Cargo.lock')
    (release / 'SOURCE.json').write_bytes(canonical(fixed))
    (release / 'INPUTS.json').write_bytes(canonical(contract()['combined_manifest']))
    (release / 'BUILD.json').write_bytes(canonical(dict(checks=checks, targets=list(TARGETS), abi_complete=True, configure=configure)))
    (release / 'RUNTIME-ABI.json').write_bytes(canonical(dict(runtime_image=inventory['runtime_image'], checked=abi, perl_config=perl_config)))
    make_tar(release, Path('/opt/release-output/release.tar'), fixed)


if __name__ == '__main__':
    try:
        main()
    except CommandFailure as error:
        RESULT['failed_exit_code'] = error.code
        raise
    finally:
        Path('/opt/release-output/container-result.json').write_bytes(canonical(RESULT))
