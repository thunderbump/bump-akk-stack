"""Rust provisioning/checks for isolated guests. Never call this workload on the host."""
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile
import time

import rust


def guard():
    if not Path('/opt/eqemu-proof/BUILD_GUEST_ONLY').is_file():
        raise RuntimeError('Guest-only Rust workload guard')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def extract(archive_path, target, deadline):
    """Bound expanded bytes/counts before extraction; reject escaped/link/special members."""
    target.mkdir()
    with tarfile.open(archive_path, 'r:*') as archive:
        members = []; total = 0
        for member in archive:
            if time.monotonic() >= deadline:
                raise TimeoutError('Rust extraction deadline')
            rust.path(member.name.rstrip('/'))
            # Official components use normal files/directories and occasional
            # internal symlinks. data_filter validates their resolved location.
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError('Rust archive special member')
            total += member.size
            members.append(member)
            if total > rust.UNPACK_LIMIT or len(members) > rust.FILE_LIMIT:
                raise ValueError('Rust extraction budget')
        names = [m.name.rstrip('/') for m in members]
        if len(set(names)) != len(names):
            raise ValueError('Duplicate Rust archive member')
        for member in members:
            if time.monotonic() >= deadline:
                raise TimeoutError('Rust extraction deadline')
            archive.extract(member, target, filter='data')


def prepare(expected, bundle, work, command, env, toolchain=None):
    guard()
    rust.contract(expected)
    if (not bundle.is_file() or bundle.is_symlink() or bundle.stat().st_size != expected['bundle']['bytes']
            or sha(bundle) != expected['bundle']['sha256']):
        raise ValueError('Rust bundle custody')
    toolchain = toolchain or json.loads(Path('/opt/eqemu-proof/rust-toolchain.json').read_text())
    rust.verify_bundle(bundle, toolchain)
    root = work/'rust'; root.mkdir()
    outer = root/'inputs'
    extract(bundle, outer, time.monotonic()+120)
    prefix = root/'toolchain'
    for name in toolchain['components']:
        unpacked = root/name
        extract(outer/(name+'.tar.xz'), unpacked, time.monotonic()+120)
        installers = list(unpacked.glob('*/install.sh'))
        if len(installers) != 1:
            raise ValueError('Rust component installer missing')
        command('rust-install-'+name, ['/bin/sh', str(installers[0]), '--prefix='+str(prefix),
                                     '--disable-ldconfig'], timeout=120, cap=1024**2)
    vendor = root/'vendor'
    extract(outer/'vendor.tar', vendor, time.monotonic()+120)
    cfg = root/'config.toml'
    cfg.write_text(rust.config((outer/'vendor-config.toml').read_text(), vendor))
    env.update(PATH=str(prefix/'bin')+':'+env['PATH'], RUSTC=str(prefix/'bin/rustc'),
               RUSTDOC=str(prefix/'bin/rustdoc'), RUSTFMT=str(prefix/'bin/rustfmt'),
               RUSTC_WRAPPER='', RUSTC_WORKSPACE_WRAPPER='', CARGO_HOME=str(root/'home'),
               CARGO_TARGET_DIR=str(root/'target'), CARGO_NET_OFFLINE='true',
               CARGO_BUILD_JOBS='1', CARGO_INCREMENTAL='0', RUSTUP_AUTO_INSTALL='0',
               CC='/usr/bin/gcc', CXX='/usr/bin/g++')
    # A shared source replacement is required by CMake's later Cargo invocation.
    home = root/'home'; home.mkdir(); (home/'config.toml').write_text(cfg.read_text())
    for name in ('rustc', 'cargo', 'rustfmt', 'cargo-clippy', 'clippy-driver', 'rustdoc'):
        executable = prefix/'bin'/name
        if not executable.is_file():
            raise ValueError('Missing Rust component executable: '+name)
        output = command('rust-version-'+name, [str(executable), '--version'], timeout=30, cap=16384).read_text()
        if name in ('cargo', 'rustc', 'rustdoc') and not output.startswith(name+' '+expected['release']):
            raise ValueError('Rust executable version mismatch')
    info = command('rust-host', [str(prefix/'bin/rustc'), '-vV'], timeout=30, cap=16384).read_text()
    if '\nhost: '+rust.HOST+'\n' not in info:
        raise ValueError('Rust compiler host mismatch')
    return root


def metadata(text, expected, source, vendor):
    value = json.loads(text, object_pairs_hook=rust.unique)
    packages = value.get('packages'); resolve = value.get('resolve')
    if value.get('version') != 1 or not isinstance(packages, list) or not isinstance(resolve, dict):
        raise ValueError('Rust metadata resolution missing')
    found = set()
    for item in packages:
        manifest = Path(item['manifest_path']).resolve()
        if not (manifest.is_relative_to(source.resolve()) or manifest.is_relative_to(vendor.resolve())):
            raise ValueError('Rust metadata escaped source/vendor closure')
        if item['id'] in value.get('workspace_members', []):
            found.add(item['name'])
    if not set(expected['packages']) <= found:
        raise ValueError('Selected Rust workspace packages missing')
    return value


def finding(stage, output, package_ids):
    """Recognize a specific finding; generic Cargo failures remain infrastructure."""
    if re.search(r'(?i)out of memory|cannot allocate memory|no space left|failed to download|failed to get|could not execute|permission denied', output):
        return None
    if stage == 'rust-fmt' and re.search(r'^Diff in .+:\d+:', output, re.M):
        return 'format'
    if stage in ('rust-tests', 'rust-doctests') and re.search(r'test result: FAILED\. \d+ passed; [1-9]\d* failed;', output):
        return 'test'
    for line in output.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if message.get('reason') != 'compiler-message':
            continue
        item = message.get('message', {})
        if item.get('level') != 'error' or not item.get('spans'):
            continue
        # Errors must refer to the explicitly selected workspace, not a failed
        # dependency build script or missing compiler in the closure.
        if message.get('package_id') not in package_ids:
            continue
        code = (item.get('code') or {}).get('code', '')
        if stage == 'rust-clippy' and code.startswith('clippy::'):
            return 'lint'
        if code.startswith('E') or 'unsafe' in item.get('message', ''):
            return 'compile'
    return None


def counts(output, minimum):
    rows = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', output)
    passed = sum(int(row[0]) for row in rows)
    if not rows or passed < minimum or any(int(row[1]) for row in rows):
        raise ValueError('Missing/empty Rust test completion')
    return passed


def artifacts(output, package_ids):
    """Cargo success without the selected compiler targets is incomplete lint coverage."""
    seen = set()
    for line in output.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if message.get('reason') == 'compiler-artifact' and message.get('package_id') in package_ids:
            seen.add(message['package_id'])
    if seen != package_ids:
        raise ValueError('Selected Rust lint targets did not complete')
    return len(seen)


def check(expected, source, authority, verify_source, command, emit, env):
    guard()
    root = Path(env['CARGO_HOME']).parent
    cargo = str(root/'toolchain/bin/cargo')
    common = ['--frozen', '--manifest-path', str(source/expected['manifest_path']),
              '--target', expected['target']]
    selected = [arg for name in expected['packages'] for arg in ('-p', name)]
    tested = [arg for name in expected['test_packages'] for arg in ('-p', name)]
    features = ['--features', ','.join(expected['features'])] if expected['features'] else []
    meta = command('rust-metadata', [cargo, 'metadata', '--frozen', '--manifest-path', str(source/expected['manifest_path']), *features, '--filter-platform', expected['target'], '--format-version', '1'],
                   cwd=source, timeout=120, cap=4*1024**2)
    graph = metadata(meta.read_text(), expected, source, root/'vendor')
    package_ids = {item['id'] for item in graph['packages'] if item['name'] in expected['packages'] and item['id'] in graph['workspace_members']}
    verify_source(source, authority)
    emit({'kind':'observation','name':'rust-preflight','value':dict(contract_sha256=rust.digest(expected),
        release=expected['release'],host=rust.HOST,target=expected['target'],metadata_sha256=sha(meta),
        bundle_sha256=expected['bundle']['sha256'],source_unchanged=True)})
    commands = [
        ('rust-fmt',[cargo,'fmt','--manifest-path',str(source/expected['manifest_path']),'--all','--','--check']),
        ('rust-clippy',[cargo,'clippy',*common,*selected,*features,'--all-targets','--message-format=json',
                        '--','-D','clippy::correctness','-D','clippy::suspicious']),
        ('rust-tests',[cargo,'test',*common,*tested,*features,'--lib','--tests','--message-format=json',
                       '--','--test-threads=1']),
        ('rust-doctests',[cargo,'test',*common,*tested,*features,'--doc','--','--test-threads=1']),
    ]
    for stage, args in commands:
        try:
            output = command(stage,args,cwd=source,timeout=300,cap=4*1024**2).read_text()
        except RuntimeError as error:
            verify_source(source,authority)
            match = re.match(re.escape(stage)+r': exit (\d+)\n',str(error))
            log = root.parent/'logs'/(stage+'.log')
            output = log.read_text() if log.is_file() else ''
            evidence = finding(stage,output,package_ids) if match else None
            if evidence:
                emit({'kind':'observation','name':'rust-failure','value':dict(contract_sha256=rust.digest(expected),
                    stage=stage,exit_code=int(match[1]),finding=evidence,source_unchanged=True)})
            raise
        verify_source(source,authority)
        if stage in ('rust-tests','rust-doctests'):
            total = counts(output,expected['minimum_doctests'] if stage == 'rust-doctests' else expected['minimum_tests'])
        elif stage == 'rust-clippy':
            total = artifacts(output,package_ids)
        else:
            total = len(expected['packages'])
        emit({'kind':'observation','name':stage,'value':dict(contract_sha256=rust.digest(expected),
            exit_code=0,selected=total,completed=total,failed=0,source_unchanged=True)})


def native_link(expected, binary, command, emit):
    """Require the Rust bridge ABI entry point in the actual final executable."""
    guard()
    symbols = command('rust-native-symbols', ['/usr/bin/nm', '--defined-only', str(binary)],
                      timeout=30, cap=8*1024**2).read_text()
    if not re.search(r'^[0-9a-fA-F]+ [Tt] '+re.escape(expected['link_symbol'])+r'$', symbols, re.M):
        raise ValueError('Rust bridge not linked into final binary')
    emit({'kind':'observation','name':'rust-native-link','value':dict(contract_sha256=rust.digest(expected),
        symbol=expected['link_symbol'],binary_sha256=sha(binary),source_unchanged=True)})
