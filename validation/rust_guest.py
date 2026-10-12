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


def protected_inventory(root):
    """Exclude mutable Cargo cache/target files; protect every tool, dependency and config."""
    if root.is_symlink() or any((root/name).is_symlink() for name in ('toolchain','vendor','home')):
        raise ValueError('Protected Rust input directory symlink')
    return {
        'toolchain':rust.inventory(root/'toolchain',rust.UNPACK_LIMIT,rust.FILE_LIMIT,links=True),
        'vendor':rust.inventory(root/'vendor',rust.UNPACK_LIMIT,rust.FILE_LIMIT),
        'configuration':rust.inventory(root,16384,rust.FILE_LIMIT,include={'config.toml','home/config.toml','home/config'}),
    }


def verify_protected(root, expected):
    actual=protected_inventory(root)
    if 'cargo_cwds' in expected:
        actual['cargo_cwds']=expected['cargo_cwds']
        actual['ancestor_configuration']=ancestor_configuration(expected['cargo_cwds'])
    if actual != expected:
        raise ValueError('Protected Rust tool/vendor/config input drift')


def ancestor_configuration(cwds):
    """Read only Cargo's known config directory at each bounded invocation ancestor."""
    locations=set()
    for cwd in cwds:
        cwd=Path(cwd).absolute()
        if len(cwd.parents)>20:raise ValueError('Cargo invocation depth unsupported')
        locations.update(str(parent/'.cargo') for parent in (cwd,*cwd.parents))
    result={}
    for location in sorted(locations):
        directory=Path(location)
        if directory.is_symlink():raise ValueError('Cargo ancestor config symlink')
        result[location]=rust.inventory(directory,16384,64,include={'config','config.toml'}) if directory.exists() else None
    return result


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
    return protected_inventory(root)


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


def finding(stage, output, package_ids, source_files=()):
    """Recognize a specific finding; generic Cargo failures remain infrastructure."""
    if re.search(r'(?i)out of memory|cannot allocate memory|no space left|failed to download|failed to get|could not execute|permission denied', output):
        return None
    if stage == 'rust-fmt' and re.search(r'^Diff in .+:\d+:', output, re.M):
        return 'format'
    if stage == 'rust-fmt' and re.search(r'^error: (?:expected |unexpected |.*unclosed delimiter|.*mismatched closing delimiter)',output,re.M):
        locations = re.findall(r'^\s*--> (.+):\d+:\d+\s*$',output,re.M)
        if any(location in source_files for location in locations):return 'compile'
    if stage in ('rust-tests', 'rust-doctests') and re.search(r'^test result: FAILED\. \d+ passed; [1-9]\d* failed;', output,re.M):
        return 'test'
    for line in output.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if not isinstance(message,dict) or message.get('reason') != 'compiler-message':
            continue
        item = message.get('message', {})
        if not isinstance(item,dict) or item.get('level') != 'error' or not isinstance(item.get('spans'),list) or not item['spans']:
            continue
        # Errors must refer to the explicitly selected workspace, not a failed
        # dependency build script or missing compiler in the closure.
        if message.get('package_id') not in package_ids:
            continue
        code = (item.get('code') or {}).get('code') or ''
        if stage == 'rust-clippy' and code.startswith('clippy::'):
            return 'lint'
        primary = any(span.get('is_primary') is True and str(span.get('file_name','')).endswith('.rs')
                      for span in item['spans'] if isinstance(span,dict))
        syntax = code == '' and primary and re.search(r'expected |unexpected |unclosed delimiter|mismatched closing delimiter',item.get('message',''))
        if code.startswith('E') or 'unsafe' in item.get('message', '') or syntax:
            return 'compile'
    return None


def counts(output, minimum, package_ids, doc_targets=None):
    """Correlate anchored harness blocks with selected test executables/doc targets."""
    executables = {}; completed = {}; current = None; current_target = None; running = None
    completed_targets = set(); had_summary = True
    for line in output.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            message = None
        if message is not None:
            if isinstance(message,dict) and message.get('reason')=='compiler-artifact' and message.get('package_id') in package_ids:
                profile = message.get('profile')
                if not isinstance(profile,dict):raise ValueError('Invalid Cargo test profile')
                executable = message.get('executable')
                if profile.get('test') is True and executable is not None:
                    if not isinstance(executable,str) or not executable or len(executable)>4096:
                        raise ValueError('Invalid Cargo test executable')
                    executables[executable] = package_ids[message['package_id']]
            # Compiler warnings/rendered text are data, never harness output.
            continue
        header = re.fullmatch(r'\s*Running .+ \((.+)\)',line) if doc_targets is None else re.fullmatch(r'\s*Doc-tests ([a-zA-Z0-9_]+)',line)
        if header:
            if not had_summary:raise ValueError('Missing Rust harness completion')
            current = executables.get(header[1]) if doc_targets is None else doc_targets.get(header[1])
            current_target = header[1]; had_summary = False
            running = None
            if current is None:raise ValueError('Unselected Rust harness target')
            continue
        start = re.fullmatch(r'running (\d+) tests?',line)
        if start and current is not None:
            running = int(start[1]); continue
        summary = re.fullmatch(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in [0-9.]+s',line)
        if summary:
            passed,failed,ignored,measured,filtered = map(int,summary.groups())
            if current is None or running is None or failed or measured or filtered or passed+ignored != running:
                raise ValueError('Invalid Rust harness completion')
            completed[current] = completed.get(current,0)+passed
            completed_targets.add(current_target); had_summary = True
            running = None
    passed = sum(completed.values())
    targets = set(executables) if doc_targets is None else set(doc_targets)
    if (not had_summary or completed_targets != targets or passed < minimum
            or not set(package_ids.values()) <= {name for name,count in completed.items() if count>0}):
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
        if isinstance(message,dict) and message.get('reason') == 'compiler-artifact' and message.get('package_id') in package_ids:
            seen.add(message['package_id'])
    if seen != package_ids:
        raise ValueError('Selected Rust lint targets did not complete')
    return len(seen)


def check(expected, source, authority, verify_source, command, emit, env, protected):
    guard()
    root = Path(env['CARGO_HOME']).parent
    # Freeze before Cargo metadata itself can execute an inherited wrapper.
    protected['cargo_cwds']=[str(source),str(source/Path(expected['manifest_path']).parent),str(source.parent/'build')]
    protected['ancestor_configuration']=ancestor_configuration(protected['cargo_cwds'])
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
    test_ids = {item['id']:item['name'] for item in graph['packages'] if item['name'] in expected['test_packages'] and item['id'] in graph['workspace_members']}
    doc_targets = {target['name']:item['name'] for item in graph['packages'] if item['id'] in test_ids
                   for target in item.get('targets',[]) if target.get('doctest') is True}
    source_files = {str(source/entry['path']) for entry in authority.get('entries',[]) if entry['path'].endswith('.rs')}
    verify_source(source, authority)
    verify_protected(root,protected)
    emit({'kind':'observation','name':'rust-preflight','value':dict(contract_sha256=rust.digest(expected),
        release=expected['release'],host=rust.HOST,target=expected['target'],metadata_sha256=sha(meta),
        bundle_sha256=expected['bundle']['sha256'],source_unchanged=True,protected_sha256=rust.digest(protected))})
    commands = [
        ('rust-fmt',[cargo,'fmt','--manifest-path',str(source/expected['manifest_path']),'--all','--','--check']),
        ('rust-clippy',[cargo,'clippy',*common,*selected,*features,'--all-targets','--message-format=json',
                        '--','-D','clippy::correctness','-D','clippy::suspicious']),
        ('rust-tests',[cargo,'test',*common,*tested,*features,'--lib','--tests','--message-format=json',
                       '--','--test-threads=1']),
        ('rust-doctests',[cargo,'test',*common,*tested,*features,'--doc','--message-format=json','--','--test-threads=1']),
    ]
    for stage, args in commands:
        try:
            output = command(stage,args,cwd=source,timeout=300,cap=4*1024**2).read_text()
        except RuntimeError as error:
            verify_source(source,authority)
            verify_protected(root,protected)
            match = re.match(re.escape(stage)+r': exit (\d+)\n',str(error))
            log = root.parent/'logs'/(stage+'.log')
            output = log.read_text() if log.is_file() else ''
            evidence = finding(stage,output,package_ids,source_files) if match else None
            if evidence:
                emit({'kind':'observation','name':'rust-failure','value':dict(contract_sha256=rust.digest(expected),
                    stage=stage,exit_code=int(match[1]),finding=evidence,source_unchanged=True,protected_unchanged=True)})
            raise
        verify_source(source,authority)
        verify_protected(root,protected)
        if stage in ('rust-tests','rust-doctests'):
            total = counts(output,expected['minimum_doctests'] if stage == 'rust-doctests' else expected['minimum_tests'],
                           test_ids,doc_targets if stage == 'rust-doctests' else None)
        elif stage == 'rust-clippy':
            total = artifacts(output,package_ids)
        else:
            total = len(expected['packages'])
        emit({'kind':'observation','name':stage,'value':dict(contract_sha256=rust.digest(expected),
            exit_code=0,selected=total,completed=total,failed=0,source_unchanged=True,protected_unchanged=True)})


def native_link(expected, binary, command, emit, root, protected):
    """Require the Rust bridge ABI entry point in the actual final executable."""
    guard()
    symbols = command('rust-native-symbols', ['/usr/bin/nm', '--defined-only', str(binary)],
                      timeout=30, cap=8*1024**2).read_text()
    verify_protected(root,protected)
    lines = [line for line in symbols.splitlines() if line]
    if not lines or any(not re.fullmatch(r'[0-9a-fA-F]+ [a-zA-Z?] .+',line) for line in lines):
        raise ValueError('Unknown native symbol-tool output')
    if not re.search(r'^[0-9a-fA-F]+ [Tt] '+re.escape(expected['link_symbol'])+r'$', symbols, re.M):
        emit({'kind':'observation','name':'rust-failure','value':dict(contract_sha256=rust.digest(expected),
            stage='rust-native-link',exit_code=1,tool_exit_code=0,binary_sha256=sha(binary),
            finding='link',source_unchanged=True,protected_unchanged=True)})
        raise RuntimeError('rust-native-link: missing required symbol\n'+expected['link_symbol'])
    emit({'kind':'observation','name':'rust-native-link','value':dict(contract_sha256=rust.digest(expected),
        symbol=expected['link_symbol'],binary_sha256=sha(binary),source_unchanged=True,protected_unchanged=True)})
