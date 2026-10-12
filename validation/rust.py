"""Fixed offline Rust contract and evidence. Importing never executes candidate code."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import time
import tomllib

HOST = 'x86_64-unknown-linux-gnu'
BUNDLE_LIMIT = 220 * 1024**2
UNPACK_LIMIT = 2 * 1024**3
FILE_LIMIT = 30000
STAGES = ('rust-fmt', 'rust-clippy', 'rust-tests', 'rust-doctests')
REQUIRED = ('rust-preflight', *STAGES, 'rust-native-link')


def inventory(root, byte_limit=16*1024**2, file_limit=1000, links=False, include=None):
    """Bound paths and stat sizes before streaming bytes. Never materialize rglob output."""
    root = Path(root).resolve(strict=True)
    stack = [root]; entries = []; total = 0; visited = 0
    while stack:
        directory = stack.pop()
        with os.scandir(directory) as children:
            for child in children:
                visited += 1
                if visited > file_limit:
                    raise ValueError('Rust inventory file/count budget')
                file = Path(child.path); name = str(file.relative_to(root))
                if include is not None and name not in include and not any(item.startswith(name+'/') for item in include):
                    continue
                info = child.stat(follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    if not links or not file.resolve(strict=True).is_relative_to(root):
                        raise ValueError('Rust inventory symlink')
                    entries.append(dict(path=name,link=os.readlink(file)))
                    continue
                if stat.S_ISDIR(info.st_mode):
                    stack.append(file)
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_size > min(byte_limit,512*1024**2) or total+info.st_size > byte_limit:
                    raise ValueError('Rust inventory byte/type budget')
                total += info.st_size
                sha256 = hashlib.sha256()
                blob = hashlib.sha1(b'blob '+str(info.st_size).encode()+b'\0')
                fd = os.open(file,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as stream:
                    actual = os.fstat(stream.fileno())
                    if not stat.S_ISREG(actual.st_mode) or actual.st_size != info.st_size:
                        raise ValueError('Rust inventory changed before read')
                    remaining = info.st_size
                    while remaining:
                        block = stream.read(min(1024**2,remaining))
                        if not block:raise ValueError('Rust inventory short read')
                        remaining -= len(block);sha256.update(block);blob.update(block)
                    if stream.read(1):raise ValueError('Rust inventory grew during read')
                entries.append(dict(path=name,mode='100755' if info.st_mode&0o111 else '100644',
                                    bytes=info.st_size,sha256=sha256.hexdigest(),blob=blob.hexdigest()))
    return {'entries':sorted(entries,key=lambda entry:entry['path']),'gitlinks':{}}


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate Rust field')
        result[key] = value
    return result


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def path(value):
    if (not isinstance(value, str) or not value or str(PurePosixPath(value)) != value
            or PurePosixPath(value).is_absolute() or '..' in PurePosixPath(value).parts):
        raise ValueError('Unsafe Rust path')
    return value


def record(value):
    if (not isinstance(value, dict) or set(value) != {'path', 'bytes', 'sha256'}
            or type(value['bytes']) is not int or not 0 < value['bytes'] <= BUNDLE_LIMIT
            or not isinstance(value['sha256'], str) or not re.fullmatch('[a-f0-9]{64}', value['sha256'])):
        raise ValueError('Rust input identity')
    path(value['path'])
    return value


def contract(value):
    keys = {'version', 'release', 'target', 'bundle', 'manifest_path', 'packages',
            'test_packages', 'features', 'source_blobs', 'minimum_tests', 'minimum_doctests', 'link_symbol'}
    if (not isinstance(value, dict) or set(value) != keys or type(value['version']) is not int
            or value['version'] != 1 or value['release'] != '1.99.0' or value['target'] != HOST):
        raise ValueError('Unsupported Rust contract')
    record(value['bundle'])
    if value['link_symbol'] != 'eqemu_rust_bridge_v1':
        raise ValueError('Unsupported Rust native link symbol')
    manifest = path(value['manifest_path'])
    if not manifest.endswith('Cargo.toml'):
        raise ValueError('Rust workspace manifest')
    for key in ('packages', 'test_packages', 'features'):
        items = value[key]
        if (not isinstance(items, list) or len(items) > 16
                or any(not isinstance(x, str) or not re.fullmatch('[a-zA-Z0-9_/-]{1,80}', x) for x in items)
                or len(set(items)) != len(items)):
            raise ValueError('Rust selection')
    if not value['packages'] or not value['test_packages'] or not set(value['test_packages']) <= set(value['packages']):
        raise ValueError('Empty Rust package selection')
    for key in ('minimum_tests', 'minimum_doctests'):
        if type(value[key]) is not int or not 1 <= value[key] <= 100000:
            raise ValueError('Empty Rust test coverage')
    blobs = value['source_blobs']
    if not isinstance(blobs, dict) or not 3 <= len(blobs) <= 64:
        raise ValueError('Rust source declaration')
    for name, blob in blobs.items():
        path(name)
        if not isinstance(blob, str) or not re.fullmatch('[a-f0-9]{40}', blob):
            raise ValueError('Rust dependency blob')
    parent = str(PurePosixPath(manifest).parent)
    prefix = '' if parent == '.' else parent + '/'
    if not {manifest, prefix + 'Cargo.lock', 'rust-toolchain.toml'} <= set(blobs):
        raise ValueError('Rust manifest/lock/toolchain declaration missing')
    return value


def config(text, vendor):
    """Accept source replacement only; never acquire a candidate compiler wrapper."""
    value = tomllib.loads(text)
    if set(value) != {'source'} or not isinstance(value['source'], dict):
        raise ValueError('Rust vendor configuration')
    sources = value['source']
    if sources.get('vendored-sources') != {'directory': '@VENDOR@'} or 'crates-io' not in sources:
        raise ValueError('Rust vendor directory')
    for name, item in sources.items():
        if name == 'vendored-sources':
            continue
        if (not isinstance(item, dict) or not set(item) <= {'replace-with', 'git', 'rev', 'branch', 'tag', 'registry'}
                or item.get('replace-with') != 'vendored-sources'
                or any(not isinstance(x, str) or len(x) > 1024 for x in item.values())):
            raise ValueError('Unreplaced Rust source')
    result = text.replace('"@VENDOR@"', json.dumps(str(vendor)))
    if tomllib.loads(result)['source']['vendored-sources']['directory'] != str(vendor):
        raise ValueError('Rust vendor substitution')
    return result


def verify_bundle(bundle, toolchain):
    """Inspect opaque regular outer members; no extraction or installer execution."""
    expected = {'vendor.tar', 'vendor-config.toml', *[name + '.tar.xz' for name in toolchain['components']]}
    found = {}; deadline = time.monotonic() + 120
    with tarfile.open(bundle, 'r:') as archive:
        for member in archive:
            if time.monotonic() >= deadline:
                raise TimeoutError('Rust bundle inspection deadline')
            if not member.isfile() or member.name not in expected or member.name in found or not 0 < member.size <= BUNDLE_LIMIT:
                raise ValueError('Rust bundle inventory')
            hashed = hashlib.sha256(); body = archive.extractfile(member); text = bytearray()
            with body:
                while block := body.read(1024**2):
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Rust bundle inspection deadline')
                    hashed.update(block)
                    if member.name == 'vendor-config.toml':
                        text.extend(block)
                        if len(text) > 16384:
                            raise ValueError('Rust vendor config size')
            found[member.name] = {'bytes': member.size, 'sha256': hashed.hexdigest()}
            if member.name == 'vendor-config.toml':
                config(text.decode(), '/qualified/vendor')
            elif member.name.endswith('.tar.xz'):
                name = member.name.removesuffix('.tar.xz')
                if found[member.name]['sha256'] != toolchain['components'][name]['sha256']:
                    raise ValueError('Rust component identity mismatch: ' + name)
    if set(found) != expected:
        raise ValueError('Missing Rust component/vendor input')
    return found


def observation(name, value, expected):
    """Validate bounded named records before worker success or failure classification."""
    contract(expected)
    base = {'contract_sha256': digest(expected)}
    if not isinstance(value, dict) or value.get('contract_sha256') != base['contract_sha256']:
        raise ValueError('Rust observation identity')
    if name == 'rust-preflight':
        keys = {*base, 'release', 'host', 'target', 'metadata_sha256', 'bundle_sha256', 'source_unchanged', 'protected_sha256'}
        if (set(value) != keys or value['release'] != expected['release'] or value['host'] != HOST
                or value['target'] != HOST or value['bundle_sha256'] != expected['bundle']['sha256']
                or value['source_unchanged'] is not True
                or not isinstance(value['protected_sha256'], str) or not re.fullmatch('[a-f0-9]{64}', value['protected_sha256'])
                or not isinstance(value['metadata_sha256'], str) or not re.fullmatch('[a-f0-9]{64}', value['metadata_sha256'])):
            raise ValueError('Rust preflight evidence')
    elif name in STAGES:
        keys = {*base, 'exit_code', 'selected', 'completed', 'failed', 'source_unchanged', 'protected_unchanged'}
        if (set(value) != keys or type(value['exit_code']) is not int or value['exit_code'] != 0
                or any(type(value[k]) is not int for k in ('selected', 'completed', 'failed'))
                or not 0 < value['selected'] <= 100000 or value['completed'] != value['selected']
                or value['failed'] != 0 or value['source_unchanged'] is not True or value['protected_unchanged'] is not True):
            raise ValueError('Rust stage completion')
        minimum = expected['minimum_doctests'] if name == 'rust-doctests' else expected['minimum_tests'] if name == 'rust-tests' else 1
        if value['completed'] < minimum:
            raise ValueError('Insufficient Rust test coverage')
    elif name == 'rust-native-link':
        if (set(value) != {*base, 'symbol', 'binary_sha256', 'source_unchanged', 'protected_unchanged'}
                or value['symbol'] != expected['link_symbol'] or value['source_unchanged'] is not True
                or value['protected_unchanged'] is not True
                or not isinstance(value['binary_sha256'], str)
                or not re.fullmatch('[a-f0-9]{64}', value['binary_sha256'])):
            raise ValueError('Rust native link evidence')
    elif name == 'rust-failure':
        keys = {*base, 'stage', 'exit_code', 'finding', 'source_unchanged', 'protected_unchanged'}
        if value.get('stage')=='rust-native-link':
            keys |= {'tool_exit_code','binary_sha256'}
            if (type(value.get('tool_exit_code')) is not int or value['tool_exit_code']!=0
                    or not isinstance(value.get('binary_sha256'),str)
                    or not re.fullmatch('[a-f0-9]{64}',value['binary_sha256'])):
                raise ValueError('Rust missing-symbol tool evidence')
        if (set(value) != keys or value['stage'] not in (*STAGES,'rust-native-link') or type(value['exit_code']) is not int
                or not 0 < value['exit_code'] <= 255 or value['source_unchanged'] is not True or value['protected_unchanged'] is not True
                or value['finding'] not in ('format', 'lint', 'compile', 'test', 'link')):
            raise ValueError('Rust candidate failure evidence')
        if (value['stage']=='rust-fmt' and value['finding'] not in ('format','compile')
                or value['finding']=='format' and value['stage']!='rust-fmt'
                or value['finding'] == 'lint' and value['stage'] != 'rust-clippy'):
            raise ValueError('Rust failure stage/finding mismatch')
        if (value['stage']=='rust-native-link') != (value['finding']=='link'):
            raise ValueError('Rust native failure mismatch')
    else:
        raise ValueError('Unknown Rust observation')
    return value


def candidate_failure(worker, error):
    """Cargo 101 alone is insufficient. Inputs, finding and source custody are required."""
    observed = worker.get('observations_untrusted', {})
    expected = worker.get('rust_contract')
    try:
        observation('rust-preflight', observed['rust-preflight'], expected)
        item = observation('rust-failure', observed['rust-failure'], expected)
    except (KeyError, TypeError, ValueError):
        return False
    if item['stage']=='rust-native-link':
        return error.startswith('rust-native-link: missing required symbol\n')
    return error.startswith(item['stage'] + ': exit ' + str(item['exit_code']) + '\n')
