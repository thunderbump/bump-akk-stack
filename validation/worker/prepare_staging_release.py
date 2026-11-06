"""Prepare data only: narrow installed-baseline overlay, frontend and exact inventories."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from staging_release import HELPERS, SELECTION, canonical, contract, frontend_identity, sha, verify_media, write_json

ROOT = Path(__file__).resolve().parents[2]
CODE = Path('/srv/eqemu-validator-code')
CONFIG = Path('/etc/eqemu-validator/config.json')
READBACK = Path('/home/bump/.local/state/eqemu-cdau-integration-prep/20261104-source/ROOT-V6-POST-PUBLICATION-READBACK.json')
READBACK_SHA = 'd130dd59ae33a27a415bd88e707e213c4634f4a82030560eadaa9d572be360d8'
CONFIG_SHA = 'c792ffed4a2a2ea8e5fe3821326d9f613c767e0a6b3303214b707406864611c8'
HOOK_BEFORE = "    if data.get('operation')=='integration-artifacts':\n"
HOOK = "    if data.get('operation') == 'staging-build-export':\n        from staging_worker import run\n        return run(value, connection, data)\n"


def capture_baseline(code=CODE, readback=READBACK):
    """Public bytes only. Root-audit history is provenance, not a fresh private read."""
    from integration_artifacts import INSTALLED_FILES
    raw = readback.read_bytes()
    if hashlib.sha256(raw).hexdigest() != READBACK_SHA: raise ValueError('release-baseline-readback')
    records = json.loads(raw)['records']; result = {}
    for name in INSTALLED_FILES:
        path = code / name; info = path.lstat(); expected = records[str(CODE / name)]
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected['uid'] or info.st_gid != expected['gid']
                or stat.S_IMODE(info.st_mode) != expected['mode'] or info.st_size != expected['bytes']):
            raise ValueError('release-installed-baseline-metadata')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected['sha256']: raise ValueError('release-installed-baseline-bytes')
        result[name] = raw
    return result


def overlay(original, additions, commit):
    """Change only the dispatch hook and inventory. Retain every other installed helper byte."""
    result = dict(original)
    runtime = original['validation/worker/runtime.py'].decode()
    if runtime.count(HOOK_BEFORE) != 1 or HOOK in runtime: raise ValueError('release-runtime-hook-baseline')
    result['validation/worker/runtime.py'] = runtime.replace(HOOK_BEFORE, HOOK + HOOK_BEFORE).encode()
    manifest = json.loads(original['integration-release.json'])
    manifest['source_commit'] = commit
    row = manifest['files']['validation/worker/runtime.py']
    row.update(bytes=len(result['validation/worker/runtime.py']), sha256=hashlib.sha256(result['validation/worker/runtime.py']).hexdigest())
    result['integration-release.json'] = canonical(manifest) + b'\n'
    result.update(additions)
    return result


def prepare(output, media, source=ROOT):
    def git(*args):
        return subprocess.run(['/usr/bin/git', '-C', str(source), *args], check=True, capture_output=True).stdout
    if git('status', '--porcelain', '--untracked-files=all'): raise ValueError('release-package-source-dirty')
    commit = git('rev-parse', 'HEAD').decode().strip()
    tree = git('rev-parse', 'HEAD^{tree}').decode().strip()
    if git('ls-tree', '-d', commit, 'validation/resilient_ops'): raise ValueError('release-package-excludes-stopped-platform')
    request = verify_media(media)
    if sha(CONFIG) != CONFIG_SHA: raise ValueError('release-config-baseline')
    original = capture_baseline()
    additions = {'validation/worker/' + name: git('show', commit + ':validation/worker/' + name) for name in HELPERS}
    prospective = overlay(original, additions, commit)
    policy = dict(version=1, selection=SELECTION, config_sha256=CONFIG_SHA,
        files={name: dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) for name, raw in prospective.items()})
    prospective['staging-release-policy.json'] = canonical(policy) + b'\n'
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    records = {}
    def copy(name, raw):
        path = output / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        records[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    for name, raw in prospective.items(): copy('prospective/' + name, raw)
    for name, raw in original.items(): copy('baseline/' + name, raw)
    for name in ('scripts/build-staging-release', *('validation/worker/' + n for n in HELPERS)):
        copy('frontend/' + name, git('show', commit + ':' + name))
    write_json(output / 'manifest.json', dict(version=1, scope='source-package-only-not-admission',
        source_commit=commit, source_tree=tree, selection=SELECTION, assets=records,
        installed_baseline_readback_sha256=READBACK_SHA, installed_baseline_runtime_sha256=hashlib.sha256(original['validation/worker/runtime.py']).hexdigest(),
        changed_existing=['validation/worker/runtime.py', 'integration-release.json'],
        added=[*sorted(additions), 'staging-release-policy.json'], retained_original_files=17,
        policy_sha256=hashlib.sha256(prospective['staging-release-policy.json']).hexdigest(),
        anticipated_implementation_sha256=hashlib.sha256(canonical(policy)).hexdigest(),
        prospective_ordinary_runtime_identity_sha256=hashlib.sha256(canonical({name: hashlib.sha256(raw).hexdigest()
            for name, raw in prospective.items() if name in original})).hexdigest(),
        frontend_sha256=frontend_identity(output / 'frontend'),
        actual_installed_implementation='eqemu-worker-v1:9960d78d7758721c13347a9d243790cd6ac10796574e05db8d153bbd5e25e61f',
        request=request, media_path=str(media.absolute()), media_ownership='df2 sealed data; not copied or rebuilt',
        admission_commands=None, execution_authorized=False, resources_qualified=False,
        consequences='No installed change. Old ordinary/formatter/AFK identity pins remain historical; prospective worker bytes change identity. This fixed CLI has no AFK reuse claim.',
        rollback_limit='Baseline bytes supplied as review data only. No rollback/operator/admission implementation or invocation in this package.',
        static_kernel_filesystem_proof=contract()['static_kernel_filesystem_proof']))
    return dict(manifest=str(output / 'manifest.json'), manifest_sha256=sha(output / 'manifest.json'), source_commit=commit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--media', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.output, args.media)))


if __name__ == '__main__': main()
