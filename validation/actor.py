"""Fixed actor profile and completion contract; importing starts no workload."""
import json
import math
from pathlib import Path
import re
import subprocess

PROFILE = 'actor-lifecycle-v1'
PROFILES = ('build-unit-v1', 'build-static-unit-v1', PROFILE)
CONTROLS = ('assertion', 'missing-map', 'cancel')
RUNTIME_SECONDS = 1800
ZONE_SECONDS = 300
RECIPE = {
    'version': 1, 'zone': 'poknowledge', 'zone_id': 202, 'instance': 0,
    'version_id': 0, 'remove_ambient_spawn2': True, 'zone_controller': False,
    'bots': False, 'initial_zone_state': 'empty', 'external_sinks': False,
    'scenario': 'tests:actor-lifecycle', 'runtime_seconds': RUNTIME_SECONDS,
    'zone_seconds': ZONE_SECONDS,
}
CASES = {'create-duplicate', 'name-collision', 'native-processing',
         'retire-recreate', 'external-removal-id-reuse', 'save-fresh-zone'}
PUBLIC_STAGES = {
    'actor-mount-input', 'actor-package-plan', 'actor-mask-services',
    'actor-package-install', 'actor-package-audit', 'actor-package-identities',
    'actor-perl-modules', 'actor-db-init', 'actor-db-create',
    'actor-import-content', 'actor-import-login', 'actor-import-player',
    'actor-import-state', 'actor-import-system', 'actor-tables', 'actor-version',
    'actor-empty', 'actor-content', 'actor-state', 'actor-fixture',
    'actor-fixture-checked', 'actor-account', 'actor-shared-memory', 'actor-lifecycle',
    'actor-debugger-gdb', 'actor-debugger-addr2line', 'actor-debugger-readelf', 'actor-debugger-python',
}


def summary(value, control=None):
    """Project only bounded proof fields; raw guest observations stay private."""
    if (not isinstance(value, dict) or value.get('profile') != PROFILE
            or not isinstance(value.get('result'), dict)
            or not isinstance(value.get('fixture_manifest_sha256'), str)
            or not re.fullmatch('[a-f0-9]{64}', value['fixture_manifest_sha256'])):
        raise ValueError('Actor summary identity')
    native = dict(value['result'])
    code = native.pop('exit_code', None)
    try:
        native = result(native, code, control)
    except OverflowError:
        raise ValueError('Actor summary native timing') from None
    stages = value.get('stage_seconds')
    if not isinstance(stages, dict) or not set(stages) <= PUBLIC_STAGES:
        raise ValueError('Actor summary stages')
    times = [value.get('elapsed_seconds'), *stages.values()]
    if any(type(t) not in (int, float) or not 0 <= t <= 19000 or not math.isfinite(t) for t in times):
        raise ValueError('Actor summary timings')
    flags = ('database_cleanup', 'outputs_unchanged', 'inputs_unchanged')
    if any(type(value.get(name)) is not bool for name in flags):
        raise ValueError('Actor summary cleanup')
    view = dict(profile=PROFILE, fixture_manifest_sha256=value['fixture_manifest_sha256'],
                result=native, elapsed_seconds=value['elapsed_seconds'],
                stage_seconds=dict(stages), **{name: value[name] for name in flags})
    if len(json.dumps(view, allow_nan=False).encode()) > 8192:
        raise ValueError('Actor summary budget')
    return view


def options(profile, control=None, retain=False, reuse=None):
    if profile not in PROFILES:
        raise ValueError('Unknown validation profile')
    if control is not None and control not in CONTROLS:
        raise ValueError('Unknown actor qualification control')
    if type(retain) is not bool:
        raise ValueError('Invalid artifact retention selection')
    if (control is not None or retain or reuse is not None) and profile != PROFILE:
        raise ValueError('Qualification requires actor profile')
    if (reuse is None) != (control is None) or retain and reuse is not None:
        raise ValueError('Controls require one retained artifact, without retention')
    if reuse is not None and (not isinstance(reuse, str) or not re.fullmatch('[a-f0-9]{10}', reuse)):
        raise ValueError('Invalid retained artifact run')


def selected(baseline, profile, fixture):
    options(profile)
    value = json.loads(json.dumps(baseline))
    if profile == 'build-static-unit-v1':
        from native_diagnostics import TARGETS
        value['name'] = 'eqemu-complete-source-build-static-unit-v1'
        value['native_diagnostics'] = {'targets': list(TARGETS),
                                     'selection': 'fixed representative pilot, not changed-code coverage'}
    if profile == PROFILE:
        value['name'] = 'eqemu-complete-source-actor-lifecycle-v1'
        value['dependencies']['runtime'] = fixture['iso']
        value['actor'] = {'recipe': RECIPE, 'fixture_manifest_sha256': fixture['manifest_sha256']}
    return value


def verify_media(store, fixture, records):
    """Hash opaque ISO/member bytes only. Never extract or execute acquired content."""
    expected = fixture['iso']
    iso = Path(store)/expected['path']
    if records(iso, expected['bytes']) != {k: expected[k] for k in ('bytes', 'sha256')}:
        raise ValueError('Runtime ISO identity mismatch')
    import hashlib
    raw = subprocess.run(['/usr/bin/isoinfo', '-R', '-i', str(iso), '-x', '/runtime-bundle-manifest.json'],
                         check=True, capture_output=True, timeout=30).stdout
    if len(raw) > 32768 or hashlib.sha256(raw).hexdigest() != fixture['manifest_sha256']:
        raise ValueError('Runtime payload manifest identity mismatch')
    manifest = json.loads(raw)
    if manifest != fixture['manifest'] or not 1 <= len(manifest['files']) <= 128:
        raise ValueError('Unexpected runtime manifest')
    seen = set()
    for item in manifest['files']:
        name = item['path']; path = Path(name)
        if path.is_absolute() or '..' in path.parts or str(path) != name or name in seen:
            raise ValueError('Unsafe runtime manifest path')
        seen.add(name)
        data = subprocess.run(['/usr/bin/isoinfo', '-R', '-i', str(iso), '-x', '/'+name],
                              check=True, capture_output=True, timeout=30).stdout
        if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('Runtime member identity mismatch: '+name)
    return {'iso_sha256': expected['sha256'], 'manifest_sha256': fixture['manifest_sha256'],
            'files_verified': len(seen)+1, 'executed': False}


def result(value, exit_code, control=None):
    """Accept only a completed native scenario after native shutdown, never log hints."""
    keys = {'version', 'scenario', 'control', 'status', 'completed_cases', 'cycles',
            'ticks', 'id_reuse', 'save_restore', 'native_cleanup', 'elapsed_seconds'}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError('Actor completion shape')
    if (type(value['version']) is not int or value['version'] != 1
            or value['scenario'] != PROFILE or value['control'] != control
            or type(exit_code) is not int or exit_code not in (0, 1, 2)
            or value['status'] not in ('passed', 'assertion-failed', 'cancelled', 'refused')
            or any(type(value[k]) is not bool for k in ('id_reuse', 'save_restore', 'native_cleanup'))
            or value['native_cleanup'] is not True):
        raise ValueError('Actor completion identity or shutdown')
    if (not isinstance(value['completed_cases'], list)
            or any(not isinstance(c, str) or c not in CASES for c in value['completed_cases'])
            or len(set(value['completed_cases'])) != len(value['completed_cases'])
            or any(type(value[k]) is not int or not 0 <= value[k] <= 1000000 for k in ('cycles', 'ticks'))
            or not isinstance(value['elapsed_seconds'], dict)
            or set(value['elapsed_seconds']) != {'boot', 'processing', 'shutdown'}
            or any(type(t) not in (int, float) or not math.isfinite(t) or not 0 <= t <= ZONE_SECONDS
                   for t in value['elapsed_seconds'].values())):
        raise ValueError('Actor completion counts or timing')
    status = value['status']
    if status == 'passed':
        if (control is not None or exit_code != 0 or set(value['completed_cases']) != CASES
                or value['cycles'] != 3 or value['ticks'] <= 0
                or not value['id_reuse'] or not value['save_restore']):
            raise ValueError('Incomplete actor positive coverage')
    elif status == 'assertion-failed':
        if exit_code != 1 or control not in (None, 'assertion'):
            raise ValueError('Actor assertion status mismatch')
    elif exit_code != 2:
        raise ValueError('Actor refusal or cancellation must be infrastructure non-pass')
    return dict(value, exit_code=exit_code)


def completion(output, exit_code, control=None):
    if len(output.encode()) > 1024**2:
        raise ValueError('Actor output budget')
    lines = [line.removeprefix('EQEMU_ACTOR_RESULT ') for line in output.splitlines()
             if line.startswith('EQEMU_ACTOR_RESULT ')]
    if len(lines) != 1 or len(lines[0]) > 8192:
        raise ValueError('Actor completion missing or duplicated')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('Duplicate actor completion field')
            value[key] = item
        return value
    return result(json.loads(lines[0], object_pairs_hook=unique), exit_code, control)
