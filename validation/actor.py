"""Fixed actor profile and completion contract; importing starts no workload."""
import json
import math
from pathlib import Path
import re
import subprocess

PROFILE = 'actor-lifecycle-v1'
PROFILES = ('build-unit-v1', PROFILE)
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
    if manifest != fixture['manifest'] or len(manifest['files']) != 47:
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
