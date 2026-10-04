"""Small shared interface for candidate identity and deterministic results."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
BASE = Path('/var/lib/eqemu-build')
PROFILE = 'build-unit-v1'
MAX_ISO = 300 * 1024**2
FIELDS = {'candidate', 'tree', 'input_id', 'manifest_sha256', 'iso_sha256', 'iso_bytes'}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def seal(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def identity(value):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError('Invalid candidate fields')
    for key in FIELDS - {'iso_bytes'}:
        length = 40 if key in ('candidate', 'tree') else 64
        if not isinstance(value[key], str) or not re.fullmatch('[a-f0-9]{' + str(length) + '}', value[key]):
            raise ValueError('Invalid candidate identity: ' + key)
    if type(value['iso_bytes']) is not int or not 0 < value['iso_bytes'] <= MAX_ISO:
        raise ValueError('Candidate ISO exceeds budget')
    return value


def run_id(value):
    if not isinstance(value, str) or not re.fullmatch('[a-f0-9]{10}', value):
        raise ValueError('Invalid run ID')
    return value


def candidate_profile(baseline, candidate, tree):
    profile = json.loads(json.dumps(baseline))
    profile['sources']['eqemu'].update(commit=candidate, tree=tree)
    return profile


def outcome(summary, workers, clean):
    """Scope is build/unit only. Unknown failures never trigger automatic repair."""
    if not clean:
        return 2
    if summary.get('suite_passed') is True and summary.get('cases_passed') is True:
        cases = summary.get('cases', {})
        if set(cases) == {'producer', 'consumer'} and all(cases[c].get('case_passed') is True for c in cases):
            return 0
    # A completed guest command failure is actionable only after ordinary cleanup,
    # without rescue or a controller resource failure. Missing protocol stays infra.
    cleanup = summary.get('cleanup', {})
    if cleanup.get('rescued') or 'controller_budget_error' in cleanup:
        return 2
    producer = workers.get('producer', {})
    try:
        resources = producer['resource_observations']
        memory = dict(line.split() for line in resources['memory.events'].splitlines())
        pids = dict(line.split() for line in resources['pids.events'].splitlines())
        resource_ok = all(memory[k] == '0' for k in ('oom','oom_kill')) and pids['max'] == '0'
    except (KeyError, ValueError, AttributeError, TypeError):
        resource_ok = False
    if (not resource_ok or producer.get('service_result') not in ('success','exit-code')
            or producer.get('cleanup',{}).get('readonly_inputs_unchanged') is not True):
        return 2
    guest = producer.get('guest_report_untrusted', {})
    error = guest.get('error', '')
    if (guest.get('ok') is False and producer.get('checks', {}).get('host_pre_resume') is True
            and isinstance(error, str)
            and (re.match(r'^(configure|server-build|runner-control-build|upstream-tests): exit [1-9][0-9]*\n', error)
                 or re.match(r'^upstream-tests: exit -(4|6|7|8|11)\n', error))
            and not re.search(r'(?i)out of memory|cannot allocate memory|no space left|killed signal', error)):
        return 1
    return 2
