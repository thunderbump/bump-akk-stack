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


def candidate_profile(baseline, candidate, tree, profile_name=PROFILE, fixture=None):
    from actor import selected
    profile = selected(baseline, profile_name, fixture)
    profile['sources']['eqemu'].update(commit=candidate, tree=tree)
    return profile


def worker_safe(worker):
    """Candidate classification requires measured resources and sealed host inputs."""
    try:
        resources = worker['resource_observations']
        memory = dict(line.split() for line in resources['memory.events'].splitlines())
        pids = dict(line.split() for line in resources['pids.events'].splitlines())
        return (all(memory[k] == '0' for k in ('oom', 'oom_kill')) and pids['max'] == '0'
                and worker['service_result'] in ('success', 'exit-code')
                and worker['cleanup']['readonly_inputs_unchanged'] is True
                and worker['checks']['host_pre_resume'] is True)
    except (KeyError, ValueError, AttributeError, TypeError):
        return False


def candidate_failure(worker, consumer=False):
    if not worker_safe(worker):
        return False
    guest = worker.get('guest_report_untrusted', {})
    if not isinstance(guest, dict):
        return False
    error = guest.get('error', '')
    controls = 'reporting-controls|runner-(?:pass|fail|empty|setup-exception|body-exception|teardown-exception)'
    stages = 'upstream-tests|' + controls if consumer else 'configure|server-build|runner-control-build|upstream-tests|' + controls
    return (guest.get('ok') is False and isinstance(error, str)
            and (re.match(r'^(' + stages + r'): exit [1-9][0-9]*\n', error)
                 or re.match(r'^upstream-tests: exit -(4|6|7|8|11)\n', error))
            and not re.search(r'(?i)out of memory|cannot allocate memory|no space left|killed signal', error))


def outcome(summary, workers, clean, profile=PROFILE, control=None, reused=False):
    """Selected coverage must complete. Unknown failures never trigger repair."""
    if not clean:
        return 2
    cleanup = summary.get('cleanup', {})
    ordinary_cleanup = not cleanup.get('rescued') and 'controller_budget_error' not in cleanup
    producer = workers.get('producer', {})
    consumer = workers.get('consumer', {})
    producer_guest = producer.get('guest_report_untrusted') if isinstance(producer,dict) else None
    known_consumer_failure = (summary.get('cases', {}).get('producer', {}).get('case_passed') is True
                             and worker_safe(producer) and isinstance(producer_guest,dict)
                             and producer_guest.get('ok') is True
                             and candidate_failure(consumer,consumer=True)
                             and consumer['cleanup'].get('artifact_input_unchanged') is True)
    # Utility checks precede the actor stage. Their existing narrow failure evidence
    # stays repairable in ordinary runs, but cannot qualify an unexecuted control.
    if ordinary_cleanup and control is None and (candidate_failure(producer) or known_consumer_failure):
        return 1
    from actor import PROFILE as ACTOR, result
    if profile == ACTOR:
        consumer = workers.get('consumer', {})
        actor = consumer.get('observations_untrusted', {}).get('actor-runtime', {})
        try:
            record = dict(actor['result']); code = record.pop('exit_code')
            result(record, code, control)
            proven = (actor['database_cleanup'] is True and actor['outputs_unchanged'] is True
                      and actor['inputs_unchanged'] is True and worker_safe(consumer)
                      and consumer['cleanup'].get('artifact_input_unchanged') is True
                      and consumer.get('stages', {}).get('actor-lifecycle', {}).get('state') in ('passed', 'failed'))
        except (KeyError, ValueError, TypeError):
            proven = False
        producer_ok = reused or (summary.get('cases', {}).get('producer', {}).get('case_passed') is True
                               and worker_safe(workers.get('producer', {})))
        if not proven or not producer_ok:
            return 2
        guest = consumer.get('guest_report_untrusted', {})
        evidenced_assertion = (code == 1 and guest.get('ok') is False
                               and re.match(r'^actor-lifecycle: exit 1\n', guest.get('error', ''))
                               and ordinary_cleanup)
        if control is not None:
            return 1 if control == 'assertion' and evidenced_assertion else 2
        if evidenced_assertion:
            return 1
        if code != 0:
            return 2
    if summary.get('suite_passed') is True and summary.get('cases_passed') is True:
        cases = summary.get('cases', {})
        if set(cases) == ({'consumer'} if reused else {'producer', 'consumer'}) and all(cases[c].get('case_passed') is True for c in cases):
            return 0
    # Candidate failure requires ordinary cleanup without rescue or controller faults.
    cleanup = summary.get('cleanup', {})
    if cleanup.get('rescued') or 'controller_budget_error' in cleanup:
        return 2
    producer = workers.get('producer', {})
    if candidate_failure(producer):
        return 1
    consumer = workers.get('consumer', {})
    producer_guest = producer.get('guest_report_untrusted') if isinstance(producer, dict) else None
    if (summary.get('cases', {}).get('producer', {}).get('case_passed') is True
            and worker_safe(producer)
            and isinstance(producer_guest, dict) and producer_guest.get('ok') is True
            and candidate_failure(consumer, consumer=True)
            and consumer['cleanup'].get('artifact_input_unchanged') is True):
        return 1
    return 2
