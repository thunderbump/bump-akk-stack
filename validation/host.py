#!/usr/bin/python3 -I
"""Fixed build requests only; never execute submitter-provided host code."""
import contextlib
import fcntl
import grp
import io
import json
import os
from pathlib import Path
import resource
import re
import signal
import stat
import sys
import time
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BASE, HERE, MAX_ISO, PROFILE, candidate_profile, identity, load, outcome, run_id, seal, sha
from render import render
S = load('host_support', HERE/'host_support.py')
S.VERSION = HERE
S.BASE = BASE

# One administrator-reviewed installed release predates maintained packaging.
# This is an admission-only trust pin, not a general historical record reader.
PRIOR_MANIFEST = 'b193e5db558ff5346177941ca531b4ab26228f9aad7bbc7942ab33cd3311498a'
PRIOR_MANIFESTS = (PRIOR_MANIFEST, 'fc320a5152c47403f85332c35f14cf61482a3b1b95d52d68ea557382aeaa8c97',
                   'a1eec9b33bbca1ba1d3c4b8911a1827ca1b1dd4d2ef72657699a0569201ba83a')
LIB = Path('/usr/local/lib/eqemu-build')


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate request key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict) or type(value.get('version')) is not int or value['version'] != 1:
        raise ValueError('Invalid request version')
    run_id(value.get('run_id'))
    required = {'version','op','run_id'}
    if value.get('op') == 'run':
        required |= {'profile','candidate'}
        from actor import options
        retain = value.get('retain_artifact', False)
        control = value.get('qualification_control')
        reuse = value.get('reuse_artifact')
        options(value.get('profile'), control, retain, reuse)
        if 'retain_artifact' in value: required.add('retain_artifact')
        if 'qualification_control' in value: required.add('qualification_control')
        if 'reuse_artifact' in value: required.add('reuse_artifact')
        identity(value.get('candidate'))
    elif value.get('op') not in ('status','cancel','release'):
        raise ValueError('Unknown operation')
    if set(value) != required:
        raise ValueError('Unknown request fields')
    return value


def owner(identifier, uid):
    root = BASE/'runs'/run_id(identifier)
    S.safe_path(root, directory=True)
    record = S.read_json(root/'owner.json')
    if record['uid'] != uid or record['run_id'] != identifier or record['version'] != str(HERE):
        raise ValueError('Run ownership mismatch')
    return root, record


def suite_for(root, record):
    path = root/'prepared/launcher.py'
    S.safe_path(path)
    if sha(path) != record['recipe']['launcher_sha256']:
        raise ValueError('Launcher changed')
    for name, expected in record['recipe']['workers'].items():
        S.safe_path(root/'prepared'/name)
        if sha(root/'prepared'/name) != expected:
            raise ValueError('Worker changed')
    return load('owned_suite', path)


def copy_upload(uid, identifier, facts, target):
    """Open only one fixed upload filename with verified ownership; copy as opaque data."""
    directory = BASE/'uploads'/str(uid)
    fd = os.open(directory, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != uid or info.st_mode & 0o077:
            raise ValueError('Invalid upload directory')
        source_fd = os.open(identifier+'.iso', os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK, dir_fd=fd)
    finally:
        os.close(fd)
    import hashlib
    with os.fdopen(source_fd,'rb') as source, target.open('xb') as output:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1
                or info.st_size != facts['iso_bytes'] or info.st_mode & 0o077):
            raise ValueError('Invalid upload file')
        digest = hashlib.sha256(); remaining = facts['iso_bytes']; deadline = time.monotonic()+90
        while remaining:
            if time.monotonic() > deadline:
                raise ValueError('Upload copy deadline')
            block = source.read(min(1024**2,remaining))
            if not block:
                raise ValueError('Short upload')
            output.write(block); digest.update(block); remaining -= len(block)
        if source.read(1) or digest.hexdigest() != facts['iso_sha256']:
            raise ValueError('Upload changed')
        output.flush(); os.fsync(output.fileno()); os.fchmod(output.fileno(),0o400)


def unstarted_absent(suite, worker):
    return (not worker.ROOT.exists() and not worker.ROOT.is_symlink()
            and suite.properties(worker.UNIT).get('LoadState') == 'not-found'
            and worker.NAME not in worker.virsh('list','--all','--name').stdout.splitlines()
            and not worker.SLICEFILE.exists() and not worker.SLICEFILE.is_symlink()
            and not Path('/sys/fs/cgroup',worker.SLICE).exists())


def report_record(root, record, identifier, persist=True):
    result = dict(version=1, run_id=identifier, profile=record.get('profile',PROFILE), candidate=record['candidate'],
                  build_id=record.get('recipe',{}).get('build_id'), terminal=False,
                  cleanup_complete=False, exit_code=2, accepted=False, error=record.get('error'))
    if record.get('setup_failed_clean'):
        result.update(terminal=True,cleanup_complete=True)
    elif 'recipe' in record:
        suite = suite_for(root,record)
        if not persist:
            if suite.ROOT != root/'work' or suite.LOCAL != root/'prepared' or tuple(suite.CASES) != ('producer','consumer'):
                raise ValueError('Prior recipe roots or cases changed')
            S.safe_path(suite.ROOT, directory=True)
            S.safe_path(suite.SCRIPT)
            if sha(suite.SCRIPT) != record['recipe']['launcher_sha256']:
                raise ValueError('Prior owned launcher changed')
        stopped = suite.quiescent(suite.properties(suite.UNIT))
        result['terminal'] = stopped
        progress = suite.ROOT/'consumer/evidence/report.json'
        if progress.exists():
            stages = S.read_json(progress).get('stages', {})
            result['actor_created'] = stages.get('actor-created', {}).get('state') == 'started'
        else:
            result['actor_created'] = False
        if stopped and (suite.ROOT/'suite-result.json').exists():
            summary = S.read_json(suite.ROOT/'suite-result.json')
            clean = summary.get('cleanup',{}).get('complete') is True
            workers = {}
            for role in suite.CASES:
                if not persist:
                    copied = suite.ROOT/(role+'-worker.py')
                    if copied.exists() or copied.is_symlink():
                        S.safe_path(copied)
                worker = suite.module(role, local=not (suite.ROOT/(role+'-worker.py')).exists())
                if worker.ROOT.exists():
                    if not persist:
                        S.safe_path(worker.ROOT, directory=True)
                        S.safe_path(worker.STATE)
                    clean = clean and suite.quiescent(suite.properties(worker.UNIT)) and suite.absent(worker,worker.state())
                    path = worker.EVIDENCE/'report.json'
                    if path.exists():
                        workers[role] = S.read_json(path)
                else:
                    clean = clean and unstarted_absent(suite,worker)
            leases = S.read_json(suite.ROOT/'leases.json')
            if not persist and (not isinstance(leases, dict) or not isinstance(leases.get('active'), dict)):
                raise ValueError('Prior active lease state is unknown')
            clean = clean and not leases['active']
            producer = suite.module('producer')
            if record.get('retain_artifact') and producer.STORE.exists():
                retained = retained_record(root, record, suite)
                result['retained_artifact'] = retained
            else:
                clean = clean and not producer.STORE.exists()
            if not persist and suite.module('producer').STORE.is_symlink():
                clean = False
            result.update(cleanup_complete=bool(clean), exit_code=outcome(summary,workers,clean,record.get('profile',PROFILE),
                                               record.get('qualification_control'),record.get('reuse_artifact') is not None),
                          error=summary.get('error',record.get('error')))
            result['accepted'] = result['exit_code'] == 0
            result['stages'] = summary.get('cases',{})
            result['diagnostics'] = {role: str(value.get('guest_report_untrusted',{}).get('error') or value.get('error') or '')[-4500:]
                                     for role,value in workers.items()}
            if record.get('profile') == 'actor-lifecycle-v1':
                from actor import summary as actor_summary
                try:
                    observations = workers.get('consumer', {}).get('observations_untrusted', {})
                    if not isinstance(observations, dict):
                        raise ValueError('Actor observation container')
                    observation = observations.get('actor-runtime')
                    result['actor_runtime'] = actor_summary(observation, record.get('qualification_control'))
                except (TypeError, ValueError):
                    # Evidence availability is separate from the existing outcome authority.
                    result['actor_runtime'] = None
    if persist and result['terminal'] and result['cleanup_complete']:
        # Only large copied input media owned by this finished run are removed.
        # Keep small recipes and bounded receipts for inspection, capped at 8 runs.
        for name in ('candidate.iso','producer-seed.iso','consumer-seed.iso'):
            path = root/'prepared'/name
            if path.exists():
                S.safe_path(path); path.unlink()
    if persist:
        S.write_json(root/'result.json',result)
    return result


def report(identifier, uid):
    root, record = owner(identifier, uid)
    return report_record(root, record, identifier)


def prior_report(root, record):
    """Verify explicitly pinned retired releases and query live cleanup without mutation."""
    identifier = run_id(root.name)
    S.safe_path(root, directory=True)
    pinned = next((digest for digest in PRIOR_MANIFESTS if isinstance(record, dict)
                   and record.get('version') == str(LIB/digest[:16])), None)
    if pinned is None:
        raise ValueError('Unknown prior build ownership or release')
    version = LIB/pinned[:16]
    if (not isinstance(record, dict) or type(record.get('uid')) is not int
            or record['uid'] <= 0 or record.get('run_id') != identifier
            or record.get('version') != str(version)):
        raise ValueError('Unknown prior build ownership or release')
    S.safe_path(version, directory=True)
    manifest = S.read_json(version/'manifest.json')
    if sha(version/'manifest.json') != pinned:
        raise ValueError('Prior release manifest changed')
    # The manifest pin also fixes its complete file set and unchanged profile.
    for name, expected in manifest['files'].items():
        if not re.fullmatch('[a-zA-Z0-9_.-]+', name):
            raise ValueError('Prior release manifest path')
        if S.safe_path(version/name).st_size > 256*1024 or sha(version/name) != expected:
            raise ValueError('Prior release file changed: '+name)
    facts = identity(record.get('candidate'))
    recipe = record.get('recipe')
    if (not isinstance(recipe, dict) or set(recipe) != {'build_id','workers','launcher_sha256'}
            or not isinstance(recipe['workers'], dict)
            or set(recipe['workers']) != {'producer-worker.py','consumer-worker.py'}
            or any(not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value)
                   for value in [recipe['build_id'],recipe['launcher_sha256'],*recipe['workers'].values()])):
        raise ValueError('Invalid prior recipe seals')
    profile = candidate_profile(S.read_json(version/'profile.json'), facts['candidate'], facts['tree'])
    expected = seal(dict(profile=profile,input_id=facts['input_id'],
                         manifest_sha256=facts['manifest_sha256'],recipe=manifest['files']))
    if recipe['build_id'] != expected or record.get('setup_failed_clean'):
        raise ValueError('Prior build profile or recipe mismatch')
    receipt = S.read_json(root/'result.json')
    if (not isinstance(receipt, dict) or type(receipt.get('version')) is not int
            or receipt.get('version') != 1 or receipt.get('run_id') != identifier
            or receipt.get('profile') != PROFILE or receipt.get('candidate') != facts
            or receipt.get('build_id') != expected or receipt.get('terminal') is not True
            or receipt.get('cleanup_complete') is not True
            or type(receipt.get('exit_code')) is not int or receipt['exit_code'] not in (0,1,2)
            or type(receipt.get('accepted')) is not bool
            or receipt['accepted'] != (receipt['exit_code'] == 0)):
        raise ValueError('Prior build has no matching completed cleanup receipt')
    return report_record(root, record, identifier, persist=False)



def retained_record(root, record, suite):
    """Separate live worker cleanup from explicitly retained immutable custody."""
    if record.get('profile') != 'actor-lifecycle-v1' or record.get('retain_artifact') is not True:
        raise ValueError('Unexpected retained artifact')
    worker = suite.module('producer')
    path = suite.retained_file(worker)
    value = S.read_json(worker.CUSTODY)
    # Expired bytes remain owned until exact release; expiry forbids reuse.
    if (value.get('identity') != record['recipe']['build_id'] or value.get('eligible') is not True
            or value.get('consumer_verified') is not True or value.get('discarded')
            or value.get('producer_uuid') != suite.ownership_released(worker)['uuid']
            or type(value.get('expires_at')) not in (int,float)
            or not 0 < value['expires_at']-value.get('retained_at',0) <= 86400
            or not re.fullmatch('[a-f0-9]{64}',value.get('sha256',''))
            or not re.fullmatch('[a-f0-9]{64}',value.get('manifest_sha256',''))):
        raise ValueError('Retained custody changed')
    return dict(owner_run=root.name,bytes=path.stat().st_size,sha256=value['sha256'],
                manifest_sha256=value['manifest_sha256'],expires_at=value['expires_at'],
                expired=value['expires_at'] <= time.time())


def reusable_artifact(request, uid):
    """Allow only fresh controls of one successful actor build from this exact release."""
    root, record = owner(request['reuse_artifact'],uid)
    previous = report_record(root, record, root.name)
    retained = previous.get('retained_artifact')
    if (record.get('profile') != request['profile'] or request['profile'] != 'actor-lifecycle-v1'
            or previous['terminal'] is not True or previous['cleanup_complete'] is not True
            or previous['accepted'] is not True or not retained or retained['expired']):
        raise ValueError('Retained actor artifact is unavailable, expired or unqualified')
    if any(record['candidate'][key] != request['candidate'][key]
           for key in ('candidate','tree','input_id','manifest_sha256')):
        raise ValueError('Retained candidate/profile/input identity mismatch')
    baseline = S.read_json(HERE/'profile.json'); fixture = S.read_json(HERE/'runtime-fixture.json')
    profile = candidate_profile(baseline,request['candidate']['candidate'],request['candidate']['tree'],request['profile'],fixture)
    manifest = S.read_json(HERE/'manifest.json')
    expected = seal(dict(profile=profile,input_id=request['candidate']['input_id'],
                         manifest_sha256=request['candidate']['manifest_sha256'],recipe=manifest['files']))
    if record['recipe']['build_id'] != expected:
        raise ValueError('Retained package or build profile changed')
    return root


def start(request, uid):
    identifier = request['run_id']; facts = request['candidate']
    # One build at a time. Unknown cleanup retains the admission reservation.
    for root in (BASE/'runs').iterdir():
        old = S.read_json(root/'owner.json')
        prior = (report(root.name, old['uid']) if old.get('version') == str(HERE)
                 else prior_report(root, old))
        if not prior['terminal'] or not prior['cleanup_complete']:
            raise RuntimeError('Previous build active or cleanup incomplete: '+root.name)
        if request.get('retain_artifact') and prior.get('retained_artifact'):
            raise RuntimeError('One retained qualification artifact already exists; release exact owner first')
    if len(list((BASE/'runs').iterdir())) >= 8:
        raise RuntimeError('Eight-run retention limit; administrator review required')
    if os.statvfs('/var/lib').f_bavail*os.statvfs('/var/lib').f_frsize < 180*1024**3:
        raise RuntimeError('Build admission requires 180 GiB free disk')
    reuse_root = None
    if request.get('reuse_artifact'):
        reuse_root = reusable_artifact(request, uid)
    root = BASE/'runs'/identifier
    root.mkdir(mode=0o711); root.chmod(0o711)
    prepared = root/'prepared'; prepared.mkdir(mode=0o700)
    record = dict(uid=uid,run_id=identifier,version=str(HERE),candidate=facts,created_at=time.time(),
                  profile=request['profile'], retain_artifact=request.get('retain_artifact',False))
    if reuse_root is not None:
        record.update(reuse_artifact=request['reuse_artifact'], qualification_control=request['qualification_control'])
    S.write_json(root/'owner.json',record)
    try:
        copy_upload(uid,identifier,facts,prepared/'candidate.iso')
        record['recipe'] = render(identifier,facts,prepared,profile_name=request['profile'],
                                  control=request.get('qualification_control'),retain=request.get('retain_artifact',False),
                                  reuse_root=reuse_root)
        S.write_json(root/'owner.json',record)
        suite = suite_for(root,record)
        with contextlib.redirect_stdout(io.StringIO()):
            suite.setup()
    except Exception as error:
        record['error'] = str(error)[:2000]
        # Only pre-launch failures with no work directory are trivially clean.
        # Partial supervisor setup retains the reservation for exact recovery.
        record['setup_failed_clean'] = not (root/'work').exists()
        S.write_json(root/'owner.json',record)
        return report(identifier,uid)
    return dict(started=True,run_id=identifier,accepted=False,candidate=facts,build_id=record['recipe']['build_id'])


def dispatch(request,uid):
    S.safe_path(BASE/'request.lock')
    with (BASE/'request.lock').open('r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if request['op']=='run':
            installation=S.read_json(BASE/'installation.json')
            if installation.get('enabled') is not True or installation.get('version')!=str(HERE):
                raise ValueError('Build admission disabled or installation changed')
            return start(request,uid)
        root,record = owner(request['run_id'],uid)
        if request['op']=='release':
            if not record.get('retain_artifact') or record.get('profile') != 'actor-lifecycle-v1':
                raise ValueError('Run does not own a qualification artifact')
            state = report(request['run_id'],uid)
            if not state['terminal'] or not state['cleanup_complete']:
                raise ValueError('Cannot release an active or uncertain run')
            for other in (BASE/'runs').iterdir():
                if other == root: continue
                child = S.read_json(other/'owner.json')
                if child.get('reuse_artifact') == root.name:
                    child_status = report(other.name, child['uid'])
                    if not child_status['terminal'] or not child_status['cleanup_complete']:
                        raise ValueError('Retained artifact has an active or uncertain consumer')
            suite = suite_for(root,record)
            with contextlib.redirect_stdout(io.StringIO()): suite.discard_artifact()
            return dict(released=True,run_id=request['run_id'],vm_started=False)
        if request['op']=='cancel' and 'recipe' in record:
            suite = suite_for(root,record)
            if not suite.quiescent(suite.properties(suite.UNIT)):
                suite.run(['/usr/bin/systemctl','stop',suite.UNIT],timeout=330)
        return report(request['run_id'],uid)


def main():
    if os.geteuid()!=0 or len(sys.argv)!=1:
        raise ValueError('Use the installed no-argument helper')
    os.umask(0o077)
    for signum in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP):
        signal.signal(signum,signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    S.verify_installation()
    uid = S.caller_uid()
    S.parse_request = parse
    request = S.read_request(0)
    os.environ.clear(); os.environ.update(S.ENV)
    print(json.dumps(dispatch(request,uid)),flush=True)

if __name__=='__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'error':str(error)[:2000]}),file=sys.stderr)
        sys.exit(2)
