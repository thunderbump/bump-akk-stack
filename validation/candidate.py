#!/usr/bin/python3 -I
"""Foreground current-candidate build/unit validation; no inference or review logic."""
import argparse
import grp
import json
import os
from pathlib import Path
import resource
import re
import pwd
import secrets
import signal
import subprocess
import sys
import tempfile
import time
sys.dont_write_bytecode = True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import BASE, HERE, MAX_ISO, PROFILE, candidate_profile, identity, load, sha

HELPER = '/usr/local/sbin/eqemu-build-request'
WORK_SECONDS = 19000
REQUEST_SECONDS = 370
POLL_SECONDS = 3


def request_command():
    """Refresh only this fixed helper's group when an existing member is stale."""
    try:
        account = pwd.getpwuid(os.getuid())
        group = grp.getgrnam('eqemu-test')
    except KeyError as error:
        raise ValueError('Submitter account or group unavailable') from error
    if account.pw_gid != group.gr_gid and account.pw_name not in group.gr_mem:
        raise ValueError('Caller is not a submitter')
    if group.gr_gid in {os.getgid(), *os.getgroups()}:
        return ['/usr/bin/sudo', '-n', HELPER]
    return ['/usr/bin/sg', 'eqemu-test', '-c',
            'exec /usr/bin/sudo -n /usr/local/sbin/eqemu-build-request']


def request(value):
    result = subprocess.run(request_command(), input=json.dumps(value),
                            text=True,capture_output=True,timeout=REQUEST_SECONDS,start_new_session=True)
    if result.returncode:
        raise RuntimeError(result.stderr[-2000:] or 'Build request failed')
    if len(result.stdout.encode())>128*1024:
        raise ValueError('Build report exceeds output budget')
    return json.loads(result.stdout)


def prepare(source, directory, package=HERE):
    inputs = load('candidate_inputs',package/'inputs.py')
    config = json.loads((package/'client-config.json').read_text())
    baseline = json.loads((package/'profile.json').read_text())
    scratch = directory/'git'; scratch.mkdir()
    view = inputs.GitTree(source,scratch)
    candidate = view.location('HEAD')
    tree = view.git('rev-parse',candidate+'^{tree}').decode().strip()
    profile = candidate_profile(baseline,candidate,tree)
    receipt = inputs.prepare(profile,{'eqemu':source,'websocketpp':config['websocketpp']},
                             config['input_store'],directory/'source')
    iso = directory/'candidate.iso'
    subprocess.run(['/usr/bin/genisoimage','-quiet','-R','-J','-V','EQ_CANDIDATE','-o',str(iso),
                    str(directory/'source')],check=True,timeout=120)
    inputs.verify(directory/'source',receipt['manifest_sha256'],profile,receipt['input_id'])
    facts = identity(dict(candidate=candidate,tree=tree,input_id=receipt['input_id'],
                          manifest_sha256=receipt['manifest_sha256'],iso_bytes=iso.stat().st_size,iso_sha256=sha(iso)))
    return iso,facts


def checked(value,identifier,facts,build_id):
    if (not isinstance(value,dict) or type(value.get('version')) is not int or value.get('version')!=1 or value.get('run_id')!=identifier
            or value.get('profile')!=PROFILE or value.get('candidate')!=facts
            or value.get('build_id')!=build_id
            or any(type(value.get(k)) is not bool for k in ('terminal','cleanup_complete','accepted'))
            or type(value.get('exit_code')) is not int or value['exit_code'] not in (0,1,2)
            or value['accepted'] != (value['exit_code']==0)
            or (value['exit_code'] in (0,1) and not (value['terminal'] and value['cleanup_complete']))):
        raise ValueError('Build result identity or completion mismatch')
    return value


def execute(source):
    interrupted = None
    def stop(signum,_frame):
        nonlocal interrupted
        interrupted = interrupted or signum
    previous = {s:signal.signal(s,stop) for s in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP)}
    identifier = secrets.token_hex(5)
    upload = BASE/'uploads'/str(os.getuid())/(identifier+'.iso')
    facts = None; build_id = None; submitted = False; result = None; error = None; secondary = None
    upload_created = False
    deadline = time.monotonic()+WORK_SECONDS
    try:
        if os.geteuid()==0:
            raise ValueError('Run validation as the normal AFK user')
        if not upload.parent.is_dir():
            raise ValueError('Current-candidate build helper is not installed')
        # Generated inputs stay outside the checkout and disappear on every exit.
        with tempfile.TemporaryDirectory(prefix='eqemu-candidate-') as tmp:
            def preparation_timeout(*_):
                raise TimeoutError('Candidate preparation deadline exceeded')
            previous_alarm = signal.signal(signal.SIGALRM, preparation_timeout)
            signal.alarm(600)
            try:
                iso,facts = prepare(Path(source).resolve(),Path(tmp))
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous_alarm)
            if interrupted:
                raise RuntimeError('Interrupted during preparation')
            with iso.open('rb') as src, upload.open('xb') as dst:
                upload_created = True
                os.fchmod(dst.fileno(),0o600)
                while block:=src.read(1024**2):
                    dst.write(block)
            submitted = True  # Caller knows the run ID even if admission response is lost.
            admission = request(dict(version=1,op='run',run_id=identifier,profile=PROFILE,candidate=facts))
            if (not isinstance(admission,dict) or admission.get('run_id')!=identifier
                    or admission.get('candidate')!=facts):
                raise ValueError('Build admission identity mismatch')
            build_id = admission.get('build_id')
            if admission.get('started') is True and (not isinstance(build_id,str) or not re.fullmatch('[a-f0-9]{64}',build_id)):
                raise ValueError('Missing build identity in admission')
            if admission.get('started') is not True:
                result = checked(admission,identifier,facts,build_id)
                raise RuntimeError(result.get('error') or 'Build setup refused')
        upload.unlink(missing_ok=True)
        upload_created = False
        print(json.dumps(dict(event='submitted',run_id=identifier,profile=PROFILE,
                              candidate_revision=facts['candidate'],build_identity=build_id)),flush=True)
        while True:
            if interrupted or time.monotonic()>deadline:
                raise RuntimeError('Interrupted' if interrupted else 'Build command deadline reached')
            result = checked(request(dict(version=1,op='status',run_id=identifier)),identifier,facts,build_id)
            if result['terminal']:
                break
            time.sleep(POLL_SECONDS)
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        error = str(exc)[:2000]
    finally:
        if submitted and (result is None or not result['terminal']):
            try:
                cancelled = request(dict(version=1,op='cancel',run_id=identifier))
                if build_id is None and isinstance(cancelled,dict):
                    build_id = cancelled.get('build_id')
                result = checked(cancelled,identifier,facts,build_id)
            except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
                secondary = str(exc)[:2000]; result = None
        if upload_created:
            try:
                upload.unlink(missing_ok=True)
            except OSError as exc:
                secondary = str(exc)[:2000]
                error = error or 'Owned upload cleanup failed'
        code = 128+interrupted if interrupted else 2 if error or result is None else result['exit_code']
        print(json.dumps(dict(event='final',profile=PROFILE,run_id=identifier if submitted else None,
            candidate_revision=facts['candidate'] if facts else None,build_identity=build_id,
            accepted=code==0,coverage=['compile','utility-tests','fresh-consumer'],
            cleanup_complete=result['cleanup_complete'] if result else None,
            exit_code=code,error=error or (result or {}).get('error'),secondary_error=secondary,
            diagnostics=(result or {}).get('diagnostics',{}))),flush=True)
        for sig,handler in previous.items():signal.signal(sig,handler)
    return code


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path.cwd())
    args=parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS,(1024**3,1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE,(512*1024**2,512*1024**2))
    return execute(args.source)

if __name__=='__main__':
    raise SystemExit(main())
