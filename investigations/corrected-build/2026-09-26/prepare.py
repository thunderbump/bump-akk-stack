#!/usr/bin/python3
"""Prepare corrected build 01. No VM launch, candidate execution, or host guest-filesystem mount."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parent
REPO = SOURCE.parents[2]
LOCAL = Path('/home/bump/.local/state/eqemu-vm-proof')
OUTPUT = LOCAL/'corrected-build-inputs-01'
LAUNCHER = LOCAL/'offline-corrected-build-01.py'
ROOT = Path('/var/lib/eqemu-vm-proof/corrected-build-01')
EQEMU = Path('/home/bump/Projects/bump-eqemu/test-outcome-preparation')
BASELINE = '4aceae18b94ffaafc08e2b17bc41cd72c77f795d'
CANDIDATE = '1c561d442638b3da8d20e93ac105f98a227d37f2'
ARTIFACT = REPO/'investigations/artifact-handoff/2026-09-26'
spec = importlib.util.spec_from_file_location('handoff_prepare', ARTIFACT/'prepare.py')
helpers = importlib.util.module_from_spec(spec); spec.loader.exec_module(helpers)
replace_once = helpers.replace_once


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def git(*args):
    return subprocess.run(['git', '-C', str(EQEMU), *args], check=True, capture_output=True).stdout


def prepare():
    if any(p.exists() or p.is_symlink() for p in [ROOT, OUTPUT, LAUNCHER]):
        raise RuntimeError('Preserve existing attempt; do not regenerate launched inputs')
    names = sorted(git('diff', '--name-only', BASELINE, CANDIDATE).decode().splitlines())
    if names != ['tests/CMakeLists.txt', 'tests/main.cpp', 'tests/runner_controls.cpp', 'tests/suite_runner.h']:
        raise RuntimeError('Unexpected candidate changes')
    files = []
    for name in names:
        content = git('show', CANDIDATE + ':' + name)
        before = git('show', BASELINE + ':' + name) if name in ['tests/CMakeLists.txt', 'tests/main.cpp'] else None
        files.append({'path': name, 'hex': content.hex(), 'sha256': hashlib.sha256(content).hexdigest(),
                      'before_sha256': hashlib.sha256(before).hexdigest() if before is not None else None})
    overlay = json.dumps({'baseline': BASELINE, 'candidate': CANDIDATE, 'files': files}, sort_keys=True)
    candidate = {'baseline': BASELINE, 'candidate': CANDIDATE, 'overlay_sha256': hashlib.sha256(overlay.encode()).hexdigest()}
    sources = {str(p.relative_to(REPO)): sha(p) for p in sorted(SOURCE.rglob('*.py'))}
    sources.update({str(p.relative_to(REPO)): sha(p) for p in [ARTIFACT/'diagnostics.py', ARTIFACT/'prepare.py',
        REPO/'investigations/runtime-proof/2026-09-26/runtime-proof-inputs-03/build-worker.py']})
    experiment = hashlib.sha256(json.dumps({'sources': sources, 'candidate': candidate}, sort_keys=True).encode()).hexdigest()
    stage = Path(tempfile.mkdtemp(prefix='.corrected-build-', dir=LOCAL))
    try:
        guest = (SOURCE/'templates/guest.py').read_text()
        guest = replace_once(guest, 'cap=64*1024**2):', 'cap=64*1024**2,expected_exit=0):')
        guest = replace_once(guest, "if rc!=0:", "if rc!=expected_exit:")
        guest = replace_once(guest, " vp=src/'submodules/vcpkg'", " apply_candidate(src)\n vp=src/'submodules/vcpkg'")
        guest = replace_once(guest, " command('server-build'", " runner_controls()\n command('server-build'")
        guest = replace_once(guest, " command('upstream-tests',[str(WORK/'build/bin/tests')],timeout=600,cwd=WORK/'build')", " real_utility_suite()\n measure_outputs()")
        guest = replace_once(guest, "'-DCMAKE_BUILD_TYPE=RelWithDebInfo'", "'-DCMAKE_BUILD_TYPE=RelWithDebInfo','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'")
        guest = replace_once(guest, "emit({'kind':'ready','manifest_sha256':MANIFEST_SHA})", "emit({'kind':'ready','manifest_sha256':MANIFEST_SHA,'experiment_sha256':"+repr(experiment)+"})")
        # Serial writes also have a local deadline; the host still owns the overall kill limit.
        guest = replace_once(guest, ' while data:data=data[os.write(FD,data):]', ''' end=time.monotonic()+10
 while data:
  if time.monotonic()>=end:raise RuntimeError('Serial write deadline')
  if select.select([],[FD],[],.2)[1]:
   try:data=data[os.write(FD,data):]
   except BlockingIOError:pass''')
        guest = replace_once(guest, 'tty.setraw(FD);EMIT=emit', 'tty.setraw(FD);os.set_blocking(FD,False);EMIT=emit')
        extension = '\n'.join((p.read_text() for p in [ARTIFACT/'diagnostics.py', SOURCE/'outcomes.py', SOURCE/'guest_extension.py']))
        guest = replace_once(guest, "if __name__=='__main__':main()", extension+"\nif __name__=='__main__':main()")
        config = {'package_update': False, 'package_upgrade': False, 'users': [], 'ssh_pwauth': False,
                  'disable_root': True, 'growpart': {'mode': 'auto', 'devices': ['/'], 'ignore_growroot_disabled': False},
                  'write_files': [
                    {'path': '/opt/eqemu-proof/guest_build.py', 'permissions': '0700', 'content': guest},
                    {'path': '/opt/eqemu-proof/BUILD_GUEST_ONLY', 'permissions': '0600', 'content': 'corrected-build-01\n'},
                    {'path': '/opt/eqemu-proof/candidate.json', 'permissions': '0600', 'content': overlay},
                    {'path': '/etc/cloud/cloud.cfg.d/99-offline.cfg', 'content': 'network: {config: disabled}\n'}],
                  'runcmd': [['systemctl', 'mask', '--now', 'apt-daily.timer', 'apt-daily-upgrade.timer'],
                             ['python3', '-I', '/opt/eqemu-proof/guest_build.py']]}
        (stage/'guest.py').write_text(guest)
        (stage/'user-data').write_text('#cloud-config\n'+json.dumps(config, indent=2)+'\n')
        (stage/'meta-data').write_text('instance-id: eqemu-corrected-build-01\nlocal-hostname: eqemu-build\n')
        subprocess.run(['cloud-localds', str(stage/'seed.iso'), str(stage/'user-data'), str(stage/'meta-data')], check=True)
        worker = (REPO/'investigations/runtime-proof/2026-09-26/runtime-proof-inputs-03/build-worker.py').read_text()
        worker = worker.replace('runtime-proof-03', 'corrected-build-01').replace('runtime-03', 'corrected-build-01').replace('runtime03', 'correctedbuild01')
        worker = replace_once(worker, "NAME='eqemu-corrected-build-01'", "NAME='eqemu-cbuild-01'")
        name = re.search(r"^NAME='([^']+)'$", worker, re.M)[1]
        if not re.fullmatch('[a-z0-9-]{1,20}', name): raise RuntimeError('Invalid domain name')
        worker = '\n'.join(line for line in worker.split('\n') if "'runtime.iso':" not in line and '{DATA}/runtime.iso' not in line)
        worker = worker.replace("['seed.iso','fixture.iso','runtime.iso']", "['seed.iso','fixture.iso']")
        worker = re.sub(r"'seed.iso':\([^\n]+", "'seed.iso':"+repr(('corrected-build-inputs-01/seed.iso', (stage/'seed.iso').stat().st_size, sha(stage/'seed.iso')))+',', worker, count=1)
        transport = (SOURCE/'templates/host-transport.py').read_text()
        transport = transport.replace('class BuildProtocol:', 'class BaseBuildProtocol:')
        index = transport.index('def collect_build(')
        extension = '\n'.join(p.read_text() for p in [ARTIFACT/'diagnostics.py', SOURCE/'outcomes.py', SOURCE/'host_extension.py'])
        transport = transport[:index] + '\nEXPERIMENT_SHA='+repr(experiment)+'\nCANDIDATE='+repr(candidate)+'\n'+extension+'\n'+transport[index:]
        transport = replace_once(transport, "                elif kind=='preflight':report", "                elif kind=='observation':report.setdefault('observations_untrusted',{})[v['name']]=v['value']\n                elif kind=='preflight':report")
        transport = transport.replace("len(report['stages'])>=50", "len(report['stages'])>=200")
        start = worker.index('MANIFEST_SHA='); end = worker.index('def main():', start)
        worker = worker[:start]+transport+'\n'+worker[end:]
        (stage/'build-worker.py').write_text(worker)
        suite = (SOURCE/'templates/suite.py').read_text().replace('build-proof-04','corrected-build-01').replace('build-04','corrected-build-01').replace('build04','correctedbuild01').replace('build-proof-inputs-v4','corrected-build-inputs-01')
        suite = re.sub(r'HASHES=\{[^\n]+\}', 'HASHES='+repr({'build-worker.py':sha(stage/'build-worker.py')}), suite, count=1)
        # Previous build receipt is historical provenance only. Its tests are not treated as trustworthy.
        suite = replace_once(suite, "        receipt['controller_budget']=controller_budget()", "        try:receipt['controller_budget']=controller_budget()\n        except Exception as error:receipt['controller_budget_error']=str(error)[:2000]")
        suite = replace_once(suite, "        CTLFILE.unlink();receipt['complete']=True", "        CTLFILE.unlink();run(['systemctl','daemon-reload']);receipt['complete']=True")
        suite = replace_once(suite, "and not receipt['rescued'] and r['service_result']=='success'", "and not receipt['rescued'] and 'controller_budget_error' not in receipt and r['service_result']=='success'")
        for name, code in [('guest.py', guest), ('build-worker.py', worker), ('launcher.py', suite)]:
            compile(code, name, 'exec'); (stage/name).write_text(code)
        (stage/'preparation.json').write_text(json.dumps({'scope':'corrected candidate build and ELF measurements; no artifact publication or runtime scenario',
            'experiment_sha256':experiment, 'candidate':candidate, 'sources':sources,
            'worker_sha256':sha(stage/'build-worker.py'), 'launcher_sha256':sha(stage/'launcher.py'),
            'seed_sha256':sha(stage/'seed.iso'), 'vm_started':False}, indent=2)+'\n')
        stage.rename(OUTPUT); LAUNCHER.write_text(suite)
        print(json.dumps({'prepared':str(OUTPUT),'launcher':str(LAUNCHER),'vm_started':False}))
    finally:
        if stage.exists(): shutil.rmtree(stage)


if __name__ == '__main__': prepare()
