"""Render only installed, sealed recipes. Candidate input is opaque ISO data."""
import ast
import json
from pathlib import Path
import re
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import BASE, HERE, candidate_profile, identity, run_id, seal, sha


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Pinned recipe seam changed: ' + old[:80])
    return text.replace(old, new, 1)


def assign(text, name, value):
    tree = ast.parse(text)
    nodes = [n for n in tree.body if isinstance(n, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
    if len(nodes) != 1:
        raise ValueError('Pinned constant changed: ' + name)
    node = nodes[0]
    lines = text.splitlines(keepends=True)
    return ''.join(lines[:node.lineno-1]) + name + '=' + repr(value) + '\n' + ''.join(lines[node.end_lineno:])


def render(identifier, facts, destination, package=HERE, profile_name='build-unit-v1', control=None, retain=False, reuse_root=None):
    run_id(identifier); identity(facts)
    destination = Path(destination)
    baseline = json.loads((package/'profile.json').read_text())
    from actor import PROFILE as ACTOR, options
    options(profile_name, control, retain, reuse_root.name if reuse_root is not None else None)
    fixture = json.loads((package/'runtime-fixture.json').read_text())
    profile = candidate_profile(baseline, facts['candidate'], facts['tree'], profile_name, fixture)
    manifest = json.loads((package/'manifest.json').read_text())
    build_id = seal({'profile': profile, 'input_id': facts['input_id'],
                     'manifest_sha256': facts['manifest_sha256'], 'recipe': manifest['files']})
    previous = json.loads((package/'recipe-binding.json').read_text())
    binding = {k: facts[k] for k in ('candidate', 'tree', 'input_id', 'manifest_sha256')}
    root = BASE/'runs'/identifier/'work'
    inputs = json.loads((package/'host-inputs.json').read_text())
    if profile_name == ACTOR and 'runtime.iso' not in inputs:
        raise ValueError('Actor runtime input is not installed')
    inputs = {k: v for k, v in inputs.items() if k != 'runtime.iso' or profile_name == ACTOR}
    def rename(text):
        return (text.replace("BASE=P('/var/lib/eqemu-vm-proof')", "BASE=P("+repr(str(BASE/'runs'))+")")
                .replace("'candidate-build-01'", repr(identifier+'/work'))
                .replace('eqemu-vm-candidate-build-01-', 'eqemu-vm-b'+identifier+'-')
                .replace('eqemuvmcandidatebuild01', 'eqemuvmb'+identifier)
                .replace('eqemu-vm-cb-prod01', 'eqemu-vm-bp'+identifier)
                .replace('eqemu-vm-cb-cons01', 'eqemu-vm-bc'+identifier)
                .replace('eqemu-cb-prod01', 'eqemu-bp'+identifier)
                .replace('eqemu-cb-cons01', 'eqemu-bc'+identifier)
                .replace('eqemuvmcandidatebuildprod01', 'eqemuvmbp'+identifier)
                .replace('eqemuvmcandidatebuildcons01', 'eqemuvmbc'+identifier)
                .replace(previous['build_id'], build_id))
    hashes = {}
    for role in ('producer', 'consumer'):
        user = json.loads((package/(role+'-user.json')).read_text())
        for entry in user['write_files']:
            if 'content_file' in entry:
                entry['content'] = (package/entry.pop('content_file')).read_text()
            if entry['path'].endswith('/candidate-profile.json'):
                entry['content'] = json.dumps(profile)
            elif entry['path'].endswith('/guest_build.py'):
                guest = entry['content'].replace(previous['build_id'], build_id)
                if role == 'producer':
                    guest = assign(guest, 'VALIDATION_PROFILE', profile_name)
                    guest = assign(guest, 'CANDIDATE_INPUT', facts['input_id'])
                    guest = assign(guest, 'CANDIDATE_SEAL', facts['manifest_sha256'])
                    guest = assign(guest, 'CANDIDATE_FACTS', binding)
                if role == 'consumer':
                    guest = assign(guest, 'VALIDATION_PROFILE', profile_name)
                    guest = assign(guest, 'QUALIFICATION_CONTROL', control)
                    if profile_name == ACTOR:
                        guest = guest.replace('DEADLINE=time.monotonic()+1800', 'DEADLINE=time.monotonic()+3900')
                entry['content'] = guest
                compile(guest, role+'-guest.py', 'exec')
        if role == 'producer':
            user['write_files'].append(dict(path='/opt/eqemu-proof/native_diagnostics.py', permissions='0600',
                                           content=(package/'native_diagnostics.py').read_text()))
        if role == 'consumer' and profile_name == ACTOR:
            for name in ('actor.py', 'actor_runtime.py', 'runtime-fixture.json', 'debugger.py', 'debugger-gdb.py'):
                user['write_files'].append(dict(path='/opt/eqemu-proof/'+name, permissions='0600', content=(package/name).read_text()))
        ud = destination/(role+'-user-data'); md = destination/(role+'-meta-data')
        ud.write_text('#cloud-config\n'+json.dumps(user)+'\n')
        md.write_text('instance-id: eqemu-build-'+identifier+'-'+role+'\n')
        seed = destination/(role+'-seed.iso')
        subprocess.run(['/usr/bin/cloud-localds', str(seed), str(ud), str(md)], check=True, timeout=30)
        worker = rename((package/(role+'-worker.py.in')).read_text())
        if role == 'producer':
            worker = assign(worker, 'VALIDATION_PROFILE', profile_name)
            worker = worker.replace('P=pathlib.Path', 'sys.path.insert(0, '+repr(str(package.resolve()))+')\nP=pathlib.Path', 1)
        worker = re.sub(r'^INPUTS=.+$', 'INPUTS=P('+repr(str(destination))+')', worker, count=1, flags=re.M)
        files = {name: (str(BASE/'inputs'/name), item['bytes'], item['sha256']) for name,item in inputs.items() if name != 'runtime.iso' or role == 'consumer'}
        worker = assign(worker, 'VALIDATION_PROFILE', profile_name) if role == 'consumer' else worker
        if role == 'consumer':
            worker = assign(worker, 'QUALIFICATION_CONTROL', control)
            worker = assign(worker, 'ACTOR_FIXTURE', fixture)
            worker = worker.replace('P=pathlib.Path', 'sys.path.insert(0, '+repr(str(package.resolve()))+')\nP=pathlib.Path', 1)
            if profile_name == ACTOR:
                worker = worker.replace('{DATA}/fixture.iso rk,', '{DATA}/fixture.iso rk,\n  {DATA}/runtime.iso rk,')
                disk = '<disk type="file" device="cdrom"><driver name="qemu" type="raw"/><source file="{DATA}/runtime.iso"/><target dev="sdc" bus="sata"/><readonly/></disk>'
                worker = worker.replace('    <serial type="unix">', '    '+disk+'\n    <serial type="unix">', 1)
                worker = worker.replace("for name in ['seed.iso','fixture.iso']", "for name in ['seed.iso','fixture.iso','runtime.iso']")
                worker = worker.replace('deadline=time.monotonic()+1800', 'deadline=time.monotonic()+3900')
            if reuse_root is not None:
                worker = replace_once(worker, 'STORE = ROOT.parent / \'retained\'', 'STORE = P('+repr(str(reuse_root/'work/retained'))+')')
                worker = replace_once(worker, 'CUSTODY = ROOT.parent / \'custody.json\'', 'CUSTODY = P('+repr(str(reuse_root/'work/custody.json'))+')')
                worker = worker.replace("ROOT.parent/'producer/evidence/report.json'", 'P('+repr(str(reuse_root/'work/producer/evidence/report.json'))+')')
        files['seed.iso'] = (seed.name, seed.stat().st_size, sha(seed))
        if role == 'producer':
            files['candidate.iso'] = ('candidate.iso', facts['iso_bytes'], facts['iso_sha256'])
        worker = assign(worker, 'FILES', files)
        worker = assign(worker, 'CANDIDATE', binding)
        compile(worker, role+'-worker.py', 'exec')
        path = destination/(role+'-worker.py'); path.write_text(worker)
        hashes[path.name] = sha(path)
    suite = rename((package/'suite.py.in').read_text())
    suite = re.sub(r'^LOCAL=.+$', 'LOCAL=P('+repr(str(destination))+')', suite, count=1, flags=re.M)
    suite = assign(suite, 'HASHES', hashes)
    suite = assign(suite, 'EXECUTE_CASES', ('consumer',) if reuse_root is not None else ('producer', 'consumer'))
    suite = assign(suite, 'RETAIN_ARTIFACT', retain)
    suite = suite.replace(previous['input_id'], facts['input_id'])
    # Routine validation discards its own handoff artifact after the fresh consumer.
    suite = replace_once(suite, "keep = (result.get('cases_passed') is True", "keep = (RETAIN_ARTIFACT and result.get('cases_passed') is True")
    suite = suite.replace('time.time()+7*86400', 'time.time()+86400')
    compile(suite, 'launcher.py', 'exec')
    (destination/'launcher.py').write_text(suite)
    return {'build_id': build_id, 'workers': hashes, 'launcher_sha256': sha(destination/'launcher.py')}
