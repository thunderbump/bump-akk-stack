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


def render(identifier, facts, destination, package=HERE):
    run_id(identifier); identity(facts)
    destination = Path(destination)
    baseline = json.loads((package/'profile.json').read_text())
    profile = candidate_profile(baseline, facts['candidate'], facts['tree'])
    manifest = json.loads((package/'manifest.json').read_text())
    build_id = seal({'profile': profile, 'input_id': facts['input_id'],
                     'manifest_sha256': facts['manifest_sha256'], 'recipe': manifest['files']})
    previous = json.loads((package/'recipe-binding.json').read_text())
    binding = {k: facts[k] for k in ('candidate', 'tree', 'input_id', 'manifest_sha256')}
    root = BASE/'runs'/identifier/'work'
    inputs = json.loads((package/'host-inputs.json').read_text())
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
                    guest = assign(guest, 'CANDIDATE_INPUT', facts['input_id'])
                    guest = assign(guest, 'CANDIDATE_SEAL', facts['manifest_sha256'])
                    guest = assign(guest, 'CANDIDATE_FACTS', binding)
                entry['content'] = guest
                compile(guest, role+'-guest.py', 'exec')
        ud = destination/(role+'-user-data'); md = destination/(role+'-meta-data')
        ud.write_text('#cloud-config\n'+json.dumps(user)+'\n')
        md.write_text('instance-id: eqemu-build-'+identifier+'-'+role+'\n')
        seed = destination/(role+'-seed.iso')
        subprocess.run(['/usr/bin/cloud-localds', str(seed), str(ud), str(md)], check=True, timeout=30)
        worker = rename((package/(role+'-worker.py.in')).read_text())
        worker = re.sub(r'^INPUTS=.+$', 'INPUTS=P('+repr(str(destination))+')', worker, count=1, flags=re.M)
        files = {name: (str(BASE/'inputs'/name), item['bytes'], item['sha256']) for name,item in inputs.items()}
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
    suite = suite.replace(previous['input_id'], facts['input_id'])
    # Routine validation discards its own handoff artifact after the fresh consumer.
    suite = replace_once(suite, "keep = (result.get('cases_passed') is True", "keep = (False and result.get('cases_passed') is True")
    compile(suite, 'launcher.py', 'exec')
    (destination/'launcher.py').write_text(suite)
    return {'build_id': build_id, 'workers': hashes, 'launcher_sha256': sha(destination/'launcher.py')}
