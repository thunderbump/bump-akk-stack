#!/usr/bin/python3
"""Prepare one complete-source producer/consumer attempt. Starts no VM."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parent
REPO = SOURCE.parents[2]
LOCAL = Path('/home/bump/.local/state/eqemu-vm-proof')
PREVIOUS = LOCAL/'build-handoff-inputs-01'
PACKAGE = LOCAL/'sealed-candidate-inputs-01'
OUTPUT = LOCAL/'candidate-build-inputs-01'
LAUNCHER = LOCAL/'offline-candidate-build-01.py'
ROOT = Path('/var/lib/eqemu-vm-proof/candidate-build-01')
INPUT_SOURCE = REPO/'investigations/candidate-inputs/2026-09-28'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inputs = load('inputs', INPUT_SOURCE/'inputs.py')
helpers = load('helpers', REPO/'investigations/artifact-handoff/2026-09-26/prepare.py')
replace_once = helpers.replace_once


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def literal(code, name):
    for node in ast.parse(code).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError('Missing fixed template constant: ' + name)


def renamed(code):
    return (code.replace('build-handoff-inputs-01', OUTPUT.name)
            .replace('build-handoff-01', ROOT.name).replace('buildhandoff', 'candidatebuild')
            .replace('eqemu-bh-', 'eqemu-cb-').replace('eqemu-vm-bh-', 'eqemu-vm-cb-'))


def build_identity(receipt, profile, sources, template):
    return inputs.digest({'format': 2, 'input_id': receipt['input_id'],
        'manifest_sha256': receipt['manifest_sha256'], 'profile': profile,
        'adapter_sources': sources, 'template': template})


def publish(stage, output, launcher, suite):
    """Claim destinations exclusively; retain the package if launcher publication refuses."""
    output.mkdir(mode=0o700)
    for path in stage.iterdir():
        path.rename(output/path.name)
    with launcher.open('x') as stream:
        stream.write(suite)


def prepare():
    if any(p.exists() or p.is_symlink() for p in [OUTPUT, LAUNCHER, ROOT]):
        raise RuntimeError('Preserve existing preparation/attempt')
    receipt = json.loads((INPUT_SOURCE/'receipts/preparation.json').read_text())
    profile = json.loads((INPUT_SOURCE/'profile.json').read_text())
    inputs.check_dependencies(profile, LOCAL)
    inputs.verify(PACKAGE, receipt['manifest_sha256'], profile, receipt['input_id'])
    prior = json.loads((REPO/'investigations/build-handoff/2026-09-27/receipts/preparation.json').read_text())
    templates = {}
    for name, expected in dict(prior['worker_files'], **{'launcher.py': prior['launcher_sha256']}).items():
        if sha(PREVIOUS/name) != expected: raise RuntimeError('Pinned template changed: ' + name)
        templates[name] = (PREVIOUS/name).read_text()
    source_paths = [*SOURCE.glob('*.py'), INPUT_SOURCE/'inputs.py', INPUT_SOURCE/'profile.json',
                    REPO/'investigations/artifact-handoff/2026-09-26/prepare.py']
    sources = {str(p.relative_to(REPO)): sha(p) for p in sorted(source_paths)}
    build_id = build_identity(receipt, profile, sources, prior)
    facts = {'candidate': profile['sources']['eqemu']['commit'], 'tree': profile['sources']['eqemu']['tree'],
             'input_id': receipt['input_id'], 'manifest_sha256': receipt['manifest_sha256']}
    if shutil.disk_usage(LOCAL).free < 2*1024**3: raise RuntimeError('Insufficient preparation space')
    with tempfile.TemporaryDirectory(prefix='.candidate-build-', dir=LOCAL) as tmp:
        stage = Path(tmp)
        # ISO is opaque transport. No candidate filesystem is extracted on the host.
        media = stage/'candidate.iso'
        subprocess.run(['genisoimage', '-quiet', '-R', '-J', '-V', 'EQ_CANDIDATE', '-o', str(media),
                        str(PACKAGE)], check=True, timeout=120)
        inputs.verify(PACKAGE, receipt['manifest_sha256'], profile, receipt['input_id'])
        hashes = {}
        for role in ['producer', 'consumer']:
            worker = templates[role+'-worker.py']
            seed_path, length, expected = literal(worker, 'FILES')['seed.iso']
            seed = LOCAL/seed_path
            if seed.stat().st_size != length or sha(seed) != expected: raise RuntimeError('Pinned seed changed')
            raw = subprocess.run(['isoinfo', '-i', str(seed), '-x', '/USER_DAT.;1'],
                                 check=True, capture_output=True, timeout=30).stdout.decode()
            user = json.loads(raw.split('\n', 1)[1])
            entry = next(f for f in user['write_files'] if f['path'].endswith('/guest_build.py'))
            guest = entry['content'].replace(prior['recipe_sha256'], build_id).replace(prior['build_id'], build_id)
            user['write_files'] = [f for f in user['write_files'] if not f['path'].endswith('/candidate.json')]
            if role == 'producer':
                start = guest.index(" src=WORK/'eqemu';src.mkdir()")
                end = guest.index(" vp=src/'submodules/vcpkg'", start)
                guest = guest[:start]+" src=WORK/'eqemu'\n materialize_candidate(src)\n"+guest[end:]
                extension = (SOURCE/'guest_source.py').read_text().replace('@INPUT_ID@', receipt['input_id'])
                extension = extension.replace('@MANIFEST_SHA@', receipt['manifest_sha256']).replace('@CANDIDATE_FACTS@', json.dumps(facts))
                guest = helpers.replace_function(guest, 'apply_candidate', extension)
                guest = replace_once(guest, " shutil.copyfile(MEDIA/'tools/vcpkg',vp/'vcpkg')",
                    " if command('registry-tree',['git','-C',str(vp),'rev-parse','HEAD^{tree}']).read_text().strip() != "
                    +repr(profile['submodules']['vcpkg']['tree'])+":raise RuntimeError('Registry tree differs')\n shutil.copyfile(MEDIA/'tools/vcpkg',vp/'vcpkg')")
                user['write_files'].extend([
                    {'path': '/opt/eqemu-proof/candidate_inputs.py', 'permissions': '0600', 'content': (INPUT_SOURCE/'inputs.py').read_text()},
                    {'path': '/opt/eqemu-proof/candidate-profile.json', 'permissions': '0600', 'content': json.dumps(profile)}])
            else:
                # The consumer cannot call the producer source/compile recipe.
                guest = helpers.replace_function(guest, 'build', "def build():\n    raise RuntimeError('Consumer cannot compile source')")
                guest = helpers.replace_function(guest, 'apply_candidate', "def apply_candidate(src):\n    raise RuntimeError('Consumer cannot prepare source')")
            entry['content'] = guest
            (stage/(role+'-guest.py')).write_text(guest)
            ud, md, seed = [stage/(role+s) for s in ['-user-data', '-meta-data', '-seed.iso']]
            ud.write_text('#cloud-config\n'+json.dumps(user, indent=2)+'\n')
            md.write_text('instance-id: eqemu-candidate-build-01-'+role+'\nlocal-hostname: eqemu-candidate\n')
            subprocess.run(['cloud-localds', str(seed), str(ud), str(md)], check=True, timeout=30)
            worker = renamed(worker).replace(prior['recipe_sha256'], build_id).replace(prior['build_id'], build_id)
            worker = re.sub(r'^CANDIDATE=.+$', 'CANDIDATE='+repr(facts), worker, count=1, flags=re.M)
            worker = re.sub(r" 'seed.iso':[^\n]+", " 'seed.iso':"+repr((OUTPUT.name+'/'+seed.name, seed.stat().st_size, sha(seed)))+',', worker, count=1)
            if role == 'producer':
                worker = replace_once(worker, "FILES={\n", "FILES={\n 'candidate.iso':"+repr((OUTPUT.name+'/candidate.iso', media.stat().st_size, sha(media)))+",\n")
                worker = replace_once(worker, '  {DATA}/fixture.iso rk,', '  {DATA}/fixture.iso rk,\n  {DATA}/candidate.iso rk,')
                disk = '    <disk type="file" device="cdrom"><driver name="qemu" type="raw"/><source file="{DATA}/candidate.iso"/><target dev="sdc" bus="sata"/><readonly/></disk>\n'
                worker = replace_once(worker, '    <serial type="unix">', disk+'    <serial type="unix">')
                worker = replace_once(worker, 'if len(disks)!=4', 'if len(disks)!=5')
                worker = replace_once(worker, "        if virsh('domstate',s['uuid'])", "        candidate_disk=next((d for d in disks if d.find('target').get('dev')=='sdc'),None)\n        if candidate_disk is None or candidate_disk.get('device')!='cdrom' or candidate_disk.find('source').get('file')!=str(DATA/'candidate.iso') or candidate_disk.find('readonly') is None:raise RuntimeError('Candidate disk policy mismatch')\n        if virsh('domstate',s['uuid'])")
                worker = worker.replace("['seed.iso','fixture.iso']", "['seed.iso','fixture.iso','candidate.iso']")
            for name, code in [(role+'-guest.py', guest), (role+'-worker.py', worker)]:
                compile(code, name, 'exec')
                (stage/name).write_text(code)
            hashes[role+'-worker.py'] = sha(stage/(role+'-worker.py'))
        suite = renamed(templates['launcher.py'])
        suite = re.sub(r'^HASHES=.+$', 'HASHES='+repr(hashes), suite, count=1, flags=re.M)
        # A successful experiment is still not default candidate acceptance.
        suite = replace_once(suite, "report = {'suite_passed': False,", "report = {'accepted': False, 'input_id': "+repr(receipt['input_id'])+", 'build_id': "+repr(build_id)+", 'suite_passed': False,")
        compile(suite, 'launcher.py', 'exec')
        (stage/'launcher.py').write_text(suite)
        proof = {'scope': 'complete-source build and fresh consumer; unexecuted', 'accepted': False,
            'input_id': receipt['input_id'], 'manifest_sha256': receipt['manifest_sha256'], 'build_id': build_id,
            'sources': sources, 'worker_files': hashes, 'launcher_sha256': sha(stage/'launcher.py'),
            'candidate_iso_bytes': media.stat().st_size, 'candidate_iso_sha256': sha(media),
            'retention_bytes': 4*1024**3, 'retention_days': 7, 'vm_started': False}
        (stage/'preparation.json').write_text(json.dumps(proof, indent=2)+'\n')
        # Destination is claimed only after every generated file and input check passes.
        inputs.check_dependencies(profile, LOCAL)
        publish(stage, OUTPUT, LAUNCHER, suite)
    print(json.dumps({'prepared': str(OUTPUT), 'launcher': str(LAUNCHER), 'vm_started': False}))


if __name__ == '__main__': prepare()
