#!/usr/bin/python3
"""Extend authenticated runtime media with GDB and matching system debug packages.

Only metadata and opaque bytes are handled on the host. No installation or VM.
The retained resolver status is a simulation aid, not guest provisioning proof.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOTS = ['gdb=15.1-1ubuntu1~24.04.1', 'libc6-dbg=2.39-0ubuntu8.9',
         'libstdc++6-14-dbg=14.2.0-4ubuntu2~24.04.1']


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fields(block):
    return dict(line.split(': ', 1) for line in block.splitlines()
                if ': ' in line and not line.startswith(' '))


def prepare(store, resolver, output):
    if os.geteuid() == 0:
        raise ValueError('Prepare as normal user')
    store = store.resolve(strict=True); resolver = resolver.resolve(strict=True)
    output = output.resolve()
    if output.exists() or output.is_relative_to(resolver):
        raise ValueError('Use a new output outside retained resolver state')
    baseline = json.loads(Path(__file__).with_name('baseline.json').read_text())
    iso = store/baseline['iso']['path']
    if iso.stat().st_size != baseline['iso']['bytes'] or sha(iso) != baseline['iso']['sha256']:
        raise ValueError('Original runtime ISO changed')
    output.mkdir(mode=0o700)
    payload = output/'payload'; payload.mkdir()
    for row in baseline['manifest']['files']:
        target = payload/row['path']; target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            subprocess.run(['isoinfo', '-R', '-i', str(iso), '-x', '/'+row['path']],
                           stdout=stream, check=True, timeout=30)
        if target.stat().st_size != row['bytes'] or sha(target) != row['sha256']:
            raise ValueError('Original payload changed: '+row['path'])
    key = payload/'ubuntu-archive-keyring.gpg'
    records = {}
    for suite in ('noble', 'noble-updates', 'noble-security'):
        prefix = 'archive.ubuntu.com_ubuntu_dists_'+suite+'_'
        release = payload/'apt-lists'/(prefix+'InRelease')
        subprocess.run(['gpgv', '--keyring', str(key), str(release)],
                       check=True, capture_output=True, timeout=30)
        checks = {}
        for line in release.read_text().split('\nSHA256:\n', 1)[1].split('\nSHA512:', 1)[0].splitlines():
            parts = line.split()
            if len(parts) == 3 and re.fullmatch('[a-f0-9]{64}', parts[0]):
                checks[parts[2]] = (parts[0], int(parts[1]))
        for component in ('main', 'universe'):
            index = payload/'apt-lists'/(prefix+component+'_binary-amd64_Packages')
            if (sha(index), index.stat().st_size) != checks[component+'/binary-amd64/Packages']:
                raise ValueError('Signed index identity')
            for block in index.read_text().split('\n\n'):
                value = fields(block)
                if 'Package' in value:
                    identity = (value['Package'], value['Version'])
                    if identity in records and records[identity]['SHA256'] != value['SHA256']:
                        raise ValueError('Ambiguous signed archive identity')
                    value['signed_index'] = 'apt-lists/'+index.name
                    records[identity] = value
    # Copy only the simulation status. Solver metadata comes from verified media.
    apt = output/'apt'
    for name in ('lists/partial', 'cache/archives/partial', 'parts', 'sources', 'log'):
        (apt/name).mkdir(parents=True, exist_ok=True)
    for path in (payload/'apt-lists').iterdir(): shutil.copyfile(path, apt/'lists'/path.name)
    shutil.copyfile(resolver/'guest-status', apt/'status')
    (apt/'empty.conf').touch()
    (apt/'sources.list').write_text('\n'.join(
        f'deb [arch=amd64 signed-by={key}] https://archive.ubuntu.com/ubuntu {suite} main universe'
        for suite in ('noble', 'noble-updates', 'noble-security'))+'\n')
    config = apt/'apt.conf'
    config.write_text(f'''Dir::Etc "{apt}";
Dir::Etc::main "{apt}/empty.conf";
Dir::Etc::parts "{apt}/parts";
Dir::Etc::sourceparts "{apt}/sources";
Dir::Etc::sourcelist "{apt}/sources.list";
Dir::State "{apt}";
Dir::State::lists "{apt}/lists";
Dir::State::status "{apt}/status";
Dir::Cache "{apt}/cache";
Dir::Log "{apt}/log";
APT::Architecture "amd64";
APT::Architectures {{ "amd64"; }};
APT::Install-Recommends "false";
''')
    env = {**os.environ, 'APT_CONFIG': str(config)}
    result = subprocess.run(['apt-get', '-s', '--no-remove', 'install', *ROOTS],
                            env=env, check=True, capture_output=True, text=True, timeout=60)
    (output/'resolver-plan.txt').write_text(result.stdout+result.stderr)
    wanted = {}
    for line in result.stdout.splitlines():
        if line.startswith('Remv '): raise ValueError('Resolver removal')
        match = re.match(r'Inst (\S+)(?: \[([^]]+)\])? \((\S+)', line)
        if match:
            if match[2]:
                # Manifest-derived placeholders omit full dependency metadata.
                # Reinstallation of identical installed versions is not a new dependency.
                if match[2] != match[3]: raise ValueError('Resolver would change existing version')
                continue
            wanted[match[1]] = match[3]
    if not {'gdb', 'libc6-dbg', 'libstdc++6-14-dbg'} <= wanted.keys():
        raise ValueError('Missing debugger roots')
    additions = [records[(name, version)] for name, version in sorted(wanted.items())]
    if sum(int(p['Size']) for p in additions) > 512*1024**2:
        raise ValueError('Package download budget')
    for package in additions:
        if shutil.disk_usage(output).free < 180*1024**3: raise ValueError('Disk reserve')
        filename = package['Filename']
        if not filename.startswith('pool/') or '..' in Path(filename).parts:
            raise ValueError('Archive path')
        target = payload/'debs'/Path(filename).name
        subprocess.run(['curl', '-fsSL', '--proto', '=https', '--proto-redir', '=https',
                        '--max-time', '120', '--max-filesize', package['Size'],
                        '-o', str(target), 'https://archive.ubuntu.com/ubuntu/'+filename],
                       check=True, timeout=130)
        if target.stat().st_size != int(package['Size']) or sha(target) != package['SHA256']:
            raise ValueError('Downloaded archive identity')
    proof = payload/'provenance/runtime-package-proof.json'
    value = json.loads(proof.read_text())
    value['packages'] += additions
    value['debugger_roots'] = ROOTS
    value['guest_solver_install_pending'] = True
    value['host_install'] = False
    proof.write_text(json.dumps(value, indent=2)+'\n')
    rows = []
    old_roles = {r['path']:r['role'] for r in baseline['manifest']['files']}
    for path in sorted(payload.rglob('*')):
        if path.is_file():
            name = str(path.relative_to(payload))
            rows.append(dict(path=name, bytes=path.stat().st_size, sha256=sha(path),
                             role=old_roles.get(name, 'guest-package')))
    manifest = dict(baseline['manifest'], files=rows,
                    scope='Authenticated offline runtime plus debugger closure; guest proof pending')
    raw = output/'runtime-bundle-manifest.json'
    raw.write_text(json.dumps(manifest, indent=2)+'\n')
    target = output/'runtime-inputs.iso'
    subprocess.run(['genisoimage', '-quiet', '-R', '-J', '-V', 'EQEMURUNTIME', '-o', str(target),
                    '-graft-points', 'runtime-bundle-manifest.json='+str(raw),
                    *[row['path']+'='+str(payload/row['path']) for row in rows]], check=True, timeout=120)
    fixture = dict(iso=dict(path=str(target.relative_to(store)), bytes=target.stat().st_size,
                           sha256=sha(target)), manifest=manifest, manifest_sha256=sha(raw))
    (output/'runtime-fixture.json').write_text(json.dumps(fixture, indent=2)+'\n')
    for path in (raw, target): path.chmod(0o444)
    return dict(additional_packages=len(additions), total_packages=len(value['packages']),
                iso_bytes=target.stat().st_size, iso_sha256=sha(target), host_install=False,
                guest_provisioning='pending')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-store', type=Path, required=True)
    parser.add_argument('--resolver-state', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.input_store, args.resolver_state, args.output)))
