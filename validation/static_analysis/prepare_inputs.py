#!/usr/bin/python3
"""Extend the sealed build medium with authenticated offline LLVM packages.

This handles package metadata and opaque archive bytes only. The resolver's
retained status is simulation input; a fresh guest must prove installation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOTS = ['clang-18=1:18.1.3-1ubuntu1', 'clang-tidy-18=1:18.1.3-1ubuntu1',
         'clang-format-18=1:18.1.3-1ubuntu1']
BASELINE = {'path': 'build-inputs-20260925-v3/build-inputs.iso', 'bytes': 469000192,
            'sha256': '02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4'}
MANIFEST_SHA = '95eb1cf160fdc3704d17d9d18be0919ed393f6951a98f6143a144b2c91b8f7e4'


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def fields(block):
    return dict(line.split(': ', 1) for line in block.splitlines()
                if ': ' in line and not line.startswith(' '))


def prepare(store, resolver, output):
    if os.geteuid() == 0: raise ValueError('Prepare as normal user')
    store = store.resolve(strict=True); resolver = resolver.resolve(strict=True); output = output.resolve()
    if output.exists() or not output.is_relative_to(store) or output.is_relative_to(resolver):
        raise ValueError('Use a new output inside the public input store and outside resolver state')
    iso = store/BASELINE['path']
    if iso.is_symlink() or iso.stat().st_size != BASELINE['bytes'] or sha(iso) != BASELINE['sha256']:
        raise ValueError('Original build ISO changed')
    raw = subprocess.run(['isoinfo','-R','-i',str(iso),'-x','/bundle-manifest.json'],
                         check=True,capture_output=True,timeout=30).stdout
    if len(raw)>256*1024 or hashlib.sha256(raw).hexdigest()!=MANIFEST_SHA:
        raise ValueError('Original build manifest changed')
    baseline = json.loads(raw)
    output.mkdir(mode=0o700); payload = output/'payload'; payload.mkdir(); seen = set()
    for row in baseline['files']:
        name = row['path']; relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or str(relative)!=name or name in seen:
            raise ValueError('Unsafe original payload path')
        seen.add(name); target = payload/relative; target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as stream:
            subprocess.run(['isoinfo','-R','-i',str(iso),'-x','/'+name],stdout=stream,check=True,timeout=30)
        if target.stat().st_size!=row['bytes'] or sha(target)!=row['sha256']:
            raise ValueError('Original payload changed: '+name)
    key=payload/'ubuntu-archive-keyring.gpg'; records={}
    for suite in ('noble','noble-updates','noble-security'):
        prefix='archive.ubuntu.com_ubuntu_dists_'+suite+'_'; release=payload/'apt-lists'/(prefix+'InRelease')
        subprocess.run(['gpgv','--keyring',str(key),str(release)],check=True,capture_output=True,timeout=30)
        checks={}
        for line in release.read_text().split('\nSHA256:\n',1)[1].split('\nSHA512:',1)[0].splitlines():
            parts=line.split()
            if len(parts)==3 and re.fullmatch('[a-f0-9]{64}',parts[0]):checks[parts[2]]=(parts[0],int(parts[1]))
        for component in ('main','universe'):
            index=payload/'apt-lists'/(prefix+component+'_binary-amd64_Packages')
            if (sha(index),index.stat().st_size)!=checks[component+'/binary-amd64/Packages']:
                raise ValueError('Signed index identity')
            for block in index.read_text().split('\n\n'):
                value=fields(block)
                if 'Package' in value:
                    identity=(value['Package'],value['Version'])
                    if identity in records and records[identity]['SHA256']!=value['SHA256']:
                        raise ValueError('Ambiguous signed package identity')
                    value['signed_index']='apt-lists/'+index.name; records[identity]=value
    apt=output/'apt'
    for name in ('lists/partial','cache/archives/partial','parts','sources','log'):(apt/name).mkdir(parents=True,exist_ok=True)
    for path in (payload/'apt-lists').iterdir():shutil.copyfile(path,apt/'lists'/path.name)
    shutil.copyfile(resolver/'guest-status',apt/'status');(apt/'empty.conf').touch()
    (apt/'sources.list').write_text('\n'.join(f'deb [arch=amd64 signed-by={key}] https://archive.ubuntu.com/ubuntu {s} main universe' for s in ('noble','noble-updates','noble-security'))+'\n')
    config=apt/'apt.conf'
    config.write_text(f'''Dir::Etc "{apt}";
Dir::Etc::main "{apt}/empty.conf";
Dir::Etc::parts "{apt}/parts";
Dir::Etc::sourcelist "{apt}/sources.list";
Dir::Etc::sourceparts "{apt}/sources";
Dir::State "{apt}";
Dir::State::lists "{apt}/lists";
Dir::State::status "{apt}/status";
Dir::Cache "{apt}/cache";
Dir::Cache::archives "{apt}/cache/archives";
Dir::Log "{apt}/log";
APT::Architecture "amd64";
APT::Architectures {{ "amd64"; }};
APT::Install-Recommends "false";
''')
    original_proof=json.loads((payload/'provenance/ubuntu-package-proof.json').read_text())
    existing={p['package']:p['version'] for p in original_proof['packages']}
    plan=subprocess.run(['apt-get','-s','--no-remove','install',
        *[name+'='+version for name,version in existing.items()],*ROOTS],
        env={**os.environ,'APT_CONFIG':str(config)},check=True,capture_output=True,text=True,timeout=60)
    (output/'resolver-plan.txt').write_text(plan.stdout+plan.stderr);wanted={}
    for line in plan.stdout.splitlines():
        if line.startswith('Remv '):raise ValueError('Resolver removal')
        match=re.match(r'Inst (\S+)(?: \[([^]]+)\])? \((\S+)',line)
        if match:
            name,version=match[1],match[3]
            if name in existing:
                if existing[name]!=version:raise ValueError('Resolver changes a bundled version')
                continue
            if match[2] and match[2]!=version:raise ValueError('Resolver changes an unbundled installed version')
            wanted[name]=version
    if not {root.split('=')[0] for root in ROOTS}<=wanted.keys():raise ValueError('Missing LLVM roots')
    additions=[records[(name,version)] for name,version in sorted(wanted.items())]
    if sum(int(p['Size']) for p in additions)>512*1024**2:raise ValueError('Package download budget')
    for package in additions:
        if shutil.disk_usage(output).free<180*1024**3:raise ValueError('Disk reserve')
        name=package['Filename']
        if not name.startswith('pool/') or '..' in Path(name).parts:raise ValueError('Archive path')
        target=payload/'debs'/Path(name).name
        if target.exists():raise ValueError('Package archive name collision')
        subprocess.run(['curl','-fsSL','--proto','=https','--proto-redir','=https','--max-time','120',
            '--max-filesize',package['Size'],'-o',str(target),'https://archive.ubuntu.com/ubuntu/'+name],check=True,timeout=130)
        if target.stat().st_size!=int(package['Size']) or sha(target)!=package['SHA256']:
            raise ValueError('Downloaded archive identity')
    proof=payload/'provenance/ubuntu-package-proof.json';value=json.loads(proof.read_text())
    value['packages']+=additions;value['llvm_roots']=ROOTS;value['guest_solver_install_pending']=True
    proof.write_text(json.dumps(value,indent=2)+'\n')
    roles={row['path']:row['role'] for row in baseline['files']};rows=[]
    for path in sorted(payload.rglob('*')):
        if path.is_file():
            name=str(path.relative_to(payload));rows.append(dict(path=name,bytes=path.stat().st_size,
                sha256=sha(path),role=roles.get(name,'guest-package')))
    manifest=dict(baseline,files=rows,scope='Authenticated build inputs plus LLVM closure; guest proof pending')
    raw=output/'bundle-manifest.json';raw.write_text(json.dumps(manifest,indent=2)+'\n')
    target=output/'build-inputs.iso'
    subprocess.run(['genisoimage','-quiet','-R','-J','-V','EQEMUBUILD','-o',str(target),'-graft-points',
        'bundle-manifest.json='+str(raw),*[r['path']+'='+str(payload/r['path']) for r in rows]],check=True,timeout=120)
    result=dict(dependency=dict(path=str(target.relative_to(store)),bytes=target.stat().st_size,sha256=sha(target)),
        manifest_sha256=sha(raw),additional_packages=len(additions),llvm_roots=ROOTS,
        host_install=False,guest_provisioning='pending')
    (output/'preparation.json').write_text(json.dumps(result,indent=2)+'\n')
    raw.chmod(0o444);target.chmod(0o444)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input-store',type=Path,required=True)
    parser.add_argument('--resolver-state',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(prepare(args.input_store,args.resolver_state,args.output)))
