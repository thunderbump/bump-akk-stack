#!/usr/bin/python3
"""Acquire pinned public components or seal an already vendored closure, without installing tools."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tarfile
import urllib.request

VALIDATION = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(VALIDATION))
import rust


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def acquire(output):
    """Download only the checked-in official archive URLs; preserve verified opaque bytes."""
    output = output.resolve()
    output.mkdir(mode=0o700)
    toolchain = json.loads((VALIDATION/'rust-toolchain.json').read_text())
    for name, item in toolchain['components'].items():
        target = output/(name+'.tar.xz')
        temporary = output/(name+'.partial')
        try:
            hashed = hashlib.sha256(); size = 0
            with urllib.request.urlopen(item['url'], timeout=30) as response, temporary.open('xb') as stream:
                while block := response.read(1024**2):
                    size += len(block)
                    if size > rust.BUNDLE_LIMIT:
                        raise ValueError('Rust component download exceeds budget')
                    hashed.update(block); stream.write(block)
            if hashed.hexdigest() != item['sha256']:
                raise ValueError('Rust archive checksum mismatch: '+name)
            temporary.rename(target)
        finally:
            temporary.unlink(missing_ok=True)
    return {p.name:{'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(output.iterdir())}


def bundle(components, vendor, config, output):
    """Seal data only. Vendoring must already have run in an authorized isolated guest."""
    output = output.resolve()
    if output.exists():
        raise ValueError('Use a new Rust bundle directory')
    toolchain = json.loads((VALIDATION/'rust-toolchain.json').read_text())
    text = config.read_text()
    rust.config(text, '/qualified/vendor')
    if vendor.is_symlink() or not vendor.is_file() or vendor.stat().st_size > rust.BUNDLE_LIMIT:
        raise ValueError('Vendor archive type/size')
    # Inspect archive paths/types as data, without extracting any dependency.
    total = 0; names = set()
    with tarfile.open(vendor, 'r:') as archive:
        for member in archive:
            name = rust.path(member.name.rstrip('/'))
            total += member.size
            if (name in names or not (member.isfile() or member.isdir()) or total > rust.UNPACK_LIMIT
                    or len(names) >= rust.FILE_LIMIT):
                raise ValueError('Vendor archive inventory')
            names.add(name)
    if not names or not any(name.endswith('/.cargo-checksum.json') for name in names):
        raise ValueError('Vendor checksum inventory missing')
    output.mkdir(mode=0o700)
    target = output/'rust-inputs.tar'
    try:
        with tarfile.open(target, 'w:') as archive:
            for name, item in toolchain['components'].items():
                source = components/(name+'.tar.xz')
                if source.is_symlink() or not source.is_file() or sha(source) != item['sha256']:
                    raise ValueError('Rust component identity: '+name)
                archive.add(source, arcname=name+'.tar.xz', recursive=False)
            archive.add(vendor, arcname='vendor.tar', recursive=False)
            archive.add(config, arcname='vendor-config.toml', recursive=False)
        if target.stat().st_size > rust.BUNDLE_LIMIT:
            raise ValueError('Rust bundle exceeds candidate-media budget')
        inventory = rust.verify_bundle(target, toolchain)
        receipt = dict(version=1,release=toolchain['release'],host=toolchain['host'],
                       toolchain_manifest_sha256=toolchain['manifest_sha256'],files=inventory,
                       bundle=dict(path=target.name,bytes=target.stat().st_size,sha256=sha(target)),
                       installed=False,executed_candidate=False)
        (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        return receipt
    except BaseException:
        shutil.rmtree(output)
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    download = commands.add_parser('acquire'); download.add_argument('--output', type=Path, required=True)
    seal = commands.add_parser('bundle')
    for name in ('components','vendor','config','output'):
        seal.add_argument('--'+name,type=Path,required=True)
    args = parser.parse_args()
    result = acquire(args.output) if args.command == 'acquire' else bundle(args.components,args.vendor,args.config,args.output)
    print(json.dumps(result,indent=2))
