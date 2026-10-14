#!/usr/bin/python3
"""Freeze a direct upgrade operator declaration. Never installs or launches work."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(Path(__file__).resolve().parent))
import direct


def prepare(package,output,activate_rust=False):
    package=package.resolve(strict=True);output=output.resolve()
    if output.exists() or output.is_relative_to(package) or output.is_relative_to(ROOT):
        raise ValueError('Use a fresh upgrade directory outside source/package')
    raw=direct.read(package/'manifest.json',16384);digest=direct.sha(raw)
    _,files=direct.package(package,digest)
    profile_digest=None
    if activate_rust:
        sys.path.insert(0,str(ROOT))
        import rust
        profile=direct.decode(files['profile.json'])
        rust.contract(profile['rust'])
        if profile['dependencies'].get('rust')!=profile['rust']['bundle']:
            raise ValueError('Rust bundle declaration mismatch')
        profile_digest=direct.sha(files['profile.json'])
    template=(Path(__file__).with_name('direct.py')).read_text()
    if template.count('DECLARATION = None')!=1:raise ValueError('Upgrade declaration seam changed')
    if template.count('ACTIVATION_PROFILE_SHA256 = None')!=1:raise ValueError('Activation profile seam changed')
    template=template.replace('ACTIVATION_PROFILE_SHA256 = None','ACTIVATION_PROFILE_SHA256 = '+repr(profile_digest))
    bootstrap=(ROOT/'rust/launch.py').read_text()
    output.mkdir(mode=0o700)
    results={}
    for mode in ('check','apply'):
        declaration={'version':1,'old_manifest':direct.OLD,'new_manifest':digest,'proof_report':direct.PROOF_REPORT,
                     'proof_uuid':direct.PROOF_UUID,'package':str(package),'mode':mode}
        source=output/(mode+'.py');source.write_text(template.replace('DECLARATION = None','DECLARATION = '+repr(declaration)))
        compile(source.read_text(),str(source),'exec');expected=hashlib.sha256(source.read_bytes()).hexdigest()
        wrapper=output/('reviewed-'+mode+'.sh')
        wrapper.write_text('#!/bin/sh\nset -eu\nexec /usr/bin/sudo /usr/bin/python3 -I -c '+shlex.quote(bootstrap)+' '+shlex.quote(str(source))+' '+shlex.quote(expected)+'\n')
        wrapper.chmod(0o700)
        results[mode]={'declaration':declaration,'program_sha256':expected,'wrapper_sha256':direct.sha(wrapper.read_bytes())}
    receipt={'version':1,'new_manifest':digest,'operators':results,'installed':False,'jobs_started':False,'rollback':False,'rust_activation':activate_rust,'profile_sha256':profile_digest}
    (output/'preparation.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--activate-rust',action='store_true',help='Freeze the exact Rust-enabled profile for direct activation')
    args=parser.parse_args();print(json.dumps(prepare(args.package,args.output,args.activate_rust),indent=2))
