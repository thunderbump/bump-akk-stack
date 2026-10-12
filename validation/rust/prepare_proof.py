#!/usr/bin/python3
"""Freeze a tiny qualification input directory as data. Starts no compiler, container or VM."""
import argparse
import json
from pathlib import Path
import shutil
import sys

VALIDATION = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(VALIDATION))
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common
import proof
import rust


def prepare(source,bundle,output):
    source=source.resolve(strict=True);bundle=bundle.resolve(strict=True);output=output.resolve()
    if output.exists() or output.is_relative_to(source) or output.is_relative_to(bundle.parent):
        raise ValueError('Use a new proof output outside inputs')
    selected=proof.declared(source,bundle)
    inventory=rust.verify_bundle(bundle,json.loads((VALIDATION/'rust-toolchain.json').read_text()))
    snapshot=proof.authority(source)
    output.mkdir(mode=0o700)
    try:
        shutil.copytree(source,output/'fixture')
        shutil.copyfile(bundle,output/'rust-inputs.tar')
        if proof.authority(output/'fixture') != snapshot or common.sha(output/'rust-inputs.tar') != selected['bundle']['sha256']:
            raise ValueError('Proof inputs changed while copying')
        receipt=dict(version=1,scope='Rust/CXX component proof preparation',contract=selected,
                     fixture_sha256=rust.digest(snapshot),bundle_inventory=inventory,
                     helper_sha256={name:common.sha(VALIDATION/name) for name in
                         ('common.py','rust.py','rust_guest.py','rust-toolchain.json','recipes/producer-guest.py','rust/proof.py')},
                     executed=False,installed=False)
        (output/'preparation.json').write_text(json.dumps(receipt,indent=2)+'\n')
        return receipt
    except BaseException:
        shutil.rmtree(output)
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','bundle','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(prepare(args.source,args.bundle,args.output),indent=2))
