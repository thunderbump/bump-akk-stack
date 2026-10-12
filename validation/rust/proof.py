#!/usr/bin/python3
"""Bounded isolated Rust/CXX component proof. No VM/container launch or installed activation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time

VALIDATION = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(VALIDATION))
import common
import rust
import rust_guest

CONTROLS=('format','lint','test','doctest','unsafe','link','syntax','missing-marker',
          'tool-drift','vendor-drift','config-drift','ancestor-config')

def authority(source):
    return rust.inventory(source)


def declared(source, bundle):
    blobs = {}
    for entry in authority(source)['entries']:
        if Path(entry['path']).name in ('Cargo.toml','Cargo.lock','rust-toolchain.toml'):
            blobs[entry['path']] = entry['blob']
    return rust.contract(dict(version=1,release='1.99.0',target=rust.HOST,
        bundle=dict(path=bundle.name,bytes=bundle.stat().st_size,sha256=common.sha(bundle)),
        manifest_path='Cargo.toml',packages=['eqemu-rust-proof-core','eqemu-rust-proof-bridge'],
        test_packages=['eqemu-rust-proof-core'],features=[],source_blobs=blobs,
        minimum_tests=1,minimum_doctests=1,link_symbol='eqemu_rust_bridge_v1'))


def run(source, bundle, output, control, deadline=None):
    rust_guest.guard()
    if os.geteuid() != 0:
        raise ValueError('Proof must run in an isolated guest/container as root')
    source = source.resolve(strict=True); bundle = bundle.resolve(strict=True); output = output.resolve()
    if output.exists() or output.is_relative_to(source) or output.is_relative_to(bundle.parent):
        raise ValueError('Proof requires a fresh owned output outside inputs')
    output.mkdir(mode=0o700)
    fixture = output/'source'; shutil.copytree(source,fixture)
    apply_control(fixture,control)
    expected = declared(fixture,bundle)
    snapshot = authority(fixture)
    guest = common.load('rust_proof_command',VALIDATION/'recipes/producer-guest.py')
    guest.WORK = output; guest.LOGS = output/'logs'; guest.LOGS.mkdir()
    started = time.monotonic()
    guest.DEADLINE = min(started+1200,deadline) if deadline is not None else started+1200
    guest.ENV = dict(guest.ENV)
    observations = {}
    def emit(item):
        name = item['name']; value = item['value']
        rust.observation(name,value,expected)
        observations[name] = value
    result = dict(version=1,scope='isolated Rust/CXX component proof; no zone or maintained VM acceptance',
                  control=control,contract=expected,observations=observations,accepted=False,exit_code=2)
    try:
        protected=rust_guest.prepare(expected,bundle,output,guest.command,guest.ENV,
                                     json.loads((VALIDATION/'rust-toolchain.json').read_text()))
        rust_guest.check(expected,fixture,snapshot,guest.verify_materialized,guest.command,emit,guest.ENV,protected)
        cargo = output/'rust/toolchain/bin/cargo'
        args = [str(cargo),'build','--frozen','--manifest-path',str(fixture/'Cargo.toml'),
                '-p','eqemu-rust-proof-bridge','--target',rust.HOST,'--release']
        guest.command('proof-staticlib',args,cwd=fixture,timeout=300,cap=4*1024**2)
        native = output/'proof-native'
        guest.command('proof-native-link',['/usr/bin/g++','-std=c++20',str(fixture/'native.cpp'),
                      '-I'+str(output/'rust/target/cxxbridge'),
                      str(output/'rust/target'/rust.HOST/'release/libeqemu_rust_proof_bridge.a'),
                      '-ldl','-lpthread','-lm','-o',str(native)],timeout=60,cap=1024**2)
        guest.verify_materialized(fixture,snapshot)
        rust_guest.native_link(expected,native,guest.command,emit,output/'rust',protected)
        output_log = guest.command('proof-native-run',[str(native)],timeout=10,cap=16384)
        if output_log.read_text() != 'EQEMU_RUST_BRIDGE_RESULT 42\n':
            raise ValueError('Native proof completion missing')
        rust_guest.verify_protected(output/'rust',protected)
        result.update(accepted=control is None,exit_code=0 if control is None else 2,
                      binary_sha256=common.sha(native),native_call=True)
    except (ValueError,OSError,RuntimeError,TypeError,KeyError,AttributeError) as error:
        result['error'] = str(error)[-4500:]
        known_link_failure = str(error).startswith('proof-native-link: exit 1\n') and 'undefined reference' in str(error)
        result['exit_code'] = 1 if known_link_failure or rust.candidate_failure(dict(rust_contract=expected,
                                       observations_untrusted=observations),str(error)) else 2
    finally:
        try:
            result['source_unchanged'] = authority(fixture) == snapshot
        except (ValueError,OSError):
            result['source_unchanged'] = False
        if not result['source_unchanged']:
            result.update(accepted=False,exit_code=2,error='Proof source custody changed')
        result['elapsed_seconds'] = time.monotonic()-started
        (output/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


def apply_control(source, control):
    """Mutate only the owned disposable fixture before taking its source identity."""
    core = source/'core/src/lib.rs'
    if control == 'format':
        core.write_text(core.read_text().replace('pub fn answer(value: u32) -> u32 {','pub fn answer( value:u32)->u32 {'))
    elif control == 'test':
        core.write_text(core.read_text().replace('super::answer(u32::MAX), u32::MAX','super::answer(u32::MAX), 0'))
    elif control == 'doctest':
        core.write_text(core.read_text().replace('answer(41), 42','answer(41), 0'))
    elif control == 'unsafe':
        core.write_text(core.read_text()+'\npub unsafe fn forbidden() {}\n')
    elif control == 'lint':
        core.write_text(core.read_text()+'\npub fn lint_probe(value: u32) -> bool {\n    value == value\n}\n')
    elif control == 'link':
        native = source/'native.cpp'
        native.write_text(native.read_text().replace('extern "C" unsigned int eqemu_rust_bridge_v1();',
                          'extern "C" unsigned int missing_symbol();\n#define eqemu_rust_bridge_v1 missing_symbol'))
    elif control == 'syntax':
        core.write_text(core.read_text().replace('    value.saturating_add(1)',
                                                '    let broken = ;\n    value.saturating_add(1)'))
    elif control == 'missing-marker':
        bridge=source/'bridge/src/lib.rs';native=source/'native.cpp'
        for file in (bridge,native):
            file.write_text(file.read_text().replace('eqemu_rust_bridge_v1','eqemu_rust_unqualified'))
    elif control in ('tool-drift','vendor-drift','config-drift','ancestor-config'):
        lines = {
            'tool-drift':'    let path = std::path::PathBuf::from(std::env::var("RUSTC").unwrap());\n',
            'vendor-drift':'    let home = std::path::PathBuf::from(std::env::var("CARGO_HOME").unwrap());\n    let path = home.parent().unwrap().join("vendor/cxx-1.0.194/Cargo.toml");\n',
            'config-drift':'    let home = std::path::PathBuf::from(std::env::var("CARGO_HOME").unwrap());\n    let path = home.join("config.toml");\n',
            'ancestor-config':'    let home = std::path::PathBuf::from(std::env::var("CARGO_HOME").unwrap());\n    let work = home.parent().unwrap().parent().unwrap();\n    std::fs::create_dir_all(work.join(".cargo")).unwrap();\n    let path = work.join(".cargo/config.toml");\n',
        }[control]
        # A safe Rust test deliberately changes only this proof's writable input
        # copy. The post-stage custody guard must reject it before later tooling.
        core.write_text(core.read_text()+'\n#[test]\nfn deliberate_input_drift() {\n'+lines+'    std::fs::write(path, "changed input").unwrap();\n}\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source','bundle','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--control',choices=CONTROLS)
    args = parser.parse_args()
    try:
        result = run(args.source,args.bundle,args.output,args.control)
    except (ValueError,OSError,RuntimeError,TypeError,KeyError,AttributeError) as error:
        result = dict(version=1,scope='Rust/CXX component proof refusal',accepted=False,exit_code=2,error=str(error)[-4500:])
    print(json.dumps(result,indent=2))
    raise SystemExit(result['exit_code'])
