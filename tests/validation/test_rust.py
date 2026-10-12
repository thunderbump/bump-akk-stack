"""Rust preparation, checked stages and candidate/infrastructure evidence without a Rust install."""
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation'))
import common
import rust
import rust_guest
import prepare
import render
import test_reporting_coverage as reporting
import test_packaging as packaging


def contract():
    return dict(version=1,release='1.99.0',target=rust.HOST,
                bundle=dict(path='rust/inputs.tar',bytes=1,sha256='a'*64),manifest_path='rust/Cargo.toml',
                packages=['actor-core','actor-bridge'],test_packages=['actor-core'],features=[],
                source_blobs={'rust/Cargo.toml':'a'*40,'rust/Cargo.lock':'b'*40,'rust-toolchain.toml':'c'*40},
                minimum_tests=1,minimum_doctests=1,link_symbol='eqemu_rust_bridge_v1')


def preflight(expected):
    return dict(contract_sha256=rust.digest(expected),release='1.99.0',host=rust.HOST,target=rust.HOST,
                metadata_sha256='b'*64,bundle_sha256=expected['bundle']['sha256'],source_unchanged=True,protected_sha256='e'*64)


def completion(expected):
    return dict(contract_sha256=rust.digest(expected),exit_code=0,selected=1,completed=1,failed=0,source_unchanged=True,protected_unchanged=True)


def failure(expected,stage='rust-tests',code=101):
    return dict(contract_sha256=rust.digest(expected),stage=stage,exit_code=code,finding='test',source_unchanged=True,protected_unchanged=True)


def harness(package='owned',doc=False,passed=1,ignored=0):
    artifact=json.dumps(dict(reason='compiler-artifact',package_id=package,
                        profile={'test':True},executable='/build/test-core'))
    header='   Doc-tests actor_core' if doc else '     Running unittests src/lib.rs (/build/test-core)'
    return artifact+'\n'+header+'\n\nrunning '+str(passed+ignored)+' test\n'+\
        f'test result: ok. {passed} passed; 0 failed; {ignored} ignored; 0 measured; 0 filtered out; finished in 0.00s\n'


class RustContract(unittest.TestCase):
    def test_inventory_rejects_oversize_before_read_and_bounds_directory_walk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'huge').write_bytes(b'12345')
            with patch.object(rust.os,'open') as opened,self.assertRaisesRegex(ValueError,'byte/type budget'):
                rust.inventory(root,byte_limit=4)
            opened.assert_not_called()
            (root/'huge').unlink();(root/'one').mkdir();(root/'two').mkdir()
            with self.assertRaisesRegex(ValueError,'file/count budget'):rust.inventory(root,file_limit=1)

    def test_empty_unsupported_and_drifting_selections_refuse(self):
        expected = contract(); rust.contract(expected)
        for change in ({'packages':[]},{'packages':[{}]},{'minimum_tests':0},{'minimum_doctests':False},
                       {'target':'aarch64-unknown-linux-gnu'},{'release':'stable'},
                       {'source_blobs':{'rust/Cargo.toml':'a'*40}},{'manifest_path':'../Cargo.toml'}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                rust.contract(dict(expected,**change))

    def test_vendor_config_has_no_execution_or_unreplaced_sources(self):
        text = '[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "@VENDOR@"\n'
        self.assertIn('/qualified/vendor',rust.config(text,'/qualified/vendor'))
        for bad in (text+'\n[build]\nrustc-wrapper = "/tmp/execute"\n',
                    text.replace('replace-with = "vendored-sources"','registry = "https://example.invalid"'),
                    text.replace('"@VENDOR@"',"'@VENDOR@'")):
            with self.assertRaises(ValueError):rust.config(bad,'/qualified/vendor')

    def test_archive_special_escaped_duplicate_and_expansion_refuse(self):
        for kind in ('escape','special','duplicate','oversize'):
            with tempfile.TemporaryDirectory() as tmp,self.subTest(kind=kind):
                root=Path(tmp);target=root/'input.tar'
                with tarfile.open(target,'w:') as archive:
                    item=tarfile.TarInfo('../outside' if kind=='escape' else 'file')
                    if kind=='special':item.type=tarfile.FIFOTYPE
                    item.size=0;archive.addfile(item)
                    if kind=='duplicate':archive.addfile(item)
                    if kind=='oversize':
                        item=tarfile.TarInfo('other');item.size=1;archive.addfile(item,io.BytesIO(b'x'))
                with patch.object(rust,'UNPACK_LIMIT',0 if kind=='oversize' else rust.UNPACK_LIMIT),self.assertRaises(ValueError):
                    rust_guest.extract(target,root/'output',float('inf'))
                self.assertFalse((root/'outside').exists())

    def test_observations_reject_missing_zero_bool_and_wrong_identity(self):
        expected=contract()
        for name in rust.STAGES:rust.observation(name,completion(expected),expected)
        for change in ({'selected':0},{'completed':0},{'failed':1},{'exit_code':True},{'source_unchanged':False},
                       {'contract_sha256':'0'*64},{'extra':1}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                rust.observation('rust-tests',dict(completion(expected),**change),expected)


class RustClassification(unittest.TestCase):
    def worker(self):
        expected=contract()
        return dict(rust_contract=expected,checks={'host_pre_resume':True},service_result='exit-code',
                    cleanup={'readonly_inputs_unchanged':True},
                    resource_observations={'memory.events':'oom 0\noom_kill 0','pids.events':'max 0'},
                    guest_report_untrusted={'ok':False,'error':'rust-tests: exit 101\nassertion'},
                    observations_untrusted={'rust-preflight':preflight(expected),'rust-failure':failure(expected)})

    def test_candidate_requires_specific_finding_and_safe_custody(self):
        worker=self.worker()
        self.assertEqual(common.outcome({},dict(producer=worker),True),1)
        for missing in ('rust-preflight','rust-failure'):
            bad=copy.deepcopy(worker);del bad['observations_untrusted'][missing]
            self.assertEqual(common.outcome({},dict(producer=bad),True),2)
        for error in ('rust-tests: exit 101\nfailed to get dependency',
                      'rust-tests: deadline exceeded','rust-tests: exit 101\nNo space left on device'):
            bad=copy.deepcopy(worker);bad['guest_report_untrusted']['error']=error
            if 'failed to get' in error:bad['observations_untrusted'].pop('rust-failure')
            self.assertEqual(common.outcome({},dict(producer=bad),True),2)
        for key,value in [('cleanup',{'readonly_inputs_unchanged':False}),
                          ('resource_observations',{'memory.events':'oom 1\noom_kill 1','pids.events':'max 0'})]:
            bad=copy.deepcopy(worker);bad[key]=value
            self.assertEqual(common.outcome({},dict(producer=bad),True),2)
        self.assertEqual(common.outcome({},dict(producer=worker),False),2)
        self.assertEqual(common.outcome({'cleanup':{'rescued':['producer']}},dict(producer=worker),True),2)

    def test_cargo_101_without_workspace_finding_is_not_candidate_failure(self):
        expected=contract()
        self.assertIsNone(rust_guest.finding('rust-clippy','error: failed to get package',{'owned'}))
        message=dict(reason='compiler-message',package_id='owned',message=dict(level='error',spans=[{}],code={'code':'clippy::eq_op'}))
        output=json.dumps(message)
        self.assertEqual(rust_guest.finding('rust-clippy',output,{'owned'}),'lint')
        self.assertIsNone(rust_guest.finding('rust-clippy',output,{'dependency'}))
        self.assertEqual(rust_guest.finding('rust-fmt','Diff in /source/src/lib.rs:2:\n',set()),'format')
        self.assertEqual(rust_guest.finding('rust-doctests','test result: FAILED. 0 passed; 1 failed; 0 ignored;',set()),'test')
        message['message']=dict(level='error',code=None,message='expected expression, found `;`',
                                spans=[{'is_primary':True,'file_name':'core/src/lib.rs'}])
        self.assertEqual(rust_guest.finding('rust-clippy',json.dumps(message),{'owned'}),'compile')
        self.assertIsNone(rust_guest.finding('rust-clippy',json.dumps(message),{'other'}))

    def test_missing_native_marker_preserves_successful_nm_exit_and_is_candidate_failure(self):
        worker=self.worker();expected=worker['rust_contract']
        worker['observations_untrusted']['rust-failure']=dict(contract_sha256=rust.digest(expected),
            stage='rust-native-link',exit_code=1,tool_exit_code=0,binary_sha256='f'*64,finding='link',
            source_unchanged=True,protected_unchanged=True)
        worker['guest_report_untrusted']['error']='rust-native-link: missing required symbol\neqemu_rust_bridge_v1'
        self.assertEqual(common.outcome({},dict(producer=worker),True),1)
        worker['observations_untrusted']['rust-failure']['tool_exit_code']=1
        self.assertEqual(common.outcome({},dict(producer=worker),True),2)


class RustInputCustody(unittest.TestCase):
    def test_cargo_ancestor_configuration_creation_and_symlink_drift_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source';source.mkdir();runtime=root/'rust';runtime.mkdir()
            for name in ('toolchain','vendor','home'):(runtime/name).mkdir()
            (runtime/'config.toml').write_text('fixed');(runtime/'home/config.toml').write_text('fixed')
            expected=rust_guest.protected_inventory(runtime)
            expected['cargo_cwds']=[str(source),str(root/'build')]
            expected['ancestor_configuration']=rust_guest.ancestor_configuration(expected['cargo_cwds'])
            (root/'.cargo').mkdir();(root/'.cargo/config.toml').write_text('[build]\nrustc-wrapper="changed"\n')
            with self.assertRaisesRegex(ValueError,'Protected Rust'):rust_guest.verify_protected(runtime,expected)
            shutil.rmtree(root/'.cargo');(root/'.cargo').symlink_to(runtime/'home',target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'ancestor config symlink'):rust_guest.verify_protected(runtime,expected)

    def test_candidate_stage_input_drift_cannot_emit_success_or_repairable_finding(self):
        for changed in ('toolchain/rustc','vendor/lib.rs','home/config.toml','ancestor-config'):
            with self.subTest(changed=changed),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);source=root/'source';source.mkdir();runtime=root/'rust';runtime.mkdir()
                for name in ('toolchain','vendor','home'):(runtime/name).mkdir()
                for name in ('toolchain/rustc','vendor/lib.rs','config.toml','home/config.toml'):
                    (runtime/name).write_text('verified input')
                protected=rust_guest.protected_inventory(runtime)
                expected=contract();owned='owned-core';bridge='owned-bridge'
                graph=dict(version=1,resolve={'nodes':[]},workspace_members=[owned,bridge],packages=[
                    dict(id=owned,name='actor-core',manifest_path=str(source/'core/Cargo.toml'),targets=[{'name':'actor_core','doctest':True}]),
                    dict(id=bridge,name='actor-bridge',manifest_path=str(source/'bridge/Cargo.toml'),targets=[])])
                events=[]
                def command(stage,*args,**kwargs):
                    log=root/(stage+'.log')
                    if stage=='rust-metadata':log.write_text(json.dumps(graph))
                    else:
                        log.write_text('formatter success')
                        if changed=='ancestor-config':
                            (root/'.cargo').mkdir();(root/'.cargo/config.toml').write_text('candidate wrapper')
                        else:
                            (runtime/changed).write_text('candidate changed protected input')
                    return log
                with patch.object(rust_guest,'guard'),self.assertRaisesRegex(ValueError,'Protected Rust'):
                    rust_guest.check(expected,source,{},lambda *_:None,command,events.append,
                                     {'CARGO_HOME':str(runtime/'home')},protected)
                self.assertEqual([item['name'] for item in events],['rust-preflight'])

    def test_tool_vendor_and_configuration_drift_refuse_but_cache_is_mutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name in ('toolchain','vendor','home'):(root/name).mkdir()
            for name in ('toolchain/rustc','vendor/lib.rs','config.toml','home/config.toml'):
                (root/name).write_text('identified bytes')
            expected=rust_guest.protected_inventory(root)
            (root/'home/cache').write_text('mutable cache')
            rust_guest.verify_protected(root,expected)
            for name in ('toolchain/rustc','vendor/lib.rs','home/config.toml'):
                with self.subTest(name=name):
                    (root/name).write_text('changed bytes')
                    with self.assertRaisesRegex(ValueError,'Protected Rust'):rust_guest.verify_protected(root,expected)
                    (root/name).write_text('identified bytes')
            (root/'home/config').write_text('shadow configuration')
            with self.assertRaises(ValueError):rust_guest.verify_protected(root,expected)

    def test_compiler_warning_cannot_invent_unit_or_doctest_counts(self):
        fake='test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
        diagnostic=json.dumps({'reason':'compiler-message','message':{'rendered':fake}})+'\n'
        for doc in (False,True):
            with self.subTest(doc=doc),self.assertRaisesRegex(ValueError,'Missing/empty'):
                rust_guest.counts(diagnostic+harness(doc=doc,passed=0,ignored=1),1,
                                  {'owned':'actor-core'},{'actor_core':'actor-core'} if doc else None)
            self.assertEqual(rust_guest.counts(harness(doc=doc),1,{'owned':'actor-core'},
                                              {'actor_core':'actor-core'} if doc else None),1)

    def test_unknown_test_executable_and_missing_completion_refuse(self):
        text=harness().replace('(/build/test-core)','(/build/unknown)')
        with self.assertRaises(ValueError):rust_guest.counts(text,1,{'owned':'actor-core'})
        text=harness().replace('test result: ok.','omitted completion:')
        with self.assertRaises(ValueError):rust_guest.counts(text,1,{'owned':'actor-core'})


class RustWorker(unittest.TestCase):
    def protocol(self):
        worker=reporting.recipe('producer-worker.py.in');worker.RUST_CONTRACT=contract()
        protocol=worker.BuildProtocol('nonce');protocol.ready=True;protocol.preflight=True
        return worker,protocol

    def event(self,protocol,name,value):
        return protocol.accept(dict(kind='observation',nonce='nonce',name=name,value=value))

    def populate(self,worker,protocol):
        self.event(protocol,'rust-preflight',preflight(worker.RUST_CONTRACT))
        for name in rust.STAGES:self.event(protocol,name,completion(worker.RUST_CONTRACT))
        self.event(protocol,'rust-native-link',dict(contract_sha256=rust.digest(worker.RUST_CONTRACT),
                   symbol='eqemu_rust_bridge_v1',binary_sha256='a'*64,source_unchanged=True,protected_unchanged=True))

    def test_order_unknown_duplicate_and_partial_coverage_refuse(self):
        worker,protocol=self.protocol()
        with self.assertRaisesRegex(RuntimeError,'predecessor'):
            self.event(protocol,'rust-tests',completion(worker.RUST_CONTRACT))
        self.event(protocol,'rust-preflight',preflight(worker.RUST_CONTRACT))
        with self.assertRaisesRegex(RuntimeError,'Observation name'):
            self.event(protocol,'rust-preflight',preflight(worker.RUST_CONTRACT))
        with self.assertRaises(ValueError):self.event(protocol,'rust-unknown',completion(worker.RUST_CONTRACT))

    def test_native_success_requires_all_rust_observations_and_exact_zone_hash(self):
        for missing in (*rust.REQUIRED,None,'wrong-zone'):
            with self.subTest(missing=missing):
                worker,protocol=self.protocol();self.populate(worker,protocol)
                if missing in rust.REQUIRED:del protocol.observations[missing]
                if missing=='wrong-zone':protocol.observations['rust-native-link']['binary_sha256']='c'*64
                # The existing utility success helper supplies independently checked
                # native records. Rust controls add only their required evidence.
                helper=reporting.HostCoverage()
                value,prior=helper.success(worker,protocol)
                if missing is None:helper.accept(worker,protocol,value,prior)
                else:
                    with self.assertRaises(RuntimeError):helper.accept(worker,protocol,value,prior)


class RustStages(unittest.TestCase):
    def run_checks(self,stage_fault=None,mutate=False):
        root=Path(self.temp.name); source=root/'source';source.mkdir()
        cfg=contract();cfg['manifest_path']='Cargo.toml';cfg['source_blobs']={'Cargo.toml':'a'*40,'Cargo.lock':'b'*40,'rust-toolchain.toml':'c'*40}
        owned='path+file:///source/core#actor-core@0.1.0'
        graph=dict(version=1,resolve={'nodes':[]},workspace_members=[owned,'bridge'],
                   packages=[dict(id=owned,name='actor-core',manifest_path=str(source/'core/Cargo.toml'),targets=[{'name':'actor_core','doctest':True}]),
                             dict(id='bridge',name='actor-bridge',manifest_path=str(source/'bridge/Cargo.toml'))])
        events=[];self.events=events;calls=[];env={'CARGO_HOME':str(root/'rust/home')}
        def command(name,args,**kwargs):
            calls.append((name,args,kwargs));log=root/'logs'/(name+'.log');log.parent.mkdir(exist_ok=True)
            body=json.dumps(graph) if name=='rust-metadata' else harness(owned) if name=='rust-tests' else harness(owned,doc=True)
            if name=='rust-clippy':
                body='\n'.join(json.dumps(dict(reason='compiler-artifact',package_id=x)) for x in (owned,'bridge'))
            if name==stage_fault:
                body='test result: FAILED. 0 passed; 1 failed; 0 ignored;\n'
                log.write_text(body);raise RuntimeError(name+': exit 101\n'+body)
            log.write_text(body);return log
        def verify(*args):
            if mutate and len(calls)>1:raise ValueError('Materialized source mismatch')
        with patch.object(rust_guest,'guard'),patch.object(rust_guest,'verify_protected'):
            rust_guest.check(cfg,source,{},verify,command,events.append,env,{})
        return events,calls

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)

    def test_actual_commands_use_selected_frozen_targets_and_separate_doctests(self):
        events,calls=self.run_checks()
        self.assertEqual([e['name'] for e in events],['rust-preflight',*rust.STAGES])
        commands={name:args for name,args,_ in calls}
        self.assertIn('--filter-platform',commands['rust-metadata'])
        self.assertNotIn('--target',commands['rust-metadata'])
        self.assertEqual(commands['rust-fmt'][-3:],['--all','--','--check'])
        self.assertIn('--doc',commands['rust-doctests'])
        for name in ('rust-clippy','rust-tests','rust-doctests'):self.assertIn('--frozen',commands[name])

    def test_failed_test_emits_specific_finding_and_source_mutation_never_does(self):
        with self.assertRaises(RuntimeError):self.run_checks(stage_fault='rust-tests')
        self.assertEqual(self.events[-1]['name'],'rust-failure')
        self.assertEqual(self.events[-1]['value']['finding'],'test')
        # Recreate fake directory so the second case has independent custody.
        shutil.rmtree(Path(self.temp.name)/'source')
        with self.assertRaises(ValueError):self.run_checks(mutate=True)
        self.assertNotIn('rust-failure',{item['name'] for item in self.events})

    def test_missing_zero_and_failed_test_completions_refuse(self):
        for text in ('','test result: ok. 0 passed; 0 failed; 0 ignored;',
                     'test result: ok. 1 passed; 1 failed; 0 ignored;'):
            with self.assertRaises(ValueError):rust_guest.counts(text,1,{'owned':'actor-core'})
        with self.assertRaises(ValueError):rust_guest.artifacts('',{'selected'})


class RustPackaging(unittest.TestCase):
    def test_proof_cli_refusal_is_explicit_exit_two_without_work(self):
        if Path('/opt/eqemu-proof/BUILD_GUEST_ONLY').exists():
            self.skipTest('Guest marker exists in this execution surface')
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'never-created'
            result=subprocess.run([sys.executable,'-B',str(ROOT/'validation/rust/proof.py'),
                                  '--source',tmp,'--bundle',str(Path(tmp)/'missing'),
                                  '--output',str(output)],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2)
            self.assertEqual(json.loads(result.stdout)['exit_code'],2)
            self.assertFalse(json.loads(result.stdout)['accepted'])
            self.assertFalse(output.exists())

    def test_source_as_data_transfers_bundle_and_refuses_custody_or_lock_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'candidate';source.mkdir();store=root/'store';store.mkdir()
            bundle=store/'rust.tar';bundle.write_bytes(b'opaque sealed input')
            declared=contract();declared['manifest_path']='Cargo.toml'
            declared['bundle']=dict(path=bundle.name,bytes=bundle.stat().st_size,sha256=common.sha(bundle))
            for name in ('Cargo.toml','Cargo.lock','rust-toolchain.toml'):
                (source/name).write_text(name+'\n')
            marker=root/'executed'
            (source/'build.rs').write_text('touch '+str(marker))
            def git(*args):
                return subprocess.check_output(['git','-C',str(source),*args]).decode().strip()
            git('init','-q');git('add','.')
            git('-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','identified candidate')
            declared['source_blobs']={name:git('rev-parse','HEAD:'+name) for name in ('Cargo.toml','Cargo.lock','rust-toolchain.toml')}
            wanted=dict(commit=git('rev-parse','HEAD'),tree=git('rev-parse','HEAD^{tree}'),gitlinks={})
            profile=dict(rust=declared,sources={'eqemu':wanted},submodule_sources={},submodules={},
                         dependencies={'rust':declared['bundle']},dependency_blobs=declared['source_blobs'])
            inputs=common.load('rust_input_package',ROOT/'validation/inputs.py')
            receipt=inputs.prepare(profile,{'eqemu':source},store,root/'output')
            inputs.verify(root/'output',receipt['manifest_sha256'],profile,receipt['input_id'])
            self.assertFalse(marker.exists())
            (root/'output/rust-inputs.tar').chmod(0o600)
            (root/'output/rust-inputs.tar').write_bytes(b'changed')
            with self.assertRaises(ValueError):inputs.verify(root/'output',receipt['manifest_sha256'],profile,receipt['input_id'])
            (source/'Cargo.lock').write_text('changed lock\n');git('add','Cargo.lock')
            git('-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','unsupported closure')
            profile['sources']['eqemu']=dict(commit=git('rev-parse','HEAD'),tree=git('rev-parse','HEAD^{tree}'),gitlinks={})
            with self.assertRaisesRegex(ValueError,'Unsupported dependency closure'):
                inputs.prepare(profile,{'eqemu':source},store,root/'other-output')
            self.assertFalse(marker.exists())

    def test_outer_bundle_missing_duplicate_changed_and_special_members_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);bundle=root/'bundle.tar'
            toolchain={'components':{'rustc':{'sha256':hashlib.sha256(b'compiler').hexdigest()}}}
            text=b'[source.crates-io]\nreplace-with="vendored-sources"\n[source.vendored-sources]\ndirectory="@VENDOR@"\n'
            def write(kind):
                entries=[('rustc.tar.xz',b'compiler'),('vendor.tar',b'vendored'),('vendor-config.toml',text)]
                if kind=='missing':entries=entries[1:]
                if kind=='changed':entries[0]=('rustc.tar.xz',b'other')
                if kind=='duplicate':entries.append(entries[0])
                with tarfile.open(bundle,'w:') as archive:
                    for name,body in entries:
                        item=tarfile.TarInfo(name);item.size=len(body);archive.addfile(item,io.BytesIO(body))
                    if kind=='special':
                        item=tarfile.TarInfo('evil');item.type=tarfile.SYMTYPE;item.linkname='/tmp/escape';archive.addfile(item)
            write('valid');self.assertEqual(set(rust.verify_bundle(bundle,toolchain)),{'rustc.tar.xz','vendor.tar','vendor-config.toml'})
            for kind in ('missing','changed','duplicate','special'):
                write(kind)
                with self.subTest(kind=kind),self.assertRaises(ValueError):rust.verify_bundle(bundle,toolchain)

    def test_reviewed_contract_changes_sealed_identity_and_rendered_producer_only(self):
        fixture=packaging.PackagePreparation();fixture.setUp();self.addCleanup(fixture.doCleanups)
        declared=contract();bundle=fixture.store/'rust.data';bundle.write_bytes(b'x')
        declared['bundle']=dict(path=bundle.name,bytes=1,sha256=common.sha(bundle))
        with patch('rust.verify_bundle',return_value={}):
            prepare.prepare(fixture.root/'rust-output',fixture.store,fixture.websocketpp,fixture.package,rust_contract=declared)
        output=fixture.root/'rust-output'
        profile=json.loads((output/'profile.json').read_text())
        self.assertEqual(profile['rust'],declared)
        destination=fixture.root/'rendered';destination.mkdir()
        def seed(args,**kwargs):Path(args[1]).write_bytes(b'synthetic seed')
        with patch.object(render.subprocess,'run',side_effect=seed):render.render('0123456789',packaging.FACTS,destination,output)
        producer=common.load('rust_rendered_worker',destination/'producer-worker.py')
        self.assertEqual(producer.RUST_CONTRACT,declared)
        user=json.loads((destination/'producer-user-data').read_text().split('\n',1)[1])
        self.assertIn('/opt/eqemu-proof/rust_guest.py',{entry['path'] for entry in user['write_files']})
        consumer=json.loads((destination/'consumer-user-data').read_text().split('\n',1)[1])
        self.assertNotIn('/opt/eqemu-proof/rust_guest.py',{entry['path'] for entry in consumer['write_files']})


if __name__=='__main__':unittest.main()
