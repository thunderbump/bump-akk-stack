"""Fake-root ordering/preservation controls; no native host preflight or privileged action."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
import ast
import contextlib
import io
import shlex
from unittest import mock
from types import SimpleNamespace

SCRIPT=Path(__file__).with_name('activate.py')
OPERATOR=Path('/home/bump/.local/state/eqemu-debugger-inputs-20261008/activation-v1/apply-reviewed-package.sh')
BASELINE_PACKAGE=Path('/home/bump/.local/state/eqemu-debugger-inputs-20261008/package-v3')
INSTALLED_OLD=Path('/usr/local/lib/eqemu-build/9f298e87d6e466e5')

class Host:
    def __init__(self):
        spec=importlib.util.spec_from_file_location('transaction',SCRIPT)
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.prior_mask=os.umask(0o077)
        self.tmp=tempfile.TemporaryDirectory(prefix='actor-activation-test-')
        self.root=Path(self.tmp.name);m=self.m
        m.BASE=self.root/'var/lib/eqemu-build';m.LIB=self.root/'usr/local/lib/eqemu-build'
        m.OLD=m.LIB/m.OLD_HASH[:16];m.NEW=m.LIB/m.MANIFEST[:16];m.STAGE=m.LIB/('.actor-20261005-'+m.MANIFEST[:16])
        m.BACKUP=m.BASE/'activation-backup-20261006-central-t0e1.4.2.4';m.ARCHIVE=m.BACKUP/'archived-runs'
        m.INITIAL=m.BASE/'activation-backup-20261005-central-t0e1.4.2'
        m.HELPER=self.root/'usr/local/sbin/eqemu-build-request';m.CLIENT=self.root/'usr/local/bin/eqemu-validate'
        m.STATE=m.BASE/'installation.json';m.POLICY=self.root/'etc/sudoers.d/eqemu-build'
        m.PACKAGE=BASELINE_PACKAGE
        for p in [m.BASE/'runs',m.BASE/'inputs',m.LIB,m.HELPER.parent,m.CLIENT.parent,m.POLICY.parent]:p.mkdir(parents=True,exist_ok=True,mode=0o700)
        # Read-only baseline copies are code fixtures. Real /var, /etc and system commands are never touched.
        shutil.copytree(INSTALLED_OLD,m.OLD)
        def safe(p,directory=False):
            if not p.resolve().is_relative_to(self.root):raise AssertionError('Fake-root operation escaped mocks: '+str(p))
            s=p.lstat()
            if s.st_mode&0o022 or not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)):raise RuntimeError('Unsafe fake administrator path')
            return s
        m.safe=safe
        m.run=lambda *a,**k: (_ for _ in ()).throw(AssertionError('Unexpected real subprocess from fake-root transaction'))
        self.active=False;self.live=set();self.gates=[];self.archived_probes=[]
        m.idle=lambda: self.check_idle()
        m.uploads_empty=lambda: None
        self.real_prior_gate=m.prior_gate;self.real_archived_absence=m.archived_absence
        m.prior_gate=self.gate;m.archived_absence=self.archive_gate
        m.normal_submitter_identity=lambda: self.normal_identity()
        self.sentinels=[]
        for name in ['passwd','group','nsswitch.conf','sudoers','afk-config.toml','afk-config.json']:
            p=self.root/'etc'/name;p.write_text('preserve-'+name);p.chmod(0o600);self.sentinels.append(p)
        m.policies=lambda: {str(p):m.facts(p) for p in [*self.sentinels,m.POLICY]}
        for p,data in m.wrappers(m.OLD).items():p.write_bytes(data);p.chmod(0o755)
        m.POLICY.write_bytes(m.RULE);m.POLICY.chmod(0o440)
        m.STATE.write_bytes(m.canonical({'enabled':True,'version':str(m.OLD),'manifest_sha256':m.OLD_HASH}));m.STATE.chmod(0o600)
        old_inputs={}
        for name in ['base.qcow2','fixture.iso','runtime.iso']:
            p=m.BASE/'inputs'/name;p.write_bytes(('original-'+name).encode());p.chmod(0o400)
            old_inputs[name]={'source':'fake-'+name,**{k:m.facts(p)[k] for k in ['bytes','sha256']}}
        source=self.root/'runtime-source.iso';source.write_bytes(b'opaque runtime fixture bytes');source.chmod(0o600)
        m.RUNTIME={'source':str(source),**{k:m.facts(source,administrator=False)[k] for k in ('bytes','sha256')}}
        desired_inputs={**old_inputs,'runtime.iso':m.RUNTIME}
        self.real_proof_complete=m.proof_complete
        m.proof_complete=lambda: {'bytes':1,'sha256':'a'*64,'mode':0o644,'uid':0,'gid':0}
        self.results=[]
        for identifier in m.RUNS:
            root=m.BASE/'runs'/identifier;root.mkdir(mode=0o700)
            (root/'evidence').mkdir(mode=0o700)
            (root/'owner.json').write_text(json.dumps({'run_id':identifier,'version':str(m.OLD)}))
            result={'version':1,'run_id':identifier,'terminal':True,'cleanup_complete':True,'accepted':True,'exit_code':0,'controller_group':{'name':'eqemuvmb'+identifier+'ctl.slice','state':'empty','groups_checked':1,'debt':'central-168c','suite_service_state':'inactive','controller_slice_state':'active'}}
            (root/'evidence'/'result.json').write_text(json.dumps(result));self.results.append(result)
        raw,files=m.package(BASELINE_PACKAGE)
        original={p:m.read(p) for p in [m.HELPER,m.CLIENT,m.STATE,m.POLICY]}
        self.plan={'raw':raw,'files':files,'original':original,'modes':{p:stat.S_IMODE(p.stat().st_mode) for p in original},
                   'inputs':m.input_inventory(old_inputs),'old_inputs':old_inputs,'desired_inputs':desired_inputs,
                   'policies':m.policies(),'snapshot':m.run_inventory(m.RUNS),'reports':self.results,'initial_snapshot':{},'proof':m.proof_complete()}
        m.INITIAL.mkdir(mode=0o700);(m.INITIAL/'archived-runs').mkdir(mode=0o700)
        initial_snapshot={}
        for identifier in m.INITIAL_ARCHIVED:
            old=m.INITIAL/'archived-runs'/identifier;old.mkdir(mode=0o700);(old/'owner.json').write_text(json.dumps({'run_id':identifier,'version':str(m.OLD)}));initial_snapshot[identifier]=m.tree(old)
        (m.INITIAL/'receipt.json').write_bytes(m.canonical({'new_version':str(m.OLD),'new_manifest_sha256':m.OLD_HASH,'archived_ids':m.INITIAL_ARCHIVED,'run_snapshot':initial_snapshot}))
        self.plan['initial_snapshot']=m.initial_preserved()
        self.original_inputs={p.name:p.read_bytes() for p in (m.BASE/'inputs').iterdir()}
    def close(self):
        self.tmp.cleanup();os.umask(self.prior_mask)
    def check_idle(self):
        if self.active:raise RuntimeError('AFK services active')
    def gate(self,version,ids):
        if version==self.m.NEW and '9924578091' in ids:raise RuntimeError('Actor row cannot be restored/read under9f')
        self.m.run_inventory(ids);self.gates.append((str(version),tuple(ids)))
        if self.live & set(ids):raise RuntimeError('Native resource remains')
        return [r for r in self.results if r['run_id'] in ids]
    def normal_identity(self):
        if stat.S_IMODE(self.m.NEW.stat().st_mode)!=0o755 or self.state()['enabled']:raise RuntimeError('Submitter entrypoint before755/whileenabled')
    def archive_gate(self,identifier,audit_root=None):
        self.archived_probes.append(identifier)
        if identifier in self.live:raise RuntimeError('Archived original resource remains')
    def state(self):return json.loads(self.m.STATE.read_text())
    def apply(self):
        self.check_idle()
        self.gate(self.m.OLD,self.m.RUNS)
        return self.m.apply(self.plan)
    def assert_preserved(self,test):
        m=self.m
        test.assertEqual(m.policies(),self.plan['policies'])
        for name,raw in self.original_inputs.items():
            if name=='runtime.iso':
                current=(m.BASE/'inputs'/name).read_bytes()
                test.assertTrue(current==raw or current==Path(m.RUNTIME['source']).read_bytes())
                if current!=raw:test.assertEqual((m.BACKUP/'runtime.iso.original').read_bytes(),raw)
            else:test.assertEqual((m.BASE/'inputs'/name).read_bytes(),raw)
        test.assertEqual(m.verify_distribution(self.plan['snapshot'])[0]+[],sorted(p.name for p in (m.BASE/'runs').iterdir()))

class Transaction(unittest.TestCase):
    def setUp(self):self.h=Host();self.addCleanup(self.h.close)
    def test_apply_exact_failed_archive_four_slots_and_no_foreign_changes(self):
        h=self.h;m=h.m;result=h.apply()
        self.assertEqual(result['headroom'],4);self.assertFalse(result['vm_started'])
        self.assertEqual(m.verify_distribution(h.plan['snapshot']),(m.RETAINED,m.ARCHIVED))
        self.assertEqual(h.state(),{'enabled':True,'version':str(m.NEW),'manifest_sha256':m.MANIFEST})
        self.assertEqual(m.facts(m.BASE/'inputs/runtime.iso')['mode'],0o400)
        self.assertEqual(m.read(m.POLICY),m.RULE);h.assert_preserved(self)
        receipt=json.loads(m.read(m.BACKUP/'receipt.json',8*1024**2))
        self.assertEqual(receipt['archived_ids'],['9924578091'])
        self.assertIn('normal run-ID lookup no longer applies',receipt['archive_lookup'])
        self.assertIn((str(m.NEW),tuple(m.RETAINED)),h.gates)
    def test_undo_restores_all_receipts_wrappers_inputs_and_retains_added_audit(self):
        h=self.h;m=h.m;h.apply();result=m.undo()
        self.assertTrue(result['undone']);self.assertEqual(m.run_inventory(m.RUNS),h.plan['snapshot'])
        self.assertEqual(set(p.name for p in (m.BASE/'inputs').iterdir()),set(h.original_inputs))
        self.assertFalse((m.BACKUP/'runtime.iso.installed').exists());self.assertTrue(m.NEW.exists())
        self.assertTrue(h.state()['enabled']);self.assertEqual(h.state()['version'],str(m.OLD))
        for p in [m.HELPER,m.CLIENT,m.STATE,m.POLICY]:self.assertEqual(m.read(p),h.plan['original'][p])
        self.assertIn(m.ARCHIVED[0],h.archived_probes);h.assert_preserved(self)
    def test_preflight_refuses_unknown_run_inventory(self):
        m=self.h.m;(m.BASE/'runs'/'unexpected').mkdir(mode=0o700)
        with self.assertRaisesRegex(RuntimeError,'inventory'):m.run_inventory(m.RUNS)
    def test_live_old_resource_and_active_afk_refuse_before_mutation(self):
        h=self.h;h.live.add(h.m.RUNS[0])
        with self.assertRaisesRegex(RuntimeError,'resource'):h.apply()
        self.assertFalse(h.m.BACKUP.exists());self.assertTrue(h.state()['enabled'])
        h.live.clear();h.active=True
        with self.assertRaisesRegex(RuntimeError,'AFK'):h.apply()
        self.assertFalse(h.m.BACKUP.exists())
    def test_archival_failure_keeps_admission_disabled_and_undo_restores(self):
        h=self.h;m=h.m;move=m.move
        m.move=lambda *args: (_ for _ in ()).throw(RuntimeError('injected archive failure'))
        with self.assertRaisesRegex(RuntimeError,'injected'):h.apply()
        self.assertFalse(h.state()['enabled']);self.assertEqual(m.verify_distribution(h.plan['snapshot'])[1],[])
        m.move=move;self.assertTrue(m.undo()['undone']);self.assertEqual(m.run_inventory(m.RUNS),h.plan['snapshot'])
    def test_partial_release_write_is_retained_and_undo_remains_possible(self):
        h=self.h;m=h.m;write=m.write_new
        def fail_stage(path,data,mode):
            if path.parent==m.STAGE:
                write(path,data[:7],mode);raise RuntimeError('injected staging write failure')
            return write(path,data,mode)
        m.write_new=fail_stage
        with self.assertRaisesRegex(RuntimeError,'staging'):h.apply()
        self.assertFalse(h.state()['enabled']);self.assertTrue(m.STAGE.exists());self.assertFalse(m.NEW.exists())
        m.write_new=write;self.assertTrue(m.undo()['undone']);self.assertTrue(m.STAGE.exists())
    def test_base_build_inputs_and_initial_archive_stay_identical_with_runtime_preserved(self):
        h=self.h;m=h.m;before=m.tree(m.INITIAL);h.apply()
        self.assertEqual(m.tree(m.INITIAL),before);self.assertEqual(set(p.name for p in (m.BASE/'inputs').iterdir()),set(h.original_inputs))
        for name,value in h.original_inputs.items():
            location=m.BACKUP/'runtime.iso.original' if name=='runtime.iso' else m.BASE/'inputs'/name
            self.assertEqual(location.read_bytes(),value)
    def test_undo_refuses_new_job_or_original_receipt_drift(self):
        h=self.h;m=h.m;h.apply();new=m.BASE/'runs'/'1111111111';new.mkdir(mode=0o700)
        with self.assertRaisesRegex(RuntimeError,'selection'):m.undo()
        new.rmdir();receipt=m.BASE/'runs'/m.RETAINED[0]/'owner.json';receipt.write_text('changed')
        with self.assertRaisesRegex(RuntimeError,'bytes'):m.undo()
        self.assertEqual(h.state()['version'],str(m.NEW))
    def test_undo_refuses_archive_tamper_and_live_original_resource(self):
        h=self.h;m=h.m;h.apply();h.live.add(m.ARCHIVED[0])
        with self.assertRaisesRegex(RuntimeError,'resource'):m.undo()
        h.live.clear();(m.ARCHIVE/m.ARCHIVED[0]/'owner.json').write_text('changed')
        with self.assertRaisesRegex(RuntimeError,'bytes'):m.undo()
    def test_preserved_nss_policy_drift_refuses_undo(self):
        h=self.h;m=h.m;h.apply();h.sentinels[0].write_text('external NSS mutation')
        with self.assertRaisesRegex(RuntimeError,'policy'):m.undo()
    def test_descriptor_rejects_symlink_nonregular_and_oversize(self):
        m=self.h.m;p=self.h.root/'small';p.write_bytes(b'longer');link=self.h.root/'link';link.symlink_to(p)
        with self.assertRaises(OSError):m.read(link,administrator=False)
        with self.assertRaisesRegex(RuntimeError,'bounded'):m.read(p,2,administrator=False)
        fifo=self.h.root/'fifo';os.mkfifo(fifo)
        with self.assertRaisesRegex(RuntimeError,'bounded'):m.read(fifo,administrator=False)
    def test_reviewed_package_inventory_and_byte_tamper_refuse(self):
        m=self.h.m;p=self.h.root/'package';shutil.copytree(BASELINE_PACKAGE,p)
        extra=p/'foreign.py';extra.write_text('foreign')
        with self.assertRaisesRegex(RuntimeError,'inventory'):m.package(p)
        extra.unlink();first=next(k for k in json.loads((p/'manifest.json').read_text())['files'])
        (p/first).write_text('changed')
        with self.assertRaisesRegex(RuntimeError,'file changed'):m.package(p)
    def test_generated_finite_readers_compile_without_host_execution(self):
        h=self.h;m=h.m;commands=[]
        def checked(args):
            self.assertEqual(args[:3],['/usr/bin/python3','-I','-c'])
            ast.parse(args[3]);commands.append(args[3])
            if 'archived_run' in args[3]:
                return SimpleNamespace(stdout=json.dumps({'archived_run':m.ARCHIVED[0],'original_worker_resources_absent':True,'controller_group':{'name':'eqemuvmb'+m.ARCHIVED[0]+'ctl.slice','state':'empty','groups_checked':1,'debt':'central-168c','suite_service_state':'inactive','controller_slice_state':'active'}}))
            return SimpleNamespace(stdout=json.dumps(h.results))
        m.run=checked
        self.assertEqual(len(h.real_prior_gate(m.OLD,m.RUNS)),5)
        h.apply();h.real_archived_absence(m.ARCHIVED[0])
        self.assertEqual(len(commands),2)
    def test_final_enable_failure_is_disabled_before_return_and_undo_works(self):
        h=self.h;m=h.m;atomic=m.atomic;failed=False
        def fail_commit(path,data,mode):
            nonlocal failed
            value=json.loads(data) if path==m.STATE else None
            if value and value['enabled'] and value['version']==str(m.NEW) and not failed:
                failed=True;atomic(path,data,mode);raise RuntimeError('injected post-rename commit failure')
            return atomic(path,data,mode)
        m.atomic=fail_commit
        with self.assertRaisesRegex(RuntimeError,'commit'):h.apply()
        self.assertFalse(h.state()['enabled']);m.atomic=atomic
        self.assertTrue(m.undo()['undone'])
    def test_operator_wrapper_compiles_captured_pinned_code_and_rejects_wrong_pin(self):
        wrapper=OPERATOR.read_text()
        argv=shlex.split(wrapper.splitlines()[-1]);self.assertEqual(argv[:4],['sudo','/usr/bin/python3','-I','-c'])
        code=argv[4];ast.parse(code);prior=sys.argv
        try:
            with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()),mock.patch('os.geteuid',return_value=1000):
                with self.assertRaises(SystemExit) as result:exec(compile(code,'operator-wrapper','exec'),{})
                self.assertEqual(result.exception.code,2)
            import hashlib
            digest=hashlib.sha256(SCRIPT.read_bytes()).hexdigest()
            with self.assertRaisesRegex(AssertionError,'code changed'):exec(compile(code.replace(digest,'0'*64),'wrong-pin-wrapper','exec'),{})
        finally:sys.argv=prior
    def test_draft_unarmed_entry_refuses_without_any_host_io(self):
        m=self.h.m;m.FINAL_PACKAGE_APPROVED=False;prior=sys.argv;sys.argv=[str(SCRIPT),'--apply']
        try:
            with self.assertRaisesRegex(RuntimeError,'unarmed'):m.main()
        finally:sys.argv=prior

    def test_changed_runtime_source_disables_admission_and_undo_preserves_old_bytes(self):
        h=self.h;m=h.m;Path(m.RUNTIME['source']).write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError,'Runtime source'):h.apply()
        self.assertFalse(h.state()['enabled'])
        self.assertTrue(m.undo()['undone'])
        self.assertEqual((m.BASE/'inputs/runtime.iso').read_bytes(),h.original_inputs['runtime.iso'])

    def test_failure_between_media_renames_can_restore_missing_current_input(self):
        h=self.h;m=h.m;rename=m.os.rename
        def fail_new(source,target):
            if source==m.BACKUP/'runtime.iso.new':raise RuntimeError('injected media rename')
            return rename(source,target)
        with mock.patch.object(m.os,'rename',side_effect=fail_new):
            with self.assertRaisesRegex(RuntimeError,'media rename'):h.apply()
        self.assertFalse((m.BASE/'inputs/runtime.iso').exists())
        self.assertFalse(h.state()['enabled'])
        self.assertTrue(m.undo()['undone'])
        self.assertEqual((m.BASE/'inputs/runtime.iso').read_bytes(),h.original_inputs['runtime.iso'])

    def test_successful_undo_keeps_new_media_as_audit_and_restores_original_metadata(self):
        h=self.h;m=h.m;before=m.facts(m.BASE/'inputs/runtime.iso')
        h.apply();self.assertEqual((m.BASE/'inputs/runtime.iso').read_bytes(),Path(m.RUNTIME['source']).read_bytes())
        self.assertTrue(m.undo()['undone'])
        self.assertEqual(m.facts(m.BASE/'inputs/runtime.iso'),before)
        self.assertEqual((m.BACKUP/'runtime.iso.retired').read_bytes(),Path(m.RUNTIME['source']).read_bytes())

    def test_tampered_preserved_media_refuses_undo_without_selecting_unknown_bytes(self):
        h=self.h;m=h.m;h.apply();saved=m.BACKUP/'runtime.iso.original'
        saved.chmod(0o600);saved.write_bytes(b'tampered');saved.chmod(0o400)
        with self.assertRaisesRegex(RuntimeError,'identity'):m.undo()
        self.assertFalse(h.state()['enabled'])
        self.assertEqual((m.BASE/'inputs/runtime.iso').read_bytes(),Path(m.RUNTIME['source']).read_bytes())


class ProvisioningGate(unittest.TestCase):
    def setUp(self):
        self.h=Host();self.addCleanup(self.h.close);m=self.h.m;self.m=m
        original=Path('/var/lib/eqemu-vm-proof/debugger-proof-20261008b/evidence/report.json').read_bytes()
        m.PROOF=self.h.root/'provisioning-proof';(m.PROOF/'evidence').mkdir(parents=True)
        self.report=m.PROOF/'evidence/report.json';self.report.write_bytes(original)
        value=json.loads(original)
        (m.PROOF/'evidence/cleanup.json').write_text(json.dumps(value['cleanup']))
        m.RUNTIME={'sha256':value['inputs']['runtime.iso']}
        m.proof_complete=self.h.real_proof_complete
        m.run=lambda _:SimpleNamespace(stdout='ActiveState=inactive\nMainPID=0\nControlPID=0\n')

    def test_exact_successful_receipt_and_quiescent_service_are_required(self):
        self.assertEqual(self.m.proof_complete()['sha256'],self.m.PROOF_REPORT_SHA)

    def test_changed_receipt_cannot_substitute_for_the_selected_provisioning(self):
        self.report.write_bytes(self.report.read_bytes()+b' ')
        with self.assertRaisesRegex(RuntimeError,'receipt changed'):self.m.proof_complete()

    def test_live_service_refuses_even_with_a_successful_stored_receipt(self):
        self.m.run=lambda _:SimpleNamespace(stdout='ActiveState=active\nMainPID=123\nControlPID=0\n')
        with self.assertRaisesRegex(RuntimeError,'quiescent'):self.m.proof_complete()

    def test_retained_disposable_disk_directory_refuses_activation(self):
        (self.m.PROOF/'data').mkdir()
        with self.assertRaisesRegex(RuntimeError,'resource remains'):self.m.proof_complete()

class NativeControllerProbe(unittest.TestCase):
    def setUp(self):
        spec=importlib.util.spec_from_file_location('controller_controls',SCRIPT)
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        self.ns={};exec(compile(m.CONTROLLER_PROBE,'frozen-controller-probe','exec'),self.ns)
        self.temp=tempfile.TemporaryDirectory(prefix='actor-controller-probe-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.prior_mask=os.umask(0o077);self.addCleanup(os.umask,self.prior_mask)
        self.identifier='bdf35611d3';self.name='eqemuvmb'+self.identifier+'ctl.slice'
        self.suite=SimpleNamespace(CTL=self.name,CTLFILE=self.root/'controller.slice',UNIT='owned-suite.service',
            properties=lambda unit:{'ActiveState':'inactive','MainPID':'0','ControlPID':'0'},
            quiescent=lambda props:props['ActiveState'] in ['inactive','failed'] and props['MainPID']==props['ControlPID']=='0')
        self.real_slice=self.ns['_cg_slice_properties']
        self.slice_state='active'
        self.ns['_cg_slice_properties']=lambda suite:{'LoadState':'loaded','ActiveState':self.slice_state,'SubState':'active' if self.slice_state=='active' else 'dead','FragmentPath':'','DropInPaths':'','Transient':'no'}
        self.real_info=self.ns['_cg_info']
        def fake_root_owner(info,directory=False):
            # Only UID is simulated. Actual scratch mode/type/caps, nofollow opens and descendant reads run unchanged.
            self.real_info(SimpleNamespace(st_uid=0,st_mode=info.st_mode,st_size=info.st_size),directory)
        self.ns['_cg_info']=fake_root_owner
    def group(self,path=None):
        path=self.root/self.name if path is None else path;path.mkdir(mode=0o700)
        (path/'cgroup.procs').write_bytes(b'');(path/'cgroup.events').write_bytes(b'populated 0\nfrozen 0\n')
        return path
    def probe(self):return self.ns['_controller_probe'](self.suite,self.identifier,root=self.root)
    def test_absent_controller_and_empty_controller_are_distinct_truthful_results(self):
        self.slice_state='inactive';self.assertEqual(self.probe()['state'],'absent')
        self.slice_state='active';self.group();value=self.probe();self.assertEqual(value['state'],'empty');self.assertEqual(value['suite_service_state'],'inactive');self.assertEqual(value['controller_slice_state'],'active')
    def test_empty_descendants_checked_and_populated_descendant_refuses(self):
        parent=self.group();child=self.group(parent/'owned-worker.service')
        with self.assertRaisesRegex(RuntimeError,'descendants'):self.probe()
        (child/'cgroup.events').write_bytes(b'populated 1\nfrozen 0\n')
        with self.assertRaisesRegex(RuntimeError,'descendants'):self.probe()
    def test_live_process_or_malformed_process_list_refuses_even_populated_zero(self):
        parent=self.group()
        for value in [b'123\n',b'unknown\n',b'\n']:
            (parent/'cgroup.procs').write_bytes(value)
            with self.assertRaisesRegex(RuntimeError,'process list'):self.probe()
    def test_missing_duplicate_unknown_or_bad_events_refuse(self):
        parent=self.group()
        for value in [b'',b'populated 0\n',b'populated 0\nfrozen 0\npopulated 0\n',b'populated zero\nfrozen 0\n',b'populated 0\nfrozen 0\nunknown 0\n']:
            (parent/'cgroup.events').write_bytes(value)
            with self.assertRaisesRegex(RuntimeError,'events|unknown'):self.probe()
        (parent/'cgroup.events').unlink()
        with self.assertRaises(FileNotFoundError):self.probe()
    def test_wrong_identity_active_unit_or_unit_file_refuses(self):
        self.suite.CTL='unrelated.slice'
        with self.assertRaisesRegex(RuntimeError,'identity'):self.probe()
        self.suite.CTL=self.name;self.suite.properties=lambda unit:{'ActiveState':'active','MainPID':'1','ControlPID':'0'}
        with self.assertRaisesRegex(RuntimeError,'active'):self.probe()
        self.suite.properties=lambda unit:{'ActiveState':'inactive','MainPID':'0','ControlPID':'0'}
        self.suite.CTLFILE.symlink_to('missing-controller')
        with self.assertRaisesRegex(RuntimeError,'unit file'):self.probe()
    def test_root_owner_regular_type_and_bounds_are_actual_gate_requirements(self):
        for value in [SimpleNamespace(st_uid=1000,st_mode=stat.S_IFDIR|0o755,st_size=0),
                      SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o775,st_size=0)]:
            with self.assertRaisesRegex(RuntimeError,'Unsafe'):self.real_info(value,True)
        with self.assertRaisesRegex(RuntimeError,'Unsafe'):self.real_info(SimpleNamespace(st_uid=0,st_mode=stat.S_IFIFO|0o600,st_size=0))
        with self.assertRaisesRegex(RuntimeError,'bound'):self.real_info(SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_size=65537))
    def test_writable_group_symlink_and_nonregular_file_refuse(self):
        parent=self.group();parent.chmod(0o770)
        with self.assertRaisesRegex(RuntimeError,'Unsafe'):self.probe()
        parent.chmod(0o700);(parent/'foreign-link').symlink_to('missing')
        with self.assertRaisesRegex(RuntimeError,'unsafe'):self.probe()
        (parent/'foreign-link').unlink();(parent/'cgroup.procs').unlink();os.mkfifo(parent/'cgroup.procs')
        with self.assertRaisesRegex(RuntimeError,'Unsafe'):self.probe()
    def test_symlinked_controller_directory_and_critical_file_refuse(self):
        elsewhere=self.root/'other';elsewhere.mkdir();(self.root/self.name).symlink_to(elsewhere)
        with self.assertRaises(OSError):self.probe()
        (self.root/self.name).unlink();parent=self.group();(parent/'cgroup.events').unlink();(parent/'cgroup.events').symlink_to(self.root/'events')
        with self.assertRaises(OSError):self.probe()
    def test_excess_depth_and_unknown_descendant_name_refuse(self):
        parent=self.group();child=self.group(parent/'unknown name')
        with self.assertRaisesRegex(RuntimeError,'Unknown'):self.probe()
        shutil.rmtree(child)
        for _ in range(5):parent=self.group(parent/'owned-child.slice')
        with self.assertRaisesRegex(RuntimeError,'descendants'):self.probe()
    def test_unit_becoming_active_or_events_changing_during_probe_refuses(self):
        parent=self.group();calls=0
        def properties(unit):
            nonlocal calls
            calls+=1
            return {'ActiveState':'inactive' if calls==1 else 'active','MainPID':'0','ControlPID':'0'}
        self.suite.properties=properties
        with self.assertRaisesRegex(RuntimeError,'changed'):self.probe()
        self.suite.properties=lambda unit:{'ActiveState':'inactive','MainPID':'0','ControlPID':'0'}
        read=self.ns['_cg_read'];calls=0
        def changed(fd,name):
            nonlocal calls
            if name=='cgroup.events':
                calls+=1
                if calls==2:(parent/name).write_bytes(b'populated 1\nfrozen 0\n')
            return read(fd,name)
        self.ns['_cg_read']=changed
        with self.assertRaisesRegex(RuntimeError,'populated'):self.probe()

    def test_exact_controller_name_replacement_refuses_original_empty_fd(self):
        parent=self.group();events=self.ns['_cg_events'];calls=0
        def replace(fd):
            nonlocal calls
            calls+=1
            if calls==2:
                parent.rename(self.root/'retired-empty')
                replacement=self.group()
                (replacement/'cgroup.procs').write_bytes(b'123\n')
                (replacement/'cgroup.events').write_bytes(b'populated 1\nfrozen 0\n')
            return events(fd)
        self.ns['_cg_events']=replace
        with self.assertRaisesRegex(RuntimeError,'identity changed'):self.probe()
        self.assertEqual((self.root/self.name/'cgroup.procs').read_bytes(),b'123\n')
    def test_even_an_empty_named_descendant_is_refused_before_visiting(self):
        parent=self.group();self.group(parent/'owned-worker.service')
        with self.assertRaisesRegex(RuntimeError,'descendants'):self.probe()
    def test_absent_controller_reappearing_during_final_unit_query_refuses(self):
        calls=0
        def properties(unit):
            nonlocal calls
            calls+=1
            if calls==2:self.group()
            return {'ActiveState':'inactive','MainPID':'0','ControlPID':'0'}
        self.suite.properties=properties
        with self.assertRaisesRegex(RuntimeError,'reappeared'):self.probe()
    def test_unit_file_creation_during_present_or_absent_probe_refuses(self):
        parent=self.group();events=self.ns['_cg_events'];calls=0
        def create(fd):
            nonlocal calls
            calls+=1
            if calls==2:self.suite.CTLFILE.write_bytes(b'controller file created')
            return events(fd)
        self.ns['_cg_events']=create
        with self.assertRaisesRegex(RuntimeError,'unit file appeared'):self.probe()
        self.suite.CTLFILE.unlink();shutil.rmtree(parent);calls=0
        def properties(unit):
            nonlocal calls
            calls+=1
            if calls==2:self.suite.CTLFILE.symlink_to('missing')
            return {'ActiveState':'inactive','MainPID':'0','ControlPID':'0'}
        self.suite.properties=properties
        with self.assertRaisesRegex(RuntimeError,'unit file appeared'):self.probe()

    def test_population_or_process_appearing_during_final_query_refuses(self):
        parent=self.group()
        for events_value,procs_value in [(b'populated 1\nfrozen 0\n',b'123\n'),(b'populated 0\nfrozen 0\n',b'123\n')]:
            (parent/'cgroup.events').write_bytes(b'populated 0\nfrozen 0\n');(parent/'cgroup.procs').write_bytes(b'');calls=0
            def properties(unit):
                nonlocal calls
                calls+=1
                if calls==2:
                    (parent/'cgroup.events').write_bytes(events_value);(parent/'cgroup.procs').write_bytes(procs_value)
                return {'ActiveState':'inactive','MainPID':'0','ControlPID':'0'}
            self.suite.properties=properties
            with self.assertRaisesRegex(RuntimeError,'populated|contents'):self.probe()
    def test_descendant_addition_during_final_query_refuses(self):
        parent=self.group();calls=0
        def properties(unit):
            nonlocal calls
            calls+=1
            if calls==2:self.group(parent/'new-empty-child.slice')
            return {'ActiveState':'inactive','MainPID':'0','ControlPID':'0'}
        self.suite.properties=properties
        with self.assertRaisesRegex(RuntimeError,'hierarchy'):self.probe()
    def test_descendant_added_during_final_check_window_refuses_even_when_empty(self):
        parent=self.group();events=self.ns['_cg_events'];calls=0
        def add(fd):
            nonlocal calls
            calls+=1
            if calls==2:self.group(parent/'new-empty-child.slice')
            return events(fd)
        self.ns['_cg_events']=add
        with self.assertRaisesRegex(RuntimeError,'hierarchy'):self.probe()
    def test_unit_file_created_during_final_content_read_refuses(self):
        self.group();events=self.ns['_cg_events'];calls=0
        def create(fd):
            nonlocal calls
            calls+=1
            if calls==3:self.suite.CTLFILE.write_bytes(b'late controller file')
            return events(fd)
        self.ns['_cg_events']=create
        with self.assertRaisesRegex(RuntimeError,'unit file appeared'):self.probe()

if __name__=='__main__':unittest.main(verbosity=2)
