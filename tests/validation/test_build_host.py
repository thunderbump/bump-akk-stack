"""Privilege-boundary admission controls without installing or starting a VM."""
import importlib.util
import json
import copy
import contextlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation'))
import common


class HostAdmission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The package installs the already-qualified host path/request helpers.
        cls.package=tempfile.TemporaryDirectory(prefix='eqemu-build-host-module-')
        directory=Path(cls.package.name)
        shutil.copyfile(ROOT/'validation/host.py',directory/'host.py')
        shutil.copyfile(ROOT/'validation/host_support.py',directory/'host_support.py')
        spec=importlib.util.spec_from_file_location('test_build_host',directory/'host.py')
        cls.host=importlib.util.module_from_spec(spec)
        with patch.object(common,'HERE',directory):spec.loader.exec_module(cls.host)

    @classmethod
    def tearDownClass(cls):cls.package.cleanup()

    def test_request_cannot_select_host_paths_commands_limits_or_other_profiles(self):
        facts=dict(candidate='a'*40,tree='b'*40,input_id='c'*64,manifest_sha256='d'*64,
                   iso_sha256='e'*64,iso_bytes=1)
        value=dict(version=1,op='run',run_id='0123456789',profile=common.PROFILE,candidate=facts)
        self.assertEqual(self.host.parse(json.dumps(value))['candidate'],facts)
        for change in ({'path':'/etc/shadow'},{'command':['true']},{'profile':'startup-diagnostic'},
                       {'run_id':'../shadow'},{'version':True},{'seconds':0}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.host.parse(json.dumps(dict(value,**change)))
        with self.assertRaises(ValueError):self.host.parse('{"version":1,"version":1}')

    def test_copy_only_owned_bounded_regular_upload_and_check_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);directory=base/'uploads'/str(os.getuid());directory.mkdir(parents=True,mode=0o700)
            source=directory/'0123456789.iso';source.write_bytes(b'opaque ISO');source.chmod(0o600)
            facts={'iso_bytes':source.stat().st_size,'iso_sha256':common.sha(source)}
            with patch.object(self.host,'BASE',base):
                self.host.copy_upload(os.getuid(),'0123456789',facts,base/'copied')
                self.assertEqual((base/'copied').read_bytes(),b'opaque ISO')
                with self.assertRaisesRegex(ValueError,'changed'):
                    self.host.copy_upload(os.getuid(),'0123456789',dict(facts,iso_sha256='0'*64),base/'bad-hash')
                source.unlink();source.symlink_to(base/'copied')
                with self.assertRaises(OSError):self.host.copy_upload(os.getuid(),'0123456789',facts,base/'link')
                source.unlink();os.mkfifo(source,0o600)
                with self.assertRaises(ValueError):self.host.copy_upload(os.getuid(),'0123456789',facts,base/'fifo')
                source.unlink();os.link(base/'copied',source)
                with self.assertRaises(ValueError):self.host.copy_upload(os.getuid(),'0123456789',facts,base/'hardlink')

    def test_wrong_owner_is_rejected_before_loading_or_cancelling(self):
        record={'uid':os.getuid()+1,'run_id':'0123456789','version':str(self.host.HERE)}
        with patch.object(self.host.S,'safe_path'),patch.object(self.host.S,'read_json',return_value=record):
            with self.assertRaisesRegex(ValueError,'ownership'):self.host.owner('0123456789',os.getuid())

    def test_prelaunch_failure_cleans_only_known_media(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);prepared=root/'prepared';prepared.mkdir()
            for name in ('candidate.iso','producer-seed.iso','consumer-seed.iso','unrelated'):(prepared/name).write_text('owned')
            record={'candidate':{},'setup_failed_clean':True,'error':'copy failed'}
            with patch.object(self.host,'owner',return_value=(root,record)),patch.object(self.host.S,'safe_path'),\
                 patch.object(self.host.S,'write_json'):
                result=self.host.report('0123456789',os.getuid())
            self.assertTrue(result['terminal']);self.assertTrue(result['cleanup_complete'])
            self.assertEqual(result['exit_code'],2);self.assertFalse(result['accepted'])
            self.assertEqual([p.name for p in prepared.iterdir()],['unrelated'])

    @contextlib.contextmanager
    def retired(self, pin_slot=0):
        """Small synthetic administrator trust pin, without an installed host."""
        with tempfile.TemporaryDirectory() as tmp,contextlib.ExitStack() as patches:
            base=Path(tmp);lib=base/'lib';lib.mkdir()
            package=lib/'draft';package.mkdir()
            profile={'sources':{'eqemu':{'commit':'a'*40,'tree':'b'*40}},'fixed':'build-unit-v1'}
            (package/'profile.json').write_text(json.dumps(profile))
            (package/'suite.py.in').write_text('reviewed recipe')
            manifest={'version':1,'files':{p.name:common.sha(p) for p in package.iterdir()}}
            (package/'manifest.json').write_text(json.dumps(manifest))
            digest=common.sha(package/'manifest.json');version=lib/digest[:16];package.rename(version)
            root=base/'runs/0123456789';prepared=root/'prepared';prepared.mkdir(parents=True)
            work=root/'work';work.mkdir()
            for name in ('launcher.py','producer-worker.py','consumer-worker.py'):
                (prepared/name).write_text('reviewed generated recipe')
            shutil.copyfile(prepared/'launcher.py',work/'suite.py')
            facts=dict(candidate='a'*40,tree='b'*40,input_id='c'*64,manifest_sha256='d'*64,iso_sha256='e'*64,iso_bytes=1)
            recipe=dict(build_id=common.seal(dict(profile=profile,input_id=facts['input_id'],
                 manifest_sha256=facts['manifest_sha256'],recipe=manifest['files'])),
                 launcher_sha256=common.sha(prepared/'launcher.py'),
                 workers={name:common.sha(prepared/name) for name in ('producer-worker.py','consumer-worker.py')})
            record=dict(uid=1000,run_id=root.name,version=str(version),candidate=facts,recipe=recipe)
            (root/'owner.json').write_text(json.dumps(record))
            (root/'result.json').write_text(json.dumps(dict(version=1,run_id=root.name,profile=common.PROFILE,
                 candidate=facts,build_id=recipe['build_id'],terminal=True,cleanup_complete=True,exit_code=0,accepted=True)))
            (work/'suite-result.json').write_text(json.dumps(dict(cleanup={'complete':True},suite_passed=True,cases_passed=True,
                 cases={role:{'case_passed':True} for role in ('producer','consumer')})))
            (work/'leases.json').write_text('{"active":{}}')
            (prepared/'candidate.iso').write_text('retained media')
            worker=SimpleNamespace(ROOT=work/'absent-worker',STORE=work/'absent-store')
            suite=SimpleNamespace(ROOT=work,LOCAL=prepared,SCRIPT=work/'suite.py',CASES=('producer','consumer'),UNIT='fixed',
                 properties=lambda unit:{'stopped':True},quiescent=lambda props:props['stopped'],module=lambda *a,**k:worker)
            patches.enter_context(patch.object(self.host,'LIB',lib))
            patches.enter_context(patch.object(self.host,'BASE',base))
            patches.enter_context(patch.object(self.host,'PRIOR_MANIFESTS',(digest,'0'*64) if pin_slot == 0 else ('0'*64,digest)))
            patches.enter_context(patch.object(self.host.S,'safe_path',side_effect=lambda path,**kw:path.lstat()))
            def read(path):
                self.host.S.safe_path(path)
                return json.loads(path.read_text())
            patches.enter_context(patch.object(self.host.S,'read_json',side_effect=read))
            patches.enter_context(patch.object(self.host,'suite_for',return_value=suite))
            patches.enter_context(patch.object(self.host,'unstarted_absent',return_value=True))
            yield root,record,version,suite

    def test_only_three_declared_prior_release_pins_are_supported(self):
        self.assertEqual(self.host.PRIOR_MANIFESTS, (
            'b193e5db558ff5346177941ca531b4ab26228f9aad7bbc7942ab33cd3311498a',
            'fc320a5152c47403f85332c35f14cf61482a3b1b95d52d68ea557382aeaa8c97',
            'a1eec9b33bbca1ba1d3c4b8911a1827ca1b1dd4d2ef72657699a0569201ba83a'))
        for slot in (0, 1):
            with self.subTest(slot=slot), self.retired(pin_slot=slot) as (root,record,version,suite):
                before={str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()}
                with patch.object(self.host.S,'write_json') as write:
                    result=self.host.prior_report(root,record)
                self.assertTrue(result['terminal']);self.assertTrue(result['cleanup_complete'])
                write.assert_not_called()
                self.assertEqual(before,{str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()})
                record['version']=str(self.host.LIB/('f'*16))
                with patch.object(self.host,'suite_for') as load,self.assertRaisesRegex(ValueError,'Unknown prior'):
                    self.host.prior_report(root,record)
                load.assert_not_called()

    def test_known_prior_release_live_cleanup_is_read_only(self):
        with self.retired() as (root,record,version,suite):
            before={str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            with patch.object(self.host.S,'write_json') as write:
                result=self.host.prior_report(root,record)
            write.assert_not_called()
            self.assertTrue(result['terminal']);self.assertTrue(result['cleanup_complete'])
            self.assertEqual(before,{str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()})
            # Public operations still refuse the same historical release.
            with self.assertRaisesRegex(ValueError,'ownership'):self.host.owner(root.name,record['uid'])

    def test_prior_malformed_identity_profile_and_receipts_refuse_before_recipe_load(self):
        mutations=[lambda r:r.update(version='/etc'),lambda r:r.update(version=r['version']+'/../other'),
            lambda r:r.update(uid=True),lambda r:r.update(run_id='fedcba9876'),
            lambda r:r.update(candidate={}),lambda r:r.update(recipe=[]),
            lambda r:r['recipe'].update(build_id='0'*64),lambda r:r['recipe'].update(workers={'bad':'0'*64}),
            lambda r:r.update(setup_failed_clean=True)]
        for mutate in mutations:
            with self.subTest(mutate=mutate),self.retired() as (root,record,version,suite):
                mutate(record)
                with patch.object(self.host,'suite_for') as load,self.assertRaises((ValueError,KeyError,TypeError)):
                    self.host.prior_report(root,record)
                load.assert_not_called()
        for field,value in [('terminal',False),('cleanup_complete',False),('profile','other'),
                            ('build_id','0'*64),('candidate',{}),('exit_code',False),('accepted',False)]:
            with self.subTest(field=field),self.retired() as (root,record,version,suite):
                path=root/'result.json';receipt=json.loads(path.read_text());receipt[field]=value
                path.write_text(json.dumps(receipt))
                with patch.object(self.host,'suite_for') as load,self.assertRaises(ValueError):self.host.prior_report(root,record)
                load.assert_not_called()
        for name in ('manifest.json','profile.json','suite.py.in'):
            with self.subTest(file=name),self.retired() as (root,record,version,suite):
                path=version/name;path.write_text(path.read_text()+' ')
                with patch.object(self.host,'suite_for') as load,self.assertRaisesRegex(ValueError,'changed'):
                    self.host.prior_report(root,record)
                load.assert_not_called()

    def test_prior_active_lease_artifact_or_live_absence_uncertainty_blocks(self):
        for mode in ('active','lease','artifact','artifact-link','absence','root','launcher','unknown-lease'):
            with self.subTest(mode=mode),self.retired() as (root,record,version,suite):
                if mode=='active':suite.properties=lambda unit:{'stopped':False}
                if mode=='lease':(suite.ROOT/'leases.json').write_text('{"active":{"producer":{}}}')
                if mode=='artifact':suite.module('producer').STORE.touch()
                if mode=='artifact-link':suite.module('producer').STORE.symlink_to(root/'missing')
                if mode=='absence':self.host.unstarted_absent.return_value=False
                if mode=='root':suite.ROOT=root/'other'
                if mode=='launcher':suite.SCRIPT.write_text('changed')
                if mode=='unknown-lease':(suite.ROOT/'leases.json').write_text('{"active":[]}')
                with patch.object(self.host.S,'write_json') as write:
                    if mode in ('root','launcher','unknown-lease'):
                        with self.assertRaises(ValueError):self.host.prior_report(root,record)
                    else:
                        result=self.host.prior_report(root,record)
                        self.assertFalse(result['terminal'] and result['cleanup_complete'])
                write.assert_not_called()

    def test_prior_path_ownership_or_symlinks_refuse_before_recipe_load(self):
        with self.retired() as (root,record,version,suite):
            for path in (root,version,version/'profile.json',root/'result.json'):
                original=self.host.S.safe_path.side_effect
                def unsafe(candidate,**kw):
                    if candidate==path:raise ValueError('Unsafe installed path')
                    return original(candidate,**kw)
                with self.subTest(path=path),patch.object(self.host.S,'safe_path',side_effect=unsafe),\
                     patch.object(self.host,'suite_for') as load,self.assertRaisesRegex(ValueError,'Unsafe'):
                    self.host.prior_report(root,record)
                load.assert_not_called()

    def test_prior_prepared_recipe_hash_mismatch_cannot_load(self):
        record={'recipe':{'launcher_sha256':'0'*64,'workers':{}}}
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'prepared').mkdir();(root/'prepared/launcher.py').write_text('raise AssertionError("must not load")')
            real_host=common.load('seal_check_host',ROOT/'validation/host.py')
            with patch.object(real_host.S,'safe_path'),patch.object(real_host,'load') as load,\
                 self.assertRaisesRegex(ValueError,'Launcher changed'):real_host.suite_for(root,record)
            load.assert_not_called()

    def test_admission_queries_prior_read_only_and_keeps_retention_limit(self):
        with self.retired() as (root,record,version,suite):
            before={str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()}
            request=dict(run_id='fedcba9876',candidate=record['candidate'])
            disk=SimpleNamespace(f_bavail=0,f_frsize=4096)
            with patch.object(self.host.os,'statvfs',return_value=disk),patch.object(self.host,'copy_upload') as copy:
                with self.assertRaisesRegex(RuntimeError,'180 GiB'):self.host.start(request,1000)
            copy.assert_not_called()
            self.assertEqual(before,{str(p):p.read_bytes() for p in root.rglob('*') if p.is_file()})
            suite.properties=lambda unit:{'stopped':False}
            with patch.object(self.host.os,'statvfs') as disk:
                with self.assertRaisesRegex(RuntimeError,'Previous build active'):self.host.start(request,1000)
            disk.assert_not_called()
            for index in range(7):
                other=root.parent/('%010x'%index);other.mkdir();(other/'owner.json').write_text(json.dumps(record))
            with patch.object(self.host,'prior_report',return_value={'terminal':True,'cleanup_complete':True}) as prior,\
                 patch.object(self.host.os,'statvfs') as disk:
                with self.assertRaisesRegex(RuntimeError,'Eight-run'):self.host.start(request,1000)
            self.assertEqual(prior.call_count,8);disk.assert_not_called()

class Installer(unittest.TestCase):
    def test_tampered_support_cannot_execute_before_verification(self):
        installer=common.load('build_installer',ROOT/'validation/install.py')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);marker=root/'executed'
            support=root/'installer_support.py';support.write_text('original reviewed support')
            (root/'manifest.json').write_text(json.dumps({'files':{'installer_support.py':common.sha(support)}}))
            support.write_text('from pathlib import Path; Path('+repr(str(marker))+').touch()')
            with patch.object(installer,'HERE',root),patch.object(installer.os,'geteuid',return_value=0),\
                 patch.object(installer.sys,'argv',['install.py']),patch.object(installer.os,'umask'):
                with self.assertRaisesRegex(ValueError,'Package changed'):installer.install()
            self.assertFalse(marker.exists())

if __name__=='__main__':unittest.main()
