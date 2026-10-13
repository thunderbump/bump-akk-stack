"""Forward upgrade and root custody boundaries in real scratch files; no services or VM calls."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
INACTIVE_SLICE={'LoadState':'loaded','ActiveState':'inactive','SubState':'dead','FragmentPath':'','DropInPaths':'','Transient':'no'}
spec=importlib.util.spec_from_file_location('upgrade_direct',ROOT/'validation/upgrade/direct.py')
direct=importlib.util.module_from_spec(spec);spec.loader.exec_module(direct)
slice_parser=direct.slice_properties
prep_spec=importlib.util.spec_from_file_location('upgrade_preparation',ROOT/'validation/upgrade/prepare.py')
# The maintenance preparer imports its trusted sibling, not package code.
sys_path=__import__('sys').path
sys_path.insert(0,str(ROOT/'validation/upgrade'))
prepare=importlib.util.module_from_spec(prep_spec);prep_spec.loader.exec_module(prepare)


def seal(directory,files):
    directory.mkdir();directory.chmod(0o755)
    for name,data in files.items():
        (directory/name).write_bytes(data);(directory/name).chmod(0o644)
    manifest=direct.canonical({'version':1,'files':{name:direct.sha(data) for name,data in files.items()}})
    (directory/'manifest.json').write_bytes(manifest);(directory/'manifest.json').chmod(0o644)
    return direct.sha(manifest)


class DirectUpgrade(unittest.TestCase):
    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory() as tmp,contextlib.ExitStack() as stack:
            root=Path(tmp);paths=direct.Paths(root,os.getuid())
            for path in (paths.base,paths.lib,paths.client.parent,paths.helper.parent,paths.policy.parent,
                         paths.base/'runs',paths.base/'inputs',paths.base/'uploads/1000',paths.cgroups,paths.units):
                path.mkdir(parents=True,exist_ok=True);path.chmod(0o700 if path.name=='1000' else 0o755)
            (paths.base/'uploads').chmod(0o755)
            data=b'unchanged input';(paths.base/'inputs/fixture.iso').write_bytes(data);(paths.base/'inputs/fixture.iso').chmod(0o644)
            oldfiles={}
            for name in direct.OLD_NAMES-{'host-inputs.json','client-config.json'}:
                source=ROOT/'validation'/name
                if not source.exists():source=ROOT/'validation/recipes'/name
                oldfiles[name]=source.read_bytes()
            oldfiles['host-inputs.json']=direct.canonical({'fixture.iso':{'source':'/unchanged','bytes':len(data),'sha256':direct.sha(data)}})
            oldfiles['client-config.json']=b'{"input_store":"/public","websocketpp":"/public/ws"}\n'
            draft=paths.lib/'draft';oldhash=seal(draft,oldfiles);old=paths.lib/oldhash[:16];draft.rename(old)
            stack.enter_context(patch.object(direct,'OLD',oldhash))
            files=dict(oldfiles)
            for name in direct.NAMES-direct.OLD_NAMES:files[name]=(ROOT/'validation'/name).read_bytes()
            files['producer-worker.py.in']+=b'\n# reviewed staging revision\n'
            package=root/'package';newhash=seal(package,files);new=paths.lib/newhash[:16]
            for path,data in direct.wrappers(paths,old).items():path.write_bytes(data);path.chmod(0o755)
            paths.state.write_bytes(direct.canonical({'enabled':True,'version':str(old),'manifest_sha256':oldhash}));paths.state.chmod(0o600)
            paths.policy.write_bytes(direct.RULE);paths.policy.chmod(0o440)
            (paths.base/'request.lock').touch(mode=0o600)
            run=paths.base/'runs/0123456789';run.mkdir();run.chmod(0o755);(run/'retained').write_text('immutable receipt');(run/'retained').chmod(0o644)
            stack.enter_context(patch.object(direct,'proof_gate'))
            stack.enter_context(patch.object(direct,'idle'))
            stack.enter_context(patch.object(direct,'live_runs',side_effect=lambda *args:[{'run_id':i,'unit':'owned-suite'} for i in args[2]]))
            stack.enter_context(patch.object(direct,'unit_properties',return_value={'ActiveState':'inactive','MainPID':'0','ControlPID':'0'}))
            stack.enter_context(patch.object(direct,'slice_properties',return_value=INACTIVE_SLICE))
            def health(version,digest):direct.package(version,digest,direct.NAMES,paths.uid)
            stack.enter_context(patch.object(direct,'health',side_effect=health))
            def identity(expected):
                self.assertEqual(expected,newhash)
                self.assertFalse(direct.decode(paths.state.read_bytes())['enabled'])
                for path,data in direct.wrappers(paths,new).items():self.assertEqual(path.read_bytes(),data)
            stack.enter_context(patch.object(direct,'user_identity',side_effect=identity))
            declaration={'version':1,'old_manifest':oldhash,'new_manifest':newhash,'proof_report':direct.PROOF_REPORT,
                         'proof_uuid':direct.PROOF_UUID,'package':str(package),'mode':'apply'}
            yield paths,declaration,old,new,package

    def test_success_switches_only_release_wrappers_and_selection(self):
        with self.fixture() as (paths,decl,old,new,_):
            before=direct.preserved(paths,direct.run_ids(paths));oldbytes={p.name:p.read_bytes() for p in old.iterdir()}
            result=direct.apply(decl,paths)
            self.assertTrue(result['upgraded']);self.assertFalse(result['jobs_started']);self.assertFalse(result['rollback'])
            self.assertEqual(direct.preserved(paths,direct.run_ids(paths)),before)
            self.assertEqual({p.name:p.read_bytes() for p in old.iterdir()},oldbytes)
            self.assertEqual(direct.decode(paths.state.read_bytes()),{'enabled':True,'version':str(new),'manifest_sha256':decl['new_manifest']})
            direct.apply(decl,paths)
            self.assertTrue(direct.decode(paths.state.read_bytes())['enabled'])

    def test_each_owned_partial_failure_stays_disabled_and_can_finish_forward(self):
        for point in ('disabled','stage-file','release','eqemu-build-request','eqemu-validate','identity','commit-ready'):
            with self.subTest(point=point),self.fixture() as (paths,decl,old,new,_):
                def failure(name):
                    if name==point:raise RuntimeError('controlled fault '+point)
                with self.assertRaisesRegex(RuntimeError,'controlled fault'):direct.apply(decl,paths,failure)
                self.assertFalse(direct.decode(paths.state.read_bytes())['enabled'])
                self.assertTrue(old.exists())
                audit=paths.base/('direct-upgrade-'+decl['new_manifest'][:16])/'audit.json'
                self.assertEqual(direct.decode(audit.read_bytes())['phase'],'failed')
                direct.apply(decl,paths)
                self.assertEqual(direct.decode(paths.state.read_bytes())['version'],str(new))
                self.assertTrue(direct.decode(paths.state.read_bytes())['enabled'])

    def test_restrictive_umask_and_owned_forward_retry_publish_readable_release(self):
        for point in ('stage-file','release'):
            with self.subTest(point=point),self.fixture() as (paths,decl,_,new,_):
                previous=os.umask(0o077)
                try:
                    def failure(name):
                        if name==point:raise RuntimeError('controlled fault')
                    with self.assertRaises(RuntimeError):direct.apply(decl,paths,failure)
                    owned=new if new.exists() else paths.lib/('.direct-upgrade-'+decl['new_manifest'][:16])
                    self.assertEqual(owned.stat().st_mode&0o777,0o755)
                    # Recover a known-owned partial attempt made by the old umask-sensitive code.
                    owned.chmod(0o700)
                    def readable_health(version,digest):
                        self.assertEqual(version.stat().st_mode&0o777,0o755)
                        self.assertTrue(all(path.stat().st_mode&0o444==0o444 for path in version.iterdir()))
                        direct.package(version,digest,direct.NAMES,paths.uid)
                    with patch.object(direct,'health',side_effect=readable_health):direct.apply(decl,paths)
                    self.assertEqual(new.stat().st_mode&0o777,0o755)
                    self.assertTrue(direct.decode(paths.state.read_bytes())['enabled'])
                finally:os.umask(previous)

    def test_tamper_or_active_run_refuses_before_disabling_and_import(self):
        for kind in ('package','extra','symlink','active','media','policy'):
            with self.subTest(kind=kind),self.fixture() as (paths,decl,_,new,package):
                if kind=='package':(package/'host.py').write_text('raise RuntimeError("executed unverified")')
                if kind=='extra':(package/'json.py').write_text('unreviewed stdlib shadow')
                if kind=='symlink':(package/'host.py').unlink();(package/'host.py').symlink_to(package/'common.py')
                if kind=='media':(paths.base/'inputs/fixture.iso').write_bytes(b'changed')
                if kind=='policy':paths.policy.chmod(0o600);paths.policy.write_bytes(b'changed')
                active=patch.object(direct,'live_runs',side_effect=ValueError('active worker')) if kind=='active' else contextlib.nullcontext()
                with active,patch.object(direct,'health') as imported,self.assertRaises((ValueError,OSError)):
                    direct.apply(decl,paths)
                imported.assert_not_called();self.assertTrue(direct.decode(paths.state.read_bytes())['enabled']);self.assertFalse(new.exists())

    def test_identity_failure_and_receipt_drift_never_reopen(self):
        with self.fixture() as (paths,decl,_,_,_):
            with patch.object(direct,'user_identity',side_effect=ValueError('identity mismatch')),self.assertRaises(ValueError):
                direct.apply(decl,paths)
            self.assertFalse(direct.decode(paths.state.read_bytes())['enabled'])
            (paths.base/'runs/0123456789/retained').write_text('receipt drift')
            with self.assertRaisesRegex(ValueError,'Forward retry'):direct.apply(decl,paths)
            self.assertFalse(direct.decode(paths.state.read_bytes())['enabled'])

    def test_check_is_read_only_and_bounded_inventory_refuses_unknown_ids(self):
        with self.fixture() as (paths,decl,_,_,_):
            before=direct.snapshot(paths.base,paths.uid)
            result=direct.apply({**decl,'mode':'check'},paths)
            self.assertTrue(result['checked']);self.assertEqual(direct.snapshot(paths.base,paths.uid),before)
            (paths.base/'runs/not-a-run').mkdir()
            with self.assertRaisesRegex(ValueError,'inventory bound'):direct.apply(decl,paths)

    def test_preparer_freezes_exact_modes_and_rejects_package_before_any_import(self):
        with self.fixture() as (paths,decl,_,_,package):
            output=paths.root/'operators'
            receipt=prepare.prepare(package,output)
            self.assertFalse(receipt['installed']);self.assertFalse(receipt['rollback'])
            self.assertEqual(receipt['new_manifest'],decl['new_manifest'])
            for mode in ('check','apply'):
                operator=(output/(mode+'.py')).read_text()
                self.assertIn("'mode': '"+mode+"'",operator)
                wrapper=(output/('reviewed-'+mode+'.sh')).read_text()
                self.assertIn('/usr/bin/sudo /usr/bin/python3 -I -c',wrapper)
                self.assertIn(receipt['operators'][mode]['program_sha256'],wrapper)
            (package/'unexpected.py').write_text('raise RuntimeError("executed")')
            with self.assertRaisesRegex(ValueError,'inventory|Unexpected'):prepare.prepare(package,paths.root/'refused')
            self.assertFalse((paths.root/'refused').exists())

    def test_new_sealed_reader_compatibility_refuses_before_pointer_switch(self):
        with self.fixture() as (paths,decl,_,new,_):
            oldclient=paths.client.read_bytes();oldhelper=paths.helper.read_bytes()
            original=direct.live_runs
            def incompatible(paths,version,ids):
                if version==new:raise ValueError('new prior reader incompatible')
                return original(paths,version,ids)
            with patch.object(direct,'live_runs',side_effect=incompatible),self.assertRaisesRegex(ValueError,'new prior reader'):
                direct.apply(decl,paths)
            self.assertFalse(direct.decode(paths.state.read_bytes())['enabled'])
            self.assertEqual(paths.client.read_bytes(),oldclient);self.assertEqual(paths.helper.read_bytes(),oldhelper)


class ControllerGroups(unittest.TestCase):
    def setUp(self):
        probe=patch.object(direct,'slice_properties',return_value=INACTIVE_SLICE)
        probe.start();self.addCleanup(probe.stop)

    def test_actual_isolated_health_import_creates_no_bytecode_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            version=Path(tmp);expected='a'*64
            (version/'host.py').write_text('class S:\n    @staticmethod\n    def verify_installation():\n        return True\n')
            (version/'candidate.py').write_text('def installed_identity():\n    return '+repr({'schema_version':1,'identity':'sha256:'+expected})+'\n')
            before={p.name:p.read_bytes() for p in version.iterdir()}
            direct.health(version,expected)
            self.assertEqual({p.name:p.read_bytes() for p in version.iterdir()},before)
            self.assertFalse((version/'__pycache__').exists())

    def test_unknown_load_or_substate_never_qualifies_quiescence(self):
        good='LoadState=loaded\nActiveState=inactive\nSubState=dead\nMainPID=0\nControlPID=0\n'
        with patch.object(direct,'command',return_value=good):direct.unit_properties('owned')
        for value in (good.replace('loaded','error'),good.replace('SubState=dead','SubState=running')):
            with patch.object(direct,'command',return_value=value),self.assertRaises(ValueError):direct.unit_properties('owned')

    def test_slice_definition_and_state_are_closed_and_rechecked(self):
        # Exercise the real parser separately from the fixture's service-free probe.
        good=''.join(key+'='+value+'\n' for key,value in INACTIVE_SLICE.items())
        with patch.object(direct,'command',return_value=good):self.assertEqual(slice_parser('owned'),INACTIVE_SLICE)
        for value in (good.replace('Transient=no','Transient=yes'),good.replace('FragmentPath=','FragmentPath=/foreign'),
                      good.replace('SubState=dead','SubState=running'),good.replace('LoadState=loaded','LoadState=error')):
            with patch.object(direct,'command',return_value=value),self.assertRaises(ValueError):slice_parser('owned')
        with tempfile.TemporaryDirectory() as tmp:
            paths=direct.Paths(Path(tmp),os.getuid());paths.cgroups.mkdir(parents=True);paths.units.mkdir(parents=True)
            active={**INACTIVE_SLICE,'ActiveState':'active','SubState':'active'}
            with patch.object(direct,'slice_properties',return_value=active),self.assertRaisesRegex(ValueError,'Absent'):
                direct.controller_group(paths,'0123456789',lambda:{'inactive':True})
            directory=paths.cgroups/'eqemuvmb0123456789ctl.slice';directory.mkdir(mode=0o755)
            (directory/'cgroup.events').write_text('populated 0\nfrozen 0\n');(directory/'cgroup.procs').write_text('')
            with patch.object(direct,'slice_properties',side_effect=[INACTIVE_SLICE,active]),self.assertRaisesRegex(ValueError,'identity changed'):
                direct.controller_group(paths,'0123456789',lambda:{'inactive':True})
            with patch.object(direct,'slice_properties',return_value=active):
                self.assertEqual(direct.controller_group(paths,'0123456789',lambda:{'inactive':True})['state'],'empty')

    def test_named_group_replacement_or_state_change_during_final_query_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths=direct.Paths(Path(tmp),os.getuid());paths.cgroups.mkdir(parents=True);paths.units.mkdir(parents=True)
            directory=paths.cgroups/'eqemuvmb0123456789ctl.slice';directory.mkdir(mode=0o755)
            (directory/'cgroup.events').write_text('populated 0\nfrozen 0\n');(directory/'cgroup.procs').write_text('')
            calls=0
            def changed():
                nonlocal calls
                calls+=1
                if calls==2:(directory/'cgroup.procs').write_text('123\n')
                return {'inactive':True}
            with self.assertRaisesRegex(ValueError,'populated/frozen'):direct.controller_group(paths,'0123456789',changed)

    def test_empty_held_directory_is_debt_and_active_or_descendant_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths=direct.Paths(Path(tmp),os.getuid());paths.cgroups.mkdir(parents=True);paths.units.mkdir(parents=True)
            directory=paths.cgroups/'eqemuvmb0123456789ctl.slice';directory.mkdir();directory.chmod(0o755)
            (directory/'cgroup.events').write_text('populated 0\nfrozen 0\n');(directory/'cgroup.procs').write_text('')
            result=direct.controller_group(paths,'0123456789',lambda:{'inactive':True})
            self.assertEqual(result['state'],'empty');self.assertTrue(directory.exists())
            for change in ('populated','descendant','symlink'):
                with self.subTest(change=change):
                    if change=='populated':(directory/'cgroup.events').write_text('populated 1\nfrozen 0\n')
                    if change=='descendant':(directory/'child').mkdir()
                    if change=='symlink':(directory/'link').symlink_to(directory/'cgroup.events')
                    with self.assertRaises(ValueError):direct.controller_group(paths,'0123456789',lambda:{'inactive':True})
                    (directory/'cgroup.events').write_text('populated 0\nfrozen 0\n')
                    if (directory/'child').exists():(directory/'child').rmdir()
                    if (directory/'link').is_symlink():(directory/'link').unlink()


if __name__=='__main__':unittest.main()
