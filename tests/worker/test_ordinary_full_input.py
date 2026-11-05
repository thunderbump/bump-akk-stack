"""Exact new full input is independent of the explicit native ABC selection."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
import subprocess
import hashlib
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'validation/worker'))
import actor_integration as a
import guest
import integration_artifacts as wire
import integration_repin_release as release

class OrdinaryInput(unittest.TestCase):
    def identity(self):
        source=a.local_contract('actor-integration-fixture.json')['server_source']
        files={n:dict(bytes=1,sha256='f'*64) for n in ('eqemu.tar','websocketpp.tar','native.iso','rust-inputs.tar','runtime.iso')}
        files['native.iso']=dict(bytes=469000192,sha256='02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4')
        files['runtime.iso']={k:a.local_contract('runtime-fixture.json')['iso'][k] for k in ('bytes','sha256')}
        files['rust-inputs.tar']={k:a.dependency_contract()[k] for k in ('bytes','sha256')}
        return dict(version=1,candidate=source['commit'],tree=source['tree'],files=files,world_control=None,stack_commit='a'*40)

    def test_exact_ordinary_identity_and_reject_unknown_missing_or_changed_operands(self):
        value=self.identity();a.validate_input_identity(value)
        for field in ('candidate','tree','files','stack_commit'):
            bad=copy.deepcopy(value);bad.pop(field)
            with self.subTest(field=field),self.assertRaises(ValueError):a.validate_input_identity(bad)
        for field in ('candidate','tree'):
            bad=copy.deepcopy(value);bad[field]='0'*40
            with self.assertRaises(ValueError):a.validate_input_identity(bad)
        for field in ('rust-inputs.tar','native.iso','runtime.iso'):
            bad=copy.deepcopy(value);bad['files'][field]['sha256']='0'*64
            with self.assertRaises(ValueError):a.validate_input_identity(bad)
        bad=copy.deepcopy(value);bad['files']['integration-fixture.tar']=dict(bytes=1,sha256='0'*64)
        with self.assertRaises(ValueError):a.validate_input_identity(bad)
        with patch.object(a,'read_public',return_value=b'wrong lock'),self.assertRaises(ValueError):a.verify_dependencies(value,Path('/fixture'))

    def test_repin_changes_only_three_exact_source_fields(self):
        root=Path(__file__).resolve().parents[2]
        oldraw=subprocess.check_output(['git','-C',str(root),'show','ca85658ee3f95729da7cdeb760f0e2f80250dbaa:validation/actor-integration-fixture.json'])
        newraw=(root/'validation/actor-integration-fixture.json').read_bytes()
        before=json.loads(oldraw);after=json.loads(newraw)
        expected={'commit': '7d19508967b0f924ff02441a3065dbfd7ab846cc', 'tree': '1d89d42026354b879c4d9246b52f97ee4fe0a675', 'rust_tree': 'ec41c9b0ed5d95c546fe3faf971020fac6210f1b'}
        rewritten=oldraw
        for key,value in expected.items():
            self.assertEqual(after['server_source'][key],value)
            old=before['server_source'][key].encode();self.assertEqual(rewritten.count(old),1)
            rewritten=rewritten.replace(old,value.encode())
        self.assertEqual(newraw,rewritten)
        before['server_source'].update(expected);self.assertEqual(after,before)
        self.assertEqual(after['rust_input']['lock_sha256'],'1e5c00abf14873f23fea9bbbbccb9e5f250b058404dfa8046c6b5a87a7476f53')
        self.assertEqual(hashlib.sha256((root/'validation/worker/integration-v1.4.json').read_bytes()).hexdigest(),'c604e154baf96908e2d6707714875924a198793438ec219565f05dc4e6cf6eb0')

    def test_old_or_mixed_source_binding_rejected_by_host_and_both_guest_selections(self):
        ordinary=self.identity();a.validate_build_binding(ordinary);a.validate_input_identity(ordinary)
        integrated=copy.deepcopy(ordinary);integrated['integration']=wire.SELECTION
        integrated['files']['integration-fixture.tar']=dict(bytes=a.FIXTURE_BYTES,sha256=wire.FIXTURE_SHA)
        a.validate_input_identity(integrated)
        for commit,tree in [('928d82e3fca80a0be28049330c0f93226b4a3db4','6165225b56edb97173420c465aea93bb8fa610ad'),('928d82e3fca80a0be28049330c0f93226b4a3db4',ordinary['tree']),(ordinary['candidate'],'6165225b56edb97173420c465aea93bb8fa610ad'),('1734b9e66f64ed4b431010b8206b0396732ef506','843e92b5f3acc66f1e0a71bfc3fab0e4f6b6a0e9'),('1734b9e66f64ed4b431010b8206b0396732ef506',ordinary['tree']),(ordinary['candidate'],'843e92b5f3acc66f1e0a71bfc3fab0e4f6b6a0e9'),('0'*40,ordinary['tree'])]:
            for value in (ordinary,integrated):
                bad=copy.deepcopy(value);bad.update(candidate=commit,tree=tree)
                with self.assertRaises(ValueError):a.validate_build_binding(bad)
                with self.assertRaises(ValueError):a.validate_input_identity(bad)

    def test_ordinary_guest_stages_verifier_without_selecting_abc(self):
        config=json.loads(guest.build_user_data('a'*32).split('\n',1)[1])
        files={entry['path']:entry['content'] for entry in config['write_files']}
        self.assertNotIn('/opt/eqemu-worker-integration',files)
        self.assertEqual(json.loads(files['/opt/eqemu-worker-checks.json']),list(guest.BUILD_CHECKS))
        self.assertIn('/opt/actor_integration.py',files)
        self.assertIn('/opt/integration_artifacts.py',files)
        self.assertIn('/opt/actor-integration-fixture.json',files)
        self.assertEqual(guest.BUILD_CHECKS[-1],'normal-world')

    def test_successor_patch_matches_current_ca85658_only_and_does_not_promote_master(self):
        root=Path(__file__).resolve().parents[2]
        before={name:release.read(release.CODE/name) for name in release.PATCHED}
        result=release.patch_files(before,(root/'validation/worker/integration-ca85658.patch').read_bytes())
        self.assertEqual(set(result),set(release.PATCHED))
        self.assertEqual(set(result),{'validation/actor-integration-fixture.json'})
        self.assertEqual(result['validation/actor-integration-fixture.json'],(root/'validation/actor-integration-fixture.json').read_bytes())
        changed=dict(before);changed[release.PATCHED[0]]=b'changed bytes'
        with self.assertRaises(ValueError):release.patch_files(changed,(root/'validation/worker/integration-ca85658.patch').read_bytes())

if __name__=='__main__':unittest.main()
