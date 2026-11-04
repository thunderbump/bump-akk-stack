"""Exact new full input is independent of the explicit native ABC selection."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'validation/worker'))
import actor_integration as a
import guest
import integration_artifacts as wire
import qualification_release as release

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

    def test_ordinary_guest_stages_verifier_without_selecting_abc(self):
        config=json.loads(guest.build_user_data('a'*32).split('\n',1)[1])
        files={entry['path']:entry['content'] for entry in config['write_files']}
        self.assertNotIn('/opt/eqemu-worker-integration',files)
        self.assertEqual(json.loads(files['/opt/eqemu-worker-checks.json']),list(guest.BUILD_CHECKS))
        self.assertIn('/opt/actor_integration.py',files)
        self.assertIn('/opt/integration_artifacts.py',files)
        self.assertIn('/opt/actor-integration-fixture.json',files)
        self.assertEqual(guest.BUILD_CHECKS[-1],'normal-world')

    def test_successor_patch_matches_actual_308_only_and_does_not_promote_master(self):
        root=Path(__file__).resolve().parents[2]
        before={name:release.read(release.CODE/name) for name in release.PATCHED}
        result=release.patch_files(before,(root/'validation/worker/integration-308.patch').read_bytes())
        self.assertEqual(set(result),set(release.PATCHED))
        self.assertNotIn(b'from profiling',result['validation/worker/build_guest.py'])
        changed=dict(before);changed[release.PATCHED[0]]=b'changed bytes'
        with self.assertRaises(ValueError):release.patch_files(changed,(root/'validation/worker/integration-308.patch').read_bytes())

if __name__=='__main__':unittest.main()
