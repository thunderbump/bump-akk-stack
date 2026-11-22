"""Pure manifest checks only; the host adoption operator is never invoked."""
import importlib.util
import hashlib
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]/'validation/resilient_ops'
spec=importlib.util.spec_from_file_location('adopt',ROOT/'adopt.py')
adopt=importlib.util.module_from_spec(spec)
spec.loader.exec_module(adopt)


class AdoptionManifestTests(unittest.TestCase):
    def test_exact_external_contract_and_distinct_resource_fences(self):
        packet=adopt.contract()
        policy=adopt.policy_for(packet)
        code=policy['targets']['validator-worker-code']
        workspace=policy['targets']['validator-integration-evidence']
        self.assertEqual(len(code['files']),19)
        self.assertEqual(code['service_uid'],995)
        self.assertTrue(set(code['resources']).isdisjoint(workspace['resources']))
        self.assertEqual(workspace['actions'],['recover'])
        self.assertEqual(policy['peers'][0]['uid'],1000)
        self.assertEqual(packet['migration']['original_outcome']['original_transfer'],'uncertain')
        self.assertFalse(packet['migration']['original_outcome']['complete'])

    def test_copy_contract_rejects_changed_bytes_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'file').write_bytes(b'old failure')
            expected=[dict(path='file',bytes=11,sha256=hashlib.sha256(b'old failure').hexdigest())]
            self.assertEqual(adopt.verified_files(root,expected),{'file':b'old failure'})
            (root/'file').write_bytes(b'changed')
            with self.assertRaises(ValueError): adopt.verified_files(root,expected)
            (root/'file').unlink()
            (root/'file').symlink_to('/dev/null')
            with self.assertRaises((ValueError,OSError)): adopt.verified_files(root,expected)
