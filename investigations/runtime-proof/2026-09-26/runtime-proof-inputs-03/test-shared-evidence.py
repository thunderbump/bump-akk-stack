"""Synthetic filesystem regression for the guest's real shared-memory validator."""
import importlib.util,pathlib,tempfile,unittest
D=pathlib.Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('runtime',D/'guest-runtime.py');G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)

class SharedEvidence(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='eqemu-shared-check-');self.root=pathlib.Path(self.tmp.name)
  for name,data in [('items',b'item payload'),('spells',b'spell payload'),('items.lock',b''),('spells.lock',b'')]: (self.root/name).write_bytes(data)
 def tearDown(self):self.tmp.cleanup()
 def test_payloads_with_empty_locks_pass_and_only_payloads_are_reported(self):
  evidence=G.shared_evidence(self.root);self.assertEqual(set(evidence),{'items','spells'})
  for name in evidence:
   self.assertGreater(evidence[name]['bytes'],0);self.assertEqual(evidence[name]['sha256'],G.B.sha(self.root/name))
 def test_missing_or_empty_payload_fails_even_with_locks(self):
  for name in ['items','spells']:
   p=self.root/name;original=p.read_bytes()
   for missing in [False,True]:
    with self.subTest(name=name,missing=missing):
     p.unlink() if missing else p.write_bytes(b'')
     with self.assertRaises(RuntimeError):G.shared_evidence(self.root)
     p.write_bytes(original)
 def test_symlink_payload_is_rejected(self):
  for lock in self.root.glob('*.lock'):lock.unlink()
  (self.root/'items').unlink();(self.root/'items').symlink_to('spells')
  with self.assertRaises(RuntimeError):G.shared_evidence(self.root)
 def test_unexpected_file_is_rejected(self):
  for lock in self.root.glob('*.lock'):lock.unlink()
  (self.root/'unknown').write_bytes(b'x')
  with self.assertRaises(RuntimeError):G.shared_evidence(self.root)
 def test_failure_includes_required_file_sizes(self):
  (self.root/'spells').write_bytes(b'')
  with self.assertRaisesRegex(RuntimeError,'spells.*0'):G.shared_evidence(self.root)

if __name__=='__main__':unittest.main(verbosity=2)
