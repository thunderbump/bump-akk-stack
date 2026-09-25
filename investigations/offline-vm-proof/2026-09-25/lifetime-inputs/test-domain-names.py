"""Regression for libvirt 10.0 short runtime paths; kernel proof requires VM retry."""
import fnmatch,importlib.util,json,pathlib,unittest
P=pathlib.Path
base=P(__file__).parent

def load(case):
 p=base/(case+'-worker.py');spec=importlib.util.spec_from_file_location(case,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def allowed(m,path):
 # These own-runtime rules use only the simple glob subset shared by fnmatch/AppArmor.
 return any(fnmatch.fnmatchcase(path,line.strip().split()[0]) for line in m.policy({'profile':'libvirt-test'}).splitlines() if line.strip().startswith('/var/lib/libvirt/qemu/domain-'))

class DomainNames(unittest.TestCase):
 def test_captured_mismatch(self):
  m=load('timeout');m.NAME='eqemu-lifetime-timeout'
  self.assertFalse(allowed(m,'/var/lib/libvirt/qemu/domain-1-eqemu-lifetime-timeo/master-key.aes'))
 def test_all_own_short_paths_allowed_and_other_names_excluded(self):
  for case in ['timeout','cancel','death']:
   with self.subTest(case=case):
    m=load(case)
    self.assertLessEqual(len(m.NAME),20)
    self.assertTrue(m.NAME.isascii())
    self.assertTrue(allowed(m,'/var/lib/libvirt/qemu/domain-1-'+m.NAME[:20]+'/master-key.aes'))
    self.assertFalse(allowed(m,'/var/lib/libvirt/qemu/domain-1-unrelated/master-key.aes'))
 def test_overlength_name_refused_before_launch(self):
  from unittest.mock import patch
  m=load('timeout');m.NAME='x'*21
  with patch.object(m.os,'geteuid',return_value=0),patch.object(m,'run') as run:
   with self.assertRaisesRegex(RuntimeError,'20 ASCII'):m.setup()
   run.assert_not_called()
if __name__=='__main__':unittest.main()
