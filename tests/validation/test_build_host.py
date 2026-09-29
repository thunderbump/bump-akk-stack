"""Privilege-boundary admission controls without installing or starting a VM."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
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
        shutil.copyfile(ROOT/'investigations/restricted-runner/2026-09-27/control.py',directory/'host_support.py')
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
