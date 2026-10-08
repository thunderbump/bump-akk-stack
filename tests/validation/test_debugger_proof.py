"""Controller-name regression for libvirt's observed 20-character directory limit."""
import fnmatch
import importlib.util
from pathlib import Path
import unittest

path=Path(__file__).resolve().parents[2]/'validation/debugger/prepare_proof.py'
spec=importlib.util.spec_from_file_location('prepare_debugger_proof',path)
proof=importlib.util.module_from_spec(spec);spec.loader.exec_module(proof)


class ControllerNames(unittest.TestCase):
    def test_rendered_name_matches_real_libvirt_directory_and_keeps_failed_attempt(self):
        # The policy seam below is verbatim from the pinned isolation controller.
        template='''NAME='eqemu-first-trial'
ROOT='/var/lib/eqemu-vm-proof/first-trial'
UNIT='eqemu-vm-first-trial.service'
SLICE='eqemuvmtrial.slice'
def policy():
    return f'/var/lib/libvirt/qemu/domain-[0-9]*-{NAME}/** rwk,'
'''
        old_name='eqemu-debugger-proof-20261008'
        observed='/var/lib/libvirt/qemu/domain-1-eqemu-debugger-proof/master-key.aes'
        self.assertFalse(fnmatch.fnmatchcase(observed,
                         '/var/lib/libvirt/qemu/domain-[0-9]*-'+old_name+'/**'))
        values={};exec(proof.name_controller(template),values)
        self.assertLessEqual(len(values['NAME']),20)
        actual='/var/lib/libvirt/qemu/domain-1-'+values['NAME'][:20]+'/master-key.aes'
        pattern=values['policy']().split()[0]
        self.assertTrue(fnmatch.fnmatchcase(actual,pattern))
        self.assertFalse(fnmatch.fnmatchcase('/var/lib/libvirt/qemu/domain-1-unrelated/master-key.aes',pattern))
        self.assertNotEqual(values['ROOT'],'/var/lib/eqemu-vm-proof/debugger-proof-20261008')
        self.assertEqual(values['ROOT'],'/var/lib/eqemu-vm-proof/debugger-proof-20261008b')
        self.assertEqual(values['UNIT'],'eqemu-vm-debugger-proof-20261008b.service')
        self.assertEqual(values['SLICE'],'eqemuvmdebugger20261008b.slice')
