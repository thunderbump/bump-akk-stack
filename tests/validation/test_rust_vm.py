"""No-launch VM proof rendering, fresh names, immutable media and controller-seam checks."""
import ast
import fnmatch
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation'))
import common

vm=common.load('rust_vm_preparation',ROOT/'validation/rust/prepare_vm_proof.py')
guest=common.load('rust_vm_guest_contract',ROOT/'validation/rust/vm_guest.py')
proof=common.load('rust_vm_syntax_fixture',ROOT/'validation/rust/proof.py')

TEMPLATE='''P=__import__('pathlib').Path
NAME='eqemu-first-trial'
INPUTS=P('/old/input-store')
FILES={}
ROOT=P('/var/lib/eqemu-vm-proof/first-trial')
UNIT='eqemu-vm-first-trial.service'
SLICE='eqemuvmtrial.slice'
def policy():
    return f"""{DATA}/fixture.iso rk, /var/lib/libvirt/qemu/domain-[0-9]*-{NAME}/** rwk,"""
def domain():
    return f"""
    <serial type="unix">
"""
def worker():
    try:
        for name in ['seed.iso','fixture.iso']: pass
        deadline=time.monotonic()+900
        required={'guest_root','no_virtual_nic','no_nested_virtualization','approved_input','no_host_mounts','no_host_control_socket','no_external_route','container_exchange','intentional_failure_distinct','containers_removed'}
        if guest.get('kind')!='offline-container-trial':raise RuntimeError('kind')
        report['checks']['guest_synthetic_workload']=True
    finally:
        pass
def setup():
    args=['RuntimeMaxSec=1800']
'''


class RustVmRendering(unittest.TestCase):
    def test_syntax_control_is_malformed_expression_and_requires_compile_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp);(source/'core/src').mkdir(parents=True)
            core=source/'core/src/lib.rs'
            core.write_text((ROOT/'validation/rust/fixture/core/src/lib.rs').read_text())
            proof.apply_control(source,'syntax')
            self.assertIn('    let broken = ;\n    value.saturating_add(1)',core.read_text())
        result={'observations':{'rust-failure':{'stage':'rust-fmt','finding':'format'}}}
        self.assertFalse(guest.control_finding('syntax',result))
        result['observations']['rust-failure']['finding']='compile'
        self.assertTrue(guest.control_finding('syntax',result))

    def test_controls_require_their_actual_failure_reason(self):
        self.assertFalse(guest.control_finding('config-drift',{'error':'unrelated infrastructure failure'}))
        self.assertTrue(guest.control_finding('config-drift',{'error':'Protected Rust tool/vendor/config input drift'}))
        result={'observations':{'rust-failure':{'stage':'rust-native-link','finding':'link','tool_exit_code':0}}}
        self.assertTrue(guest.control_finding('missing-marker',result))
        result['observations']['rust-failure']['tool_exit_code']=1
        self.assertFalse(guest.control_finding('missing-marker',result))

    def test_domain_name_policy_owned_paths_and_readonly_disk_stay_concentrated(self):
        rendered=vm.controller(TEMPLATE,{'fixed':('path',1,'a'*64)},Path('/retained'))
        ast.parse(rendered)
        assignments=[node for node in ast.parse(rendered).body if isinstance(node,ast.Assign)]
        values={node.targets[0].id:ast.literal_eval(node.value) for node in assignments
                if node.targets[0].id in ('NAME','UNIT','SLICE','FILES')}
        self.assertLessEqual(len(values['NAME']),20)
        self.assertEqual(values['NAME'],'eqemu-rust-1011')
        self.assertEqual(values['UNIT'],'eqemu-vm-rust-proof-20261011.service')
        self.assertEqual(values['SLICE'],'eqemuvmrust20261011.slice')
        observed='/var/lib/libvirt/qemu/domain-1-'+values['NAME']+'/master-key.aes'
        self.assertTrue(fnmatch.fnmatchcase(observed,'/var/lib/libvirt/qemu/domain-[0-9]*-'+values['NAME']+'/**'))
        self.assertIn('rust.iso rk,',rendered)
        self.assertIn('<target dev="sdc" bus="sata"/><readonly/>',rendered)
        self.assertIn("['seed.iso','fixture.iso','rust.iso']",rendered)
        self.assertIn('deadline=time.monotonic()+2400',rendered)
        self.assertIn('RuntimeMaxSec=3000',rendered)
        self.assertNotIn('offline-container-trial',rendered)

    def test_changed_template_seam_and_unpinned_source_refuse_without_launch(self):
        with self.assertRaisesRegex(ValueError,'seam changed'):
            vm.controller(TEMPLATE.replace('deadline=time.monotonic()+900','deadline=time.monotonic()+901'),{},Path('/retained'))
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);template=root/'changed.py';template.write_text(TEMPLATE)
            bundle=root/'bundle';bundle.write_bytes(b'data')
            with self.assertRaisesRegex(ValueError,'Pinned isolation controller changed'):
                vm.prepare(root,bundle,template,root/'never-created')
            self.assertFalse((root/'never-created').exists())


if __name__=='__main__':unittest.main()
