"""No-launch VM proof rendering, fresh names, immutable media and controller-seam checks."""
import ast
import fnmatch
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation'))
import common

vm=common.load('rust_vm_preparation',ROOT/'validation/rust/prepare_vm_proof.py')
guest=common.load('rust_vm_guest_contract',ROOT/'validation/rust/vm_guest.py')
proof=common.load('rust_vm_syntax_fixture',ROOT/'validation/rust/proof.py')

TEMPLATE='''import hashlib,os
P=__import__('pathlib').Path
NAME='eqemu-first-trial'
INPUTS=P('/old/input-store')
FILES={}
ROOT=P('/var/lib/eqemu-vm-proof/first-trial')
UNIT='eqemu-vm-first-trial.service'
SLICE='eqemuvmtrial.slice'
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def policy():
    return f"""{DATA}/fixture.iso rk, /var/lib/libvirt/qemu/domain-[0-9]*-{NAME}/** rwk,"""
def domain():
    return f"""
    <serial type="unix">
"""
def worker():
    try:
        for target,(rel,length,sha) in FILES.items():
            source=INPUTS/rel;dest=DATA/target
            if source.is_symlink() or not source.is_file() or source.stat().st_size!=length:raise RuntimeError('Invalid fixed input '+target)
            # Fixed size loop also prevents an expanding source from filling storage.
            with source.open('rb') as src,dest.open('xb') as dst:
                remain=length
                while remain:
                    chunk=src.read(min(remain,1024**2))
                    if not chunk:raise RuntimeError('Short input')
                    dst.write(chunk);remain-=len(chunk)
                if src.read(1):raise RuntimeError('Input grew')
            if digest(dest)!=sha:raise RuntimeError('Input digest mismatch '+target)
            report['inputs'][target]=sha;dest.chmod(0o444)
        for name in ['seed.iso','fixture.iso']: pass
        deadline=time.monotonic()+900
        required={'guest_root','no_virtual_nic','no_nested_virtualization','approved_input','no_host_mounts','no_host_control_socket','no_external_route','container_exchange','intentional_failure_distinct','containers_removed'}
        if guest.get('kind')!='offline-container-trial':raise RuntimeError('kind')
        report['checks']['guest_synthetic_workload']=True
    finally:
        pass
def setup():
    args=['RuntimeMaxSec=1800','MemoryMax=1G','MemorySwapMax=0','TasksMax=64']
'''


class ControllerInputWrites(unittest.TestCase):
    def namespace(self):
        rendered=vm.controller(TEMPLATE,{},Path('/retained'))
        namespace={};exec(compile(rendered,'rendered-copy-controller','exec'),namespace)
        return namespace,ast.parse(rendered)

    def test_actual_rendered_input_loop_bounds_dirty_bytes_and_evicts_clean_ranges(self):
        namespace,tree=self.namespace()
        worker=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='worker')
        loop=next(node for node in ast.walk(worker) if isinstance(node,ast.For) and isinstance(node.target,ast.Tuple))
        code=compile(ast.Module(body=[loop],type_ignores=[]),'rendered-input-loop','exec')
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source';source.mkdir();dest=root/'dest';dest.mkdir()
            data=b'x'*(12*1024**2);(source/'input').write_bytes(data)
            checksum=hashlib.sha256(data).hexdigest()
            namespace.update(INPUTS=source,DATA=dest,FILES={'copied':('input',len(data),checksum)},report={'inputs':{}})
            pending=0;peak=0;syncs=[];advice=[];original=Path.open
            class Writer:
                def __init__(self,stream):self.stream=stream
                def __enter__(self):return self
                def __exit__(self,*args):self.stream.close()
                def write(self,body):
                    nonlocal pending,peak
                    size=self.stream.write(body);pending+=size;peak=max(peak,pending);return size
                def flush(self):self.stream.flush()
                def fileno(self):return self.stream.fileno()
            def opened(path,mode='r',*args,**kwargs):
                stream=original(path,mode,*args,**kwargs)
                return Writer(stream) if mode=='xb' else stream
            def synced(fd):
                nonlocal pending
                syncs.append(pending);pending=0
            with patch.object(Path,'open',opened),patch.object(os,'fdatasync',side_effect=synced),\
                 patch.object(os,'posix_fadvise',side_effect=lambda *args:advice.append(args)):
                exec(code,namespace)
            self.assertLessEqual(peak,8*1024**2)
            self.assertEqual(syncs,[8*1024**2,4*1024**2])
            self.assertTrue(advice)
            self.assertTrue(all(item[2]<=8*1024**2 and item[3]==os.POSIX_FADV_DONTNEED for item in advice))
            self.assertEqual((dest/'copied').read_bytes(),data)
            self.assertEqual(namespace['report']['inputs'],{'copied':checksum})

    def test_digest_evicts_each_completed_read_window(self):
        namespace,_=self.namespace()
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'data';data=b'x'*(12*1024**2);source.write_bytes(data);advice=[]
            with patch.object(os,'posix_fadvise',side_effect=lambda *args:advice.append(args)):
                self.assertEqual(namespace['digest'](source),hashlib.sha256(data).hexdigest())
            self.assertEqual([(item[1],item[2]) for item in advice],[(0,8*1024**2),(8*1024**2,4*1024**2)])

    def test_short_or_growing_input_and_failed_sync_cannot_succeed(self):
        namespace,_=self.namespace()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source';source.write_bytes(b'1234')
            for length,message in ((5,'Short input'),(3,'Input grew')):
                with self.subTest(length=length),self.assertRaisesRegex(RuntimeError,message):
                    namespace['copy_input'](source,root/('dest-'+str(length)),length)
            with patch.object(os,'fdatasync',side_effect=OSError('failed durability')) as synced,\
                 patch.object(os,'posix_fadvise') as advised,self.assertRaisesRegex(OSError,'failed durability'):
                namespace['copy_input'](source,root/'failed-sync',4)
            synced.assert_called_once();advised.assert_not_called()

    def test_copy_and_digest_seams_are_count_checked_and_memory_guards_preserved(self):
        for seam in (vm.OLD_COPY,vm.OLD_DIGEST):
            with self.subTest(seam=seam[:32]),self.assertRaisesRegex(ValueError,'seam changed'):
                vm.controller(TEMPLATE.replace(seam,seam+'\n'+seam),{},Path('/retained'))
        rendered=vm.controller(TEMPLATE,{},Path('/retained'))
        for gate in ('MemoryMax=1G','MemorySwapMax=0','TasksMax=64'):
            self.assertIn(gate,rendered)
        self.assertNotIn('MemoryMax=2G',rendered)
        self.assertNotIn('rust-proof-20261011',rendered)
        self.assertNotIn('eqemu-rust-1011',rendered)


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
        self.assertEqual(values['NAME'],'eqemu-rust-1012b')
        self.assertEqual(values['UNIT'],'eqemu-vm-rust-proof-20261012b.service')
        self.assertEqual(values['SLICE'],'eqemuvmrust20261012b.slice')
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
