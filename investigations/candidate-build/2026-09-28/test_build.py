"""Synthetic source and artifact controls plus generated-policy checks. No VM/build."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

SOURCE = Path(__file__).resolve().parent
REPO = SOURCE.parents[2]
LOCAL = Path('/home/bump/.local/state/eqemu-vm-proof/candidate-build-inputs-01')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load('prepare_candidate_build', SOURCE/'prepare.py')
G = load('candidate_producer', LOCAL/'producer-guest.py')
C = load('candidate_consumer', LOCAL/'consumer-guest.py')
W = load('candidate_worker', LOCAL/'producer-worker.py')
CW = load('candidate_consumer_worker', LOCAL/'consumer-worker.py')
S = load('candidate_suite', LOCAL/'launcher.py')


class CompleteSource(unittest.TestCase):
    def test_materialized_files_modes_and_gitlink_boundaries(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root/'file'; path.write_bytes(b'synthetic'); path.chmod(0o644)
            module = root/'submodules/dependency'; module.mkdir(parents=True)
            (module/'separately-verified').write_text('dependency')
            source = {'gitlinks': {'submodules/dependency': 'a'*40}, 'entries': [
                {'path': 'file', 'bytes': 9, 'sha256': hashlib.sha256(b'synthetic').hexdigest(), 'mode': '100644'}]}
            G.verify_materialized(root, source)
            for change in ['bytes', 'mode', 'missing', 'extra', 'symlink', 'directory-symlink']:
                with self.subTest(change=change):
                    if change == 'bytes': path.write_bytes(b'wrong----')
                    if change == 'mode': path.chmod(0o755)
                    if change == 'missing': path.unlink()
                    if change == 'extra': (root/'extra').write_text('extra')
                    if change == 'symlink': path.unlink(); path.symlink_to(module/'separately-verified')
                    if change == 'directory-symlink': (root/'outside').symlink_to(module, target_is_directory=True)
                    with self.assertRaises(RuntimeError): G.verify_materialized(root, source)
                    for p in [path, root/'extra', root/'outside']:
                        if p.exists() or p.is_symlink(): p.unlink()
                    path.write_bytes(b'synthetic'); path.chmod(0o644)

    def test_guest_materialization_orders_verification_before_observation(self):
        # Exercise the real guest function with synthetic archives through its verifier seam.
        import tarfile
        import types
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); mount = root/'media'; config = root/'profile'
            config.write_text('{}')
            manifest = {'sources': {}}
            mount.mkdir()
            for name in ['eqemu', 'websocketpp']:
                payload = root/(name+'.txt'); payload.write_bytes(b'synthetic')
                with tarfile.open(mount/(name+'.tar'), 'w') as archive: archive.add(payload, arcname=name+'.txt')
                manifest['sources'][name] = {'archive': {'path': name+'.tar'}, 'gitlinks': {'submodules/websocketpp':'x'} if name=='eqemu' else {},
                    'entries': [{'path': name+'.txt', 'bytes':9, 'sha256':hashlib.sha256(b'synthetic').hexdigest(), 'mode':'100644'}]}
            real_path = Path
            def paths(value):
                return mount if value=='/opt/candidate-media' else config if value=='/opt/eqemu-proof/candidate-profile.json' else real_path(value)
            original_mkdir = Path.mkdir
            def mkdir(path, *args, **kwargs):
                if path == mount: return
                return original_mkdir(path, *args, **kwargs)
            observations=[]; commands=[]
            verifier=types.SimpleNamespace(verify=lambda *args: copy.deepcopy(manifest))
            spec=types.SimpleNamespace(loader=types.SimpleNamespace(exec_module=lambda module: None))
            with patch.object(G,'P',side_effect=paths), patch.object(Path,'mkdir',mkdir), \
                 patch.object(G.importlib.util,'spec_from_file_location',return_value=spec), \
                 patch.object(G.importlib.util,'module_from_spec',return_value=verifier), \
                 patch.object(G,'command',side_effect=lambda name,*a,**kw: commands.append(name)), \
                 patch.object(G,'emit',side_effect=observations.append):
                G.materialize_candidate(root/'source')
                self.assertEqual(commands, ['candidate-mount','candidate-unmount'])
                self.assertEqual(observations[0]['value'], G.CANDIDATE_FACTS)
                manifest['sources']['eqemu']['entries'][0]['sha256']='0'*64
                observations.clear(); commands.clear()
                with self.assertRaises(RuntimeError): G.materialize_candidate(root/'bad-source')
                self.assertFalse(observations)
                self.assertEqual(commands[-1], 'candidate-unmount')


class Binding(unittest.TestCase):
    def test_publication_preserves_concurrently_created_destinations(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); stage=root/'stage'; stage.mkdir(); (stage/'input').write_text('new')
            output=root/'output'; output.mkdir(); launcher=root/'launcher'; launcher.write_text('operator')
            with self.assertRaises(FileExistsError): P.publish(stage,output,launcher,'new launcher')
            self.assertEqual(launcher.read_text(),'operator')
            self.assertEqual((stage/'input').read_text(),'new')
            output.rmdir()
            with self.assertRaises(FileExistsError): P.publish(stage,output,launcher,'new launcher')
            self.assertEqual(launcher.read_text(),'operator')
            self.assertEqual((output/'input').read_text(),'new')

    def test_identity_changes_with_source_dependency_recipe_or_options(self):
        receipt={'input_id':'a','manifest_sha256':'b'}; profile={'jobs':1,'base':'c'}; sources={'adapter':'d'}; template={'worker':'e'}
        original=P.build_identity(receipt,profile,sources,template)
        for group in range(4):
            values=copy.deepcopy([receipt,profile,sources,template])
            values[group][next(iter(values[group]))]='changed'
            self.assertNotEqual(P.build_identity(*values),original)

    def test_old_source_or_recipe_and_changed_artifact_are_refused(self):
        inventory={'version':1,'identity':C.BUILD_ID,'files':[
            {'path':name,'type':'file','bytes':1,'sha256':'a'*64} for name in sorted(C.NAMES)],
            'libraries':[{'path':'/usr/lib/x86_64-linux-gnu/libc.so.6','bytes':1,'sha256':'b'*64}],
            'build':{},'preflight':{'after_status':'c'*64}}
        data=C.manifest_bytes(inventory); seal=hashlib.sha256(data).hexdigest()
        C.parse_manifest(data,C.BUILD_ID,seal)
        for identity, payload, expected in [('old-build',data,seal),(C.BUILD_ID,data+b' ',seal),(C.BUILD_ID,data,'0'*64)]:
            with self.assertRaises(ValueError): C.parse_manifest(payload,identity,expected)
        protocol=W.BuildProtocol('1'*32)
        with self.assertRaises(RuntimeError):
            protocol.accept({'kind':'ready','nonce':None,'manifest_sha256':W.MANIFEST_SHA,'experiment_sha256':'0'*64})
        protocol.accept({'kind':'ready','nonce':None,'manifest_sha256':W.MANIFEST_SHA,'experiment_sha256':W.EXPERIMENT_SHA})
        with self.assertRaises(RuntimeError):
            protocol.accept({'kind':'observation','nonce':'1'*32,'name':'candidate','value':{'candidate':'old'}})

    def test_consumer_cannot_enter_source_build(self):
        self.assertEqual(C.ROLE,'consumer')
        with self.assertRaisesRegex(RuntimeError,'cannot compile'): C.original_build()

    def test_generated_transport_resources_and_distinct_ownership(self):
        self.assertNotEqual(W.UNIT, CW.UNIT)
        for worker in [W,CW]:
            self.assertIn('candidate-build-01',str(worker.ROOT))
            self.assertIn('eqemu-vm-cb-',worker.UNIT)
            tree=ET.fromstring(worker.domain({'uuid':'1'*32,'profile':'test'}))
            self.assertEqual(tree.find('memory').text,'4096')
            self.assertEqual(tree.find('memtune/hard_limit').text,'6144')
            self.assertEqual(tree.find('vcpu').text,'2')
            self.assertFalse(tree.findall('./devices/interface'))
            disks=tree.findall('./devices/disk')
            candidate=[d for d in disks if d.find('target').get('dev')=='sdc']
            self.assertEqual(len(disks),5 if worker is W else 4)
            self.assertEqual(len(candidate),1 if worker is W else 0)
            if candidate: self.assertIsNotNone(candidate[0].find('readonly'))
        code=(LOCAL/'launcher.py').read_text()
        self.assertIn('RuntimeMaxSec=18000',code)
        self.assertIn('TimeoutStopSec=300',code)
        self.assertIn('time.monotonic() + 17700',code)
        producer=(LOCAL/'producer-guest.py').read_text()
        self.assertNotIn('apply_candidate',producer)
        self.assertNotIn("f'{name}.tar.gz'",producer)
        self.assertNotIn('/candidate.json',producer)
        self.assertEqual(W.BUILD_ID,C.BUILD_ID)
        self.assertEqual(W.CANDIDATE,G.CANDIDATE_FACTS)


if __name__ == '__main__': unittest.main()
