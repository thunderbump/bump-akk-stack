"""Contract regressions with synthetic bytes and preserved observations, no VM/C++ execution."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parent
REPO = SOURCE.parents[2]
LOCAL = Path('/home/bump/.local/state/eqemu-vm-proof/build-handoff-inputs-01')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name,path)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


W = load('consumer_worker', LOCAL/'consumer-worker.py')
G = load('consumer_guest', LOCAL/'consumer-guest.py')
S = load('suite', LOCAL/'launcher.py')
PRIOR = json.loads((REPO/'investigations/corrected-build/2026-09-26/receipts/attempt-01/build/evidence/report.json').read_text())
NONCE = '1'*32


def inventory():
    return {'version':1,'identity':G.BUILD_ID,'files':[
        {'path':name,'type':'file','bytes':1,'sha256':'a'*64} for name in sorted(G.NAMES)],
        'libraries':[{'path':'/usr/lib/x86_64-linux-gnu/libc.so.6','bytes':1,'sha256':'b'*64}],
        'build':{},'preflight':{'after_status':'c'*64}}


class Payload(unittest.TestCase):
    def test_manifest_tamper_and_wrong_build_rejected(self):
        value=inventory();data=G.manifest_bytes(value);sha=G.hashlib.sha256(data).hexdigest()
        self.assertEqual(len(G.parse_manifest(data,G.BUILD_ID,sha)['files']),4)
        for changed,identity,digest in [(data+b' ',G.BUILD_ID,sha),(data,'wrong',sha),(data,G.BUILD_ID,'0'*64)]:
            with self.assertRaises(ValueError):G.parse_manifest(changed,identity,digest)

    def test_only_measured_flat_binaries_and_system_libraries(self):
        for mutation in ['nested','missing','duplicate','system-escape','system-duplicate','oversize']:
            value=inventory()
            if mutation=='nested':value['files'][0]['path']='build/world'
            if mutation=='missing':value['files'].pop()
            if mutation=='duplicate':value['files'].append(value['files'][0])
            if mutation=='system-escape':value['libraries'][0]['path']='/usr/lib/x86_64-linux-gnu/../../etc/passwd'
            if mutation=='system-duplicate':value['libraries']*=2
            if mutation=='oversize':value['files'][0]['bytes']=4*1024**3
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):G.validate_payload(value,G.BUILD_ID)

    def test_corrupted_binary_copy_is_removed(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);source=root/'world';target=root/'copied';source.write_bytes(b'changed')
            with self.assertRaises(ValueError):G.copy_blob(source,target,7,'0'*64,G.time.monotonic()+2)
            self.assertFalse(target.exists());self.assertEqual(source.read_bytes(),b'changed')


class ConsumerProtocol(unittest.TestCase):
    def setup_protocol(self, utility=True):
        protocol=W.BuildProtocol(NONCE)
        protocol.accept({'kind':'ready','nonce':None,'manifest_sha256':W.MANIFEST_SHA,'experiment_sha256':W.EXPERIMENT_SHA})
        if utility:protocol.accept({'kind':'observation','nonce':NONCE,'name':'utility','value':PRIOR['observations_untrusted']['utility']})
        return protocol

    def result(self):
        return {'kind':'result','nonce':NONCE,'ok':True,'consumer':{
            'identity':W.BUILD_ID,'manifest_sha256':'a'*64,'readonly':True,'unmounted':True,'compiled':False,
            'binaries':{name:PRIOR['guest_report_untrusted']['binaries'][name] for name in G.NAMES},
            'libraries':{item['path']:item['sha256'] for name,item in PRIOR['observations_untrusted'].items()
                         if name.startswith('elf-') and not item['build_file']},
            'after_status':PRIOR['preflight_untrusted']['after_status'],
            'utility':PRIOR['observations_untrusted']['utility']}}

    def accept(self,protocol,result):
        with patch.object(W,'producer_result',return_value=PRIOR),patch.object(W,'custody',return_value={'manifest_sha256':'a'*64}):
            return protocol.accept(result)

    def test_matching_fresh_consumer_passes(self):
        protocol=self.setup_protocol();self.accept(protocol,self.result());self.assertTrue(protocol.result['ok'])

    def test_changed_output_environment_or_unmount_rejected(self):
        for field,value in [('manifest_sha256','b'*64),('after_status','wrong'),('binaries',{}),('libraries',{}),
                            ('compiled',True),('readonly',False),('unmounted',False)]:
            result=self.result();result['consumer'][field]=value
            with self.subTest(field=field),self.assertRaises(RuntimeError):self.accept(self.setup_protocol(),result)

    def test_missing_utility_and_duplicate_success_rejected(self):
        with self.assertRaises(RuntimeError):self.accept(self.setup_protocol(False),self.result())
        protocol=self.setup_protocol();self.accept(protocol,self.result())
        with self.assertRaises(RuntimeError):self.accept(protocol,self.result())


class Retention(unittest.TestCase):
    def exercise(self,passed=True,budget_error=False,service='success',rescued=False):
        with tempfile.TemporaryDirectory() as folder:
            store=Path(folder)/'retained';store.mkdir();path=store/'artifact.raw';path.write_bytes(b'synthetic')
            records=[];record={'eligible':True,'producer_uuid':'owned','bytes':4*1024**3,'sha256':'a'*64,'manifest_sha256':'b'*64}
            custody=Path(folder)/'custody.json';custody.write_text(json.dumps(record))
            module=types.SimpleNamespace(STORE=store,CUSTODY=custody,custody=lambda:dict(record),
                state=lambda:{'uuid':'owned'},write_custody=lambda value:records.append(value))
            receipt={'rescued':['producer'] if rescued else []}
            if budget_error:receipt['controller_budget_error']='controller OOM'
            def read(p):return record if p==custody else {'cases_passed':passed}
            with patch.object(S,'module',return_value=module),patch.object(S,'retained_file',return_value=path),\
                 patch.object(S,'read',side_effect=read),patch.object(S,'ownership_released',return_value={'uuid':'owned'}),\
                 patch.dict(os.environ,{'SERVICE_RESULT':service}):
                S.retain_or_discard(receipt)
            return path.exists(),receipt,records

    def test_success_keeps_one_artifact_with_expiry(self):
        exists,receipt,records=self.exercise()
        self.assertTrue(exists);self.assertTrue(records[0]['consumer_verified'])
        self.assertAlmostEqual(records[0]['expires_at']-records[0]['retained_at'],7*86400,delta=1)
        self.assertIn('artifact_retained',receipt)

    def test_failed_cancelled_rescued_or_budget_failed_never_retained(self):
        for args in [{'passed':False},{'budget_error':True},{'service':'signal'},{'rescued':True}]:
            with self.subTest(args=args):
                exists,receipt,records=self.exercise(**args)
                self.assertFalse(exists);self.assertFalse(records[0]['eligible']);self.assertTrue(receipt['retained_artifact_absent'])

    def test_missing_success_artifact_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            module=types.SimpleNamespace(STORE=Path(folder)/'missing')
            with patch.object(S,'module',return_value=module),patch.object(S,'read',return_value={'cases_passed':True}),\
                 patch.dict(os.environ,{'SERVICE_RESULT':'success'}):
                with self.assertRaisesRegex(RuntimeError,'lost its retained'):S.retain_or_discard({'rescued':[]})

    def test_dangling_store_is_not_clean_absence(self):
        with tempfile.TemporaryDirectory() as folder:
            store=Path(folder)/'retained';store.symlink_to(Path(folder)/'missing')
            module=types.SimpleNamespace(STORE=store)
            with patch.object(S,'module',return_value=module),patch.object(S,'read',return_value={'cases_passed':False}),\
                 patch.object(S,'retained_file',side_effect=RuntimeError('unsafe store')):
                with self.assertRaisesRegex(RuntimeError,'unsafe store'):S.retain_or_discard({'rescued':[]})

    def test_expired_custody_refuses_consumer(self):
        record={'eligible':True,'bytes':4*1024**3,'sha256':'a'*64,'manifest_sha256':'b'*64,
                'identity':W.BUILD_ID,'expires_at':0}
        fake=types.SimpleNamespace(lstat=lambda:types.SimpleNamespace(st_mode=0o100600,st_uid=0,st_size=1000),
                                   read_text=lambda:json.dumps(record))
        with patch.object(W,'CUSTODY',fake),patch.object(W,'safe_dir'),patch.object(W,'expected_manifest',return_value='b'*64):
            with self.assertRaisesRegex(RuntimeError,'expired'):W.custody()

    def test_discard_removes_only_verified_owned_file(self):
        for tampered in [False,True]:
            with self.subTest(tampered=tampered),tempfile.TemporaryDirectory() as folder:
                root=Path(folder);store=root/'retained';store.mkdir();path=store/'artifact.raw';path.write_bytes(b'owned')
                unrelated=root/'keep';unrelated.write_bytes(b'other')
                record={'producer_uuid':'owned','sha256':'a'*64};records=[]
                module=types.SimpleNamespace(STORE=store,CUSTODY=root/'custody.json',safe_dir=lambda p:None,
                    UNIT='worker',state=lambda:{'uuid':'owned'},hash_file=lambda *args:'b'*64 if tampered else 'a'*64,
                    write_custody=lambda value:records.append(value))
                with patch.object(S,'ROOT',root),patch.object(S,'module',return_value=module),\
                     patch.object(S,'properties',return_value={}),patch.object(S,'quiescent',return_value=True),\
                     patch.object(S,'absent',return_value=True),patch.object(S,'ownership_released',return_value={'uuid':'owned'}),\
                     patch.object(S,'read',return_value=record),patch.object(S,'retained_file',return_value=path):
                    if tampered:
                        with self.assertRaisesRegex(RuntimeError,'bytes differ'):S.discard_artifact()
                        self.assertTrue(path.exists());self.assertEqual(records,[])
                    else:
                        self.assertEqual(S.discard_artifact(),0);self.assertFalse(store.exists())
                        self.assertTrue(records[0]['discarded']);self.assertFalse(records[0]['eligible'])
                self.assertEqual(unrelated.read_bytes(),b'other')

    def test_discard_refuses_live_worker(self):
        worker=types.SimpleNamespace(safe_dir=lambda p:None,UNIT='worker')
        with patch.object(S,'module',return_value=worker),patch.object(S,'properties',return_value={}),\
             patch.object(S,'quiescent',return_value=False):
            with self.assertRaisesRegex(RuntimeError,'live resources'):S.discard_artifact()


if __name__=='__main__':unittest.main()
