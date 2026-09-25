import copy,hashlib,importlib.util,io,json,os,pathlib,socket,tempfile,types,unittest,uuid
from unittest.mock import patch
P=pathlib.Path;D=P(__file__).parent;B=D.parent

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
suite=load(B/'recovery-tests.py','suite');worker=suite.module('left',local=True)

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.ident=str(uuid.uuid4());self.sha='a'*64
        self.state={'uuid':self.ident,'name':'eqemu-rc-left','profile':'libvirt-'+self.ident,'controller_sha256':self.sha}
        self.lease={'uuid':self.ident,'name':'eqemu-rc-left','state':'active','worker_sha256':self.sha}
    def validate(self,state=None,lease=None,actual=None):
        return suite.validate_identity(self.state if state is None else state,self.lease if lease is None else lease,'eqemu-rc-left',self.sha,self.sha if actual is None else actual)
    def test_valid_ownership(self):self.validate()
    def test_every_identity_field_refused(self):
        for target in ['state','lease']:
            base=self.state if target=='state' else self.lease
            for key in base:
                with self.subTest(target=target,key=key):
                    bad=dict(base);bad[key]='wrong'
                    with self.assertRaises(RuntimeError):self.validate(**{target:bad})
        with self.assertRaises(RuntimeError):self.validate(actual='b'*64)
        with self.assertRaises(RuntimeError):self.validate(state={})
    def test_third_rejected_despite_capacity(self):
        ledger={'phase':'pair','active':{'left':{},'right':{}}}
        with self.assertRaisesRegex(RuntimeError,'cap reached'):suite.admission_decision(ledger,'third',500*suite.GIB,100*suite.GIB,10000000)
    def test_single_cap_and_phase(self):
        for ledger,case in [({'phase':'single','active':{'io':{}}},'supervisor'),({'phase':'single','active':{}},'left'),({'phase':'pair','active':{}},'stale')]:
            with self.assertRaises(RuntimeError):suite.admission_decision(ledger,case,500*suite.GIB,100*suite.GIB,10000000)
    def test_fresh_capacity_floor(self):
        ledger={'phase':'pair','active':{}}
        suite.admission_decision(ledger,'left',220*suite.GIB,21*suite.GIB,1000000)
        for free,mem,inodes in [(220*suite.GIB-1,21*suite.GIB,1000000),(220*suite.GIB,21*suite.GIB-1,1000000),(220*suite.GIB,21*suite.GIB,999999)]:
            with self.assertRaisesRegex(RuntimeError,'capacity'):suite.admission_decision(ledger,'left',free,mem,inodes)
        self.assertEqual(suite.capacity_required(True,32*suite.GIB),(188*suite.GIB,21*suite.GIB))
        self.assertEqual(suite.capacity_required(True,999*suite.GIB),(180*suite.GIB,21*suite.GIB))
    def response(self):return {'kind':'probe','nonce':'a'*32,'identity':'eqemu-recovery-left-v1','http':'eqemu-recovery-left-v1','counter':4,'database':'/opt/eqemu-proof/world.db','endpoint':'172.29.31.2:8080'}
    def test_probe_success(self):worker.validate_reply(self.response(),'probe','a'*32,3)
    def test_probe_replay_cross_worker_counter_and_schema(self):
        for key,val in [('nonce','b'*32),('identity','eqemu-recovery-right-v1'),('counter',3),('counter',True),('http','other'),('database','/tmp/world.db'),('endpoint','172.29.31.2:8081'),('kind','ready')]:
            with self.subTest(key=key,val=val):
                r=self.response();r[key]=val
                with self.assertRaises(RuntimeError):worker.validate_reply(r,'probe','a'*32,3)
        r=self.response();r['ok']=True
        with self.assertRaises(RuntimeError):worker.validate_reply(r,'probe','a'*32,3)
    def test_finish_must_preserve_counter_and_cleanup(self):
        r={'kind':'finish','nonce':'a'*32,'identity':'eqemu-recovery-left-v1','counter':3,'clean':True}
        worker.validate_reply(r,'finish','a'*32,3)
        for key,val in [('clean',False),('counter',4),('counter',True)]:
            bad=dict(r);bad[key]=val
            with self.assertRaises(RuntimeError):worker.validate_reply(bad,'finish','a'*32,3)
    def serial(self,chunks):
        class Sock:
            def recv(self,_):return chunks.pop(0) if chunks else b''
        out=io.BytesIO();return worker.RecoverySerial(Sock(),out),out
    def test_serial_fragmented_and_coalesced(self):
        raw=b'boot\nEQEMU_RECOVERY '+json.dumps(self.response()).encode()+b'\r\n'
        r,out=self.serial([raw[:20],raw[20:]])
        r.poll();r.poll();self.assertEqual(r.frames,[self.response()]);self.assertEqual(out.getvalue(),raw)
    def test_serial_bad_json_duplicate_key_depth_nonfinite(self):
        for raw in [b'{bad}',b'{"kind":"x","kind":"y"}',b'{"x":NaN}',b'['*33+b'0'+b']'*33]:
            r,_=self.serial([b'EQEMU_RECOVERY '+raw+b'\n'])
            with self.assertRaises(RuntimeError):r.poll()
    def test_serial_frame_line_and_queue_limits(self):
        for chunks in [[b'EQEMU_RECOVERY '+b'x'*16385+b'\n'],[b'x'*65537],[(b'EQEMU_RECOVERY {}\n')*9]]:
            r,_=self.serial(chunks)
            with self.assertRaises(RuntimeError):r.poll()
    def test_serial_disk_cap(self):
        r,out=self.serial([b'x\n'*2048]*257)
        for _ in range(256):r.poll()
        with self.assertRaisesRegex(RuntimeError,'limit'):r.poll()
        self.assertEqual(len(out.getvalue()),1024**2)
    def test_recovery_active_controller_refused_before_mutation(self):
        m=types.SimpleNamespace(UNIT='unit')
        with patch.object(suite,'ownership',return_value=self.state),patch.object(suite,'properties',return_value={'ActiveState':'active','MainPID':'23','ControlPID':'0'}),patch.object(suite,'absent') as absent:
            with self.assertRaisesRegex(RuntimeError,'active controller'):suite.reconcile(m)
            absent.assert_not_called()
    def test_recovery_clean_is_noop_and_preserves_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            p=P(temp);c=p/'cleanup.json';c.write_text(json.dumps({'uuid':self.ident,'complete':True}));before=c.read_bytes()
            m=types.SimpleNamespace(UNIT='unit',EVIDENCE=p,cleanup=lambda **_:self.fail('Cleanup repeated'))
            with patch.object(suite,'ownership',return_value=self.state),patch.object(suite,'properties',return_value={'ActiveState':'inactive','MainPID':'0','ControlPID':'0'}),patch.object(suite,'absent',return_value=True),patch.object(suite,'read',side_effect=lambda path:json.loads(path.read_text())):
                self.assertFalse(suite.reconcile(m)['changed']);self.assertEqual(c.read_bytes(),before)
    def test_recovery_identity_failure_precedes_all_actions(self):
        with patch.object(suite,'ownership',side_effect=RuntimeError('Ownership mismatch')),patch.object(suite,'properties') as props:
            with self.assertRaises(RuntimeError):suite.reconcile(types.SimpleNamespace())
            props.assert_not_called()
    def test_third_admission_calls_no_setup(self):
        with tempfile.TemporaryDirectory() as temp:
            root=P(temp);(root/'admission.lock').touch();ledger={'phase':'pair','active':{'left':{},'right':{}}};(root/'leases.json').write_text(json.dumps(ledger));before=(root/'leases.json').read_bytes()
            def mod(case):return types.SimpleNamespace(CASE=case,DATA=root/case,setup=lambda:self.fail('Allocated worker'))
            with patch.object(suite,'ROOT',root),patch.object(suite,'module',side_effect=mod),patch.object(suite,'ownership',return_value=self.state),patch.object(suite,'read',side_effect=lambda p:json.loads(p.read_text())):
                with self.assertRaisesRegex(RuntimeError,'cap reached'):suite.admit('third')
            self.assertEqual((root/'leases.json').read_bytes(),before)
    def test_generated_case_names_and_units_distinct(self):
        modules=[suite.module(case,local=True) for case in suite.CASES]
        units=[suite.UNIT,suite.CHILD]+[m.UNIT for m in modules]
        self.assertEqual(len(units),len(set(units)))
        for m in modules:
            self.assertLessEqual(len(m.NAME),20)
            self.assertIn('cleanup_barrier(s)',P(m.__file__).read_text())
            self.assertEqual(m.ROOT.parent,suite.ROOT)

if __name__=='__main__':unittest.main(verbosity=2)
