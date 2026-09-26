"""Local failure controls: no VM, package installation or acquired code execution."""
import hashlib,importlib.util,json,pathlib,tempfile,time,types,unittest
from unittest.mock import patch
D=pathlib.Path(__file__).resolve().parent

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
G=load('guest',D/'guest.py');W=load('worker',D/'build-worker.py');S=load('suite',D.parent/'offline-build-proof-v3.py')
NONCE='a'*32

def ready(p):p.accept({'kind':'ready','nonce':None,'manifest_sha256':W.MANIFEST_SHA})
def preflight(p):p.accept({'kind':'preflight','nonce':NONCE,'before_status':'1'*64,'after_status':'2'*64,'solver_sha256':'3'*64,'ports':51,'negative_control':True,'tools':{'system-zlib':'1.3'}})
def success():return {'kind':'result','nonce':NONCE,'ok':True,'checks':dict.fromkeys(['inputs','packages','solver','negative_control','perl','system_zlib','build','tests'],True),'binaries':dict.fromkeys(['world','zone','shared_memory','loginserver','ucs','queryserv','eqlaunch','tests'],'4'*64),'cache_sha256':'5'*64,'guest_disk_used_bytes':1024,'effective_cmake':{}}
class Protocol(unittest.TestCase):
 def test_split_frame(self):
  r=W.BuildSerial();data=b'EQEMU_BUILD {"kind":"hello"}\n';self.assertEqual(r.feed(data[:8]),[]);self.assertEqual(r.feed(data[8:]),[{'kind':'hello'}])
 def test_bad_json(self):
  for value in [b'{"x":1,"x":2}',b'{"x":NaN}',b'['*33+b']'*33,b'{broken']:
   with self.subTest(value=value),self.assertRaises(RuntimeError):W.BuildSerial().feed(b'EQEMU_BUILD '+value+b'\n')
 def test_limits(self):
  for data in [b'x'*65537,b'x'*1048577,b'EQEMU_BUILD '+b' '*16385+b'\n']:
   with self.subTest(size=len(data)),self.assertRaises(RuntimeError):W.BuildSerial().feed(data)
 def test_order_and_nonce(self):
  p=W.BuildProtocol(NONCE)
  with self.assertRaises(RuntimeError):p.accept(success())
  ready(p)
  with self.assertRaises(RuntimeError):ready(p)
  v={'kind':'stage','nonce':'b'*32,'name':'test','state':'passed'}
  with self.assertRaises(RuntimeError):p.accept(v)
  with self.assertRaises(RuntimeError):p.accept(success())
 def test_good_and_duplicate_end(self):
  p=W.BuildProtocol(NONCE);ready(p);preflight(p);p.accept(success());self.assertTrue(p.result['ok'])
  with self.assertRaises(RuntimeError):p.accept(success())
 def test_failure_stays_failure(self):
  p=W.BuildProtocol(NONCE);ready(p);p.accept({'kind':'result','nonce':NONCE,'ok':False,'error':'missing input'});self.assertFalse(p.result['ok'])
 def test_missing_zlib_evidence(self):
  p=W.BuildProtocol(NONCE);ready(p)
  with self.assertRaisesRegex(RuntimeError,'Invalid tool facts'):
   p.accept({'kind':'preflight','nonce':NONCE,'before_status':'1'*64,'after_status':'2'*64,'solver_sha256':'3'*64,'ports':51,'negative_control':True,'tools':{}})
  preflight(p);v=success();del v['checks']['system_zlib']
  with self.assertRaisesRegex(RuntimeError,'Invalid success result'):p.accept(v)
 def test_incomplete_success(self):
  for key in ['zone','world']:
   p=W.BuildProtocol(NONCE);ready(p);preflight(p);v=success();del v['binaries'][key]
   with self.assertRaises(RuntimeError):p.accept(v)
class GuestRunner(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.old=G.LOGS;G.LOGS=pathlib.Path(self.tmp.name);G.DEADLINE=time.monotonic()+15
 def tearDown(self):G.LOGS=self.old;self.tmp.cleanup()
 def test_nonzero(self):
  with self.assertRaisesRegex(RuntimeError,'exit 7'):G.command('fail',['/bin/sh','-c','exit 7'])
 def test_timeout(self):
  begin=time.monotonic()
  with self.assertRaisesRegex(RuntimeError,'deadline'):G.command('timeout',['/usr/bin/python3','-c','import time; time.sleep(30)'],timeout=.1)
  self.assertLess(time.monotonic()-begin,3)
 def test_log_overflow(self):
  with self.assertRaisesRegex(RuntimeError,'log limit'):G.command('overflow',['/usr/bin/python3','-c','print("x"*4096)'],cap=100)
  self.assertLessEqual((G.LOGS/'overflow.log').stat().st_size,100)
 def test_clean_success(self):self.assertEqual(G.command('ok',['/bin/echo','yes']).read_text(),'yes\n')
 def test_missing_and_tampered_media(self):
  root=pathlib.Path(self.tmp.name);p=root/'payload';p.write_bytes(b'ok')
  m=root/'bundle-manifest.json';m.write_text(json.dumps({'files':[{'path':'payload','bytes':2,'sha256':hashlib.sha256(b'ok').hexdigest()}]}))
  with patch.object(G,'MEDIA',root),patch.object(G,'MANIFEST_SHA',G.sha(m)):
   G.verify_inputs();p.write_bytes(b'no')
   with self.assertRaisesRegex(RuntimeError,'Missing or changed'):G.verify_inputs()
   p.unlink()
   with self.assertRaisesRegex(RuntimeError,'Missing or changed'):G.verify_inputs()
class Acceptance(unittest.TestCase):
 def test_green_requires_both_workload_and_cleanup(self):
  r={'uuid':'u','ok':True,'workload_ok':True,'checks':{'host_pre_resume':True},'service_result':'success'};c={'uuid':'u','complete':True,'readonly_inputs_unchanged':True,'started_at':1,'finished_at':2};p={'ActiveState':'inactive','MainPID':'0','ControlPID':'0','Result':'success'}
  self.assertTrue(S.acceptance(r,c,p,{'uuid':'u'},True)['case_passed'])
  for target,key,value in [(r,'workload_ok',False),(c,'complete',False),(p,'Result','timeout')]:
   saved=target[key];target[key]=value;self.assertFalse(S.acceptance(r,c,p,{'uuid':'u'},True)['case_passed']);target[key]=saved
  self.assertFalse(S.acceptance(r,c,p,{'uuid':'u'},False)['case_passed'])
 def test_cleanup_after_successful_release(self):
  with tempfile.TemporaryDirectory() as t:
   root=pathlib.Path(t);child=root/'build';child.mkdir();ctl=root/'controller.slice';ctl.write_text('owned')
   (root/'leases.json').write_text(json.dumps({'active':{},'released':[{'uuid':'u'}]}))
   (root/'suite-result.json').write_text(json.dumps({'cases_passed':True}))
   m=types.SimpleNamespace(ROOT=child,UNIT='unit',state=lambda:{'uuid':'u'})
   def read(p):return json.loads(p.read_text())
   with patch.object(S,'ROOT',root),patch.object(S,'CTLFILE',ctl),patch.object(S,'CTLTEXT','owned'),patch.object(S,'module',return_value=m),patch.object(S,'read',side_effect=read),patch.object(S,'properties',return_value={'ActiveState':'inactive','MainPID':'0','ControlPID':'0'}),patch.object(S,'absent',return_value=True),patch.object(S,'controller_budget',return_value={}),patch.object(S,'ownership',side_effect=AssertionError('Released lease must not be reacquired')),patch.dict(S.os.environ,{'SERVICE_RESULT':'success'}):
    self.assertEqual(S.cleanup(),0)
   self.assertTrue(json.loads((root/'suite-result.json').read_text())['suite_passed']);self.assertFalse(ctl.exists())
 def test_controller_deadlines_and_network_boundary(self):
  code=(D/'build-worker.py').read_text();suite=(D.parent/'offline-build-proof-v3.py').read_text()
  self.assertIn('RuntimeMaxSec=17400',code);self.assertIn('RuntimeMaxSec=18000',suite)
  xml=W.domain({'uuid':'00000000-0000-4000-8000-000000000031','profile':'test'})
  self.assertNotIn('<interface',xml);self.assertNotIn('<filesystem',xml);self.assertIn('<readonly/>',xml)
if __name__=='__main__':unittest.main()
