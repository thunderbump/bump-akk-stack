import importlib.util,json,pathlib,unittest
from unittest.mock import patch
P=pathlib.Path;D=P(__file__).parent

def load(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load(D/'resources-worker.py','worker');suite=load(D.parent/'pressure-tests.py','suite')
ready={'schema':1,'kind':'offline-container-trial','ok':True,'checks':dict.fromkeys(m.REQUIRED,True)}
result={'schema':1,'kind':'pressure-resource-result','ok':True,'checks':{'disk_full':True,'cpu_done':True},'written_bytes':20*1024**2}
def frame(prefix,obj):return prefix+json.dumps(obj).encode()+b'\n'
R=frame(m.READY,ready);V=frame(m.RESULT,result)
class Evidence(unittest.TestCase):
 def test_fragmented_and_coalesced_positive(self):
  for n in [1,7,65536]:
   p=m.SerialReader();events=[];data=b'boot log\n'+R+V
   for i in range(0,len(data),n):events+=list(p.feed(data[i:i+n]))
   self.assertEqual([x[0] for x in events],['ready','result'])
 def test_ready_survives_coalesced_failure(self):
  p=m.SerialReader();stream=p.feed(R+m.RESULT+b'{broken}\n')
  self.assertEqual(next(stream)[0],'ready')
  with self.assertRaisesRegex(m.EvidenceError,'Malformed result JSON'):next(stream)
 def test_duplicate_json_keys(self):
  with self.assertRaisesRegex(m.EvidenceError,'Duplicate JSON key'):list(m.SerialReader().feed(m.READY+b'{"ok":true,"ok":false}\n'))
 def test_duplicate_frames(self):
  for data,message in [(R+R,'Duplicate readiness'),(R+V+V,'Duplicate result')]:
   with self.subTest(message=message),self.assertRaisesRegex(m.EvidenceError,message):list(m.SerialReader().feed(data))
 def test_result_requires_readiness(self):
  with self.assertRaisesRegex(m.EvidenceError,'before readiness'):list(m.SerialReader().feed(V))
 def test_forged_success(self):
  for data in [{'schema':1,'kind':'suite-result','ok':True,'suite_passed':True},{**result,'checks':{'disk_full':1,'cpu_done':1}}]:
   with self.assertRaisesRegex(m.EvidenceError,'Invalid result schema'):list(m.SerialReader().feed(R+frame(m.RESULT,data)))
 def test_strict_types_and_numbers(self):
  for data in [{**ready,'schema':True},{**ready,'ok':1},{**ready,'checks':dict.fromkeys(m.REQUIRED,1)}]:
   with self.assertRaisesRegex(m.EvidenceError,'Invalid readiness schema'):list(m.SerialReader().feed(frame(m.READY,data)))
  with self.assertRaisesRegex(m.EvidenceError,'Non-finite'):list(m.SerialReader().feed(m.READY+b'{"x":NaN}\n'))
 def test_oversized_and_unterminated(self):
  for data,msg in [(m.RESULT+b'x'*20000+b'\n','Oversized result'),(b'x'*65537+b'\n','Oversized serial'),(b'x'*65537,'Unterminated oversized')]:
   with self.assertRaisesRegex(m.EvidenceError,msg):list(m.SerialReader().feed(data))
 def test_flood_cap(self):
  p=m.SerialReader();block=b'x'*4095+b'\n'
  for _ in range(256):list(p.feed(block))
  self.assertEqual(p.total,1024**2)
  with self.assertRaisesRegex(m.EvidenceError,'Serial output limit'):list(p.feed(block))
  self.assertEqual(p.total,1024**2)
 def test_deep_or_invalid_utf8(self):
  with self.assertRaisesRegex(m.EvidenceError,'Malformed result JSON'):m.strict_json(b'\xff')
  with self.assertRaisesRegex(m.EvidenceError,'JSON nesting limit'):m.strict_json(b'['*1200+b'0'+b']'*1200)
  self.assertEqual(m.strict_json(b'"'+b'['*64+b'"'),'['*64)

class Collector(unittest.TestCase):
 def test_actual_collector_caps_file_and_records_rejection(self):
  import tempfile
  class Socket:
   def __init__(self):self.blocks=iter([R]+[b'x'*4095+b'\n']*300)
   def recv(self,_):return next(self.blocks,b'')
   def __enter__(self):return self
   def __exit__(self,*_):pass
  with tempfile.TemporaryDirectory(prefix='eqemu-pressure-replay-') as tmp:
   report={'started_at':m.time.time()}
   with patch.object(m,'EVIDENCE',P(tmp)),patch.object(m,'CASE','flood'),patch.object(m,'host_ready'):
    with self.assertRaisesRegex(m.EvidenceError,'Serial output limit exceeded'):
     m.collect_pressure(Socket(),{},report,P(tmp))
   self.assertTrue(report.get('ready_at'));self.assertEqual(report['evidence_rejected'],'Serial output limit exceeded')
   self.assertEqual(report['serial_bytes'],1024**2);self.assertEqual((P(tmp)/'serial.log').stat().st_size,1024**2)
 def test_cpu_claim_needs_actual_host_pressure(self):
  for after in [{'usage_usec':0,'nr_throttled':0},{'usage_usec':90_000_000,'nr_throttled':100},{'usage_usec':5_000_000,'nr_throttled':0}]:
   report={'cpu_start':{'usage_usec':0,'nr_throttled':0},'cpu_started_monotonic':0}
   with tempfile_context() as path:
    with patch.object(m,'CASE','resources'),patch.object(m,'counters',return_value=after),patch.object(m.time,'monotonic',return_value=30):
     with self.assertRaisesRegex(RuntimeError,'CPU enforcement'):m.resource_result(result,report,path)

def tempfile_context():
 import contextlib,tempfile
 @contextlib.contextmanager
 def ctx():
  with tempfile.TemporaryDirectory(prefix='eqemu-cpu-replay-') as tmp:
   p=P(tmp);(p/'cpu.max').write_text('25000 100000');yield p
 return ctx()

class Outcomes(unittest.TestCase):
 def facts(self,case):
  return [case,{'checks':{'host_pre_resume':True},'live_vm_at_injection':True,'ready_at':1,'error':suite.EXPECTED[case],'pressure_verified':True,'evidence_rejected':suite.EXPECTED[case],'ok':False,'workload_ok':False,'service_result':'exit-code','uuid':'owned'}, {'complete':True,'uuid':'owned','started_at':1,'finished_at':2,'readonly_inputs_unchanged':True}, {'Result':'exit-code','ExecMainCode':'1','ExecMainStatus':'1','ActiveState':'failed','MainPID':'0','ControlPID':'0'},True,1024]
 def test_all_expected(self):
  for c in suite.CASES:self.assertTrue(suite.classify(*self.facts(c))['case_passed'])
 def test_missing_kernel_evidence(self):
  x=self.facts('oom');x[1]['pressure_verified']=False;self.assertFalse(suite.classify(*x)['case_passed'])
 def test_wrong_error_not_expected_rejection(self):
  x=self.facts('malformed');x[1]['error']='Controller interrupted';self.assertFalse(suite.classify(*x)['case_passed'])
 def test_cleanup_and_false_success(self):
  for which,key,value in [(1,'ok',True),(2,'complete',False),(2,'readonly_inputs_unchanged',False),(2,'uuid','other'),(3,'ControlPID','12'),(3,'Result','timeout')]:
   x=self.facts('resources');x[which][key]=value;self.assertFalse(suite.classify(*x)['case_passed'])
 def test_output_and_residual_resources(self):
  x=self.facts('flood');x[-1]=1024**2+1;self.assertFalse(suite.classify(*x)['case_passed'])
  x=self.facts('tasks');x[-2]=False;self.assertFalse(suite.classify(*x)['case_passed'])
 def test_stops_after_failed_case(self):
  with patch.object(suite,'properties',return_value={'MemoryMax':str(64*1024**2),'MemorySwapMax':'0'}),patch.object(suite,'write'),patch.object(suite,'execute_case',side_effect=RuntimeError('failed')) as execute,patch.object(suite.signal,'signal'):
   self.assertEqual(suite.supervise(),1);self.assertEqual(execute.call_count,1)
 def test_names_and_extra_disk(self):
  for c in suite.CASES:
   w=suite.module(c,local=True);self.assertLessEqual(len(w.NAME),20)
   xml=w.ET.fromstring(w.domain({'uuid':'00000000-0000-4000-8000-000000000001','profile':'test'}))
   disks=xml.findall('./devices/disk');self.assertEqual(len(disks),4 if c=='resources' else 3)
if __name__=='__main__':unittest.main()
