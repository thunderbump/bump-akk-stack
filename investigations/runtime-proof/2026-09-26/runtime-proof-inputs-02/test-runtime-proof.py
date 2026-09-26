"""Trusted local protocol/process controls only. Never execute public quest/SQL/package inputs."""
import copy,hashlib,importlib.util,json,pathlib,tempfile,time,types,unittest
from unittest.mock import patch
D=pathlib.Path(__file__).resolve().parent

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
W=load('worker',D/'build-worker.py');G=load('runtime',D/'guest-runtime.py');S=load('suite',D.parent/'offline-runtime-proof-02.py')
N='a'*32

def begin():
 p=W.BuildProtocol(N);p.accept({'kind':'ready','nonce':None,'manifest_sha256':W.MANIFEST_SHA,'runtime_manifest_sha256':W.RUNTIME_MANIFEST_SHA})
 p.accept({'kind':'preflight','nonce':N,'before_status':'1'*64,'after_status':'2'*64,'solver_sha256':'3'*64,'ports':51,'negative_control':True,'tools':{'system-zlib':'1.3'}});return p

def frame(case,state,**kw):return dict(kind='runtime',nonce=N,case=case,state=state,**kw)
def case_frames(p,case):
 p.accept(frame(case,'started'));flags=sorted(W.READY_FLAGS-({'water_map'} if case=='negative' else set()))
 p.accept(frame(case,'ready',flags=flags,zone_id=202,instance_id=0))
 count=4 if case=='negative' else 7;interval=5 if case=='negative' else 10
 for i in range(count):p.accept(frame(case,'sample',sample=i+1,elapsed=i*interval))
 p.runtime_events[case]['host_ready_at']-=70
 p.accept(frame(case,'completed',accepted=case=='positive',missing_readiness=['water_map'] if case=='negative' else []))

def record(case):
 f={'bytes':123,'sha256':'4'*64}
 return {'accepted':case=='positive','missing_readiness':['water_map'] if case=='negative' else [],'flags':sorted(W.READY_FLAGS-({'water_map'} if case=='negative' else set())),'samples':4 if case=='negative' else 7,'duration':15 if case=='negative' else 60,'exits':{'zone':0,'world':0,'database':0},'config_sha256':'a'*64,'schema_sha256':'5'*64,'state_before_sha256':'6'*64,'state_after_sha256':'7'*64,'changed_tables':['eqtime'],'shared':{'items':f,'spells':f},'logs':dict.fromkeys(['world-console.log','zone-console.log','database-console.log'],f)}
def success():
 return {'kind':'result','nonce':N,'ok':True,'checks':dict.fromkeys(['inputs','packages','solver','negative_control','perl','system_zlib','build','tests','runtime'],True),'binaries':dict.fromkeys(['world','zone','shared_memory','loginserver','ucs','queryserv','eqlaunch','tests'],'8'*64),'cache_sha256':'9'*64,'guest_disk_used_bytes':1024,'effective_cmake':{},'runtime':{'input_manifest_sha256':W.RUNTIME_MANIFEST_SHA,'package_plan_sha256':'0'*64,'negative':record('negative'),'positive':record('positive'),'disk_growth_bytes':1024}}
def completed():
 p=begin();case_frames(p,'negative');case_frames(p,'positive');return p

class Protocol(unittest.TestCase):
 def test_accept_complete_positive_and_failed_control(self):
  p=completed();p.accept(success());self.assertTrue(p.result['ok']);self.assertFalse(p.result['runtime']['negative']['accepted'])
 def test_no_runtime_is_not_success(self):
  with self.assertRaises(RuntimeError):begin().accept(success())
 def test_wrong_identity_and_duplicate_readiness(self):
  p=begin();p.accept(frame('negative','started'));v=frame('negative','ready',flags=sorted(W.READY_FLAGS-{'water_map'}),zone_id=202,instance_id=0)
  wrong=dict(v,nonce='b'*32)
  with self.assertRaises(RuntimeError):p.accept(wrong)
  with self.assertRaises(RuntimeError):p.accept(dict(v,zone_id=1))
  p.accept(v)
  with self.assertRaises(RuntimeError):p.accept(v)
 def test_missing_map_never_positive(self):
  p=begin();case_frames(p,'negative');p.accept(frame('positive','started'))
  with self.assertRaises(RuntimeError):p.accept(frame('positive','ready',flags=sorted(W.READY_FLAGS-{'water_map'}),zone_id=202,instance_id=0))
 def test_fake_fast_health_window(self):
  p=begin();p.accept(frame('negative','started'));p.accept(frame('negative','ready',flags=sorted(W.READY_FLAGS-{'water_map'}),zone_id=202,instance_id=0))
  for i in range(4):p.accept(frame('negative','sample',sample=i+1,elapsed=i*5))
  with self.assertRaises(RuntimeError):p.accept(frame('negative','completed',accepted=False,missing_readiness=['water_map']))
 def test_replayed_sample(self):
  p=begin();p.accept(frame('negative','started'));p.accept(frame('negative','ready',flags=sorted(W.READY_FLAGS-{'water_map'}),zone_id=202,instance_id=0));v=frame('negative','sample',sample=1,elapsed=0);p.accept(v)
  with self.assertRaises(RuntimeError):p.accept(v)
 def test_incomplete_result_variants(self):
  for change in [lambda v:v['runtime']['positive']['exits'].update(zone=1),lambda v:v['runtime']['positive']['changed_tables'].append('items'),lambda v:v['runtime']['positive'].update(samples=6),lambda v:v['runtime']['negative'].update(accepted=True),lambda v:v['runtime']['positive']['shared'].pop('spells'),lambda v:v['runtime'].update(input_manifest_sha256='0'*64)]:
   p=completed();v=success();change(v)
   with self.assertRaises(RuntimeError):p.accept(v)
 def test_truncated_duplicate_json_and_frame_bounds(self):
  parser=W.BuildSerial();self.assertEqual(parser.feed(b'EQEMU_BUILD {"ok":true}'),[]);self.assertTrue(parser.tail)
  for data in [b'EQEMU_BUILD {"ok":true,"ok":false}\n',b'EQEMU_BUILD {"x":NaN}\n',b'x'*1048577,b'EQEMU_BUILD '+b' '*16385+b'\n']:
   with self.assertRaises(RuntimeError):W.BuildSerial().feed(data)
 def test_failure_after_ready_stays_failure(self):
  p=begin();p.accept({'kind':'result','nonce':N,'ok':False,'error':'world exit 0 without readiness'});self.assertFalse(p.result['ok'])
  with self.assertRaises(RuntimeError):p.accept(success())

class RuntimeControls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name)
 def tearDown(self):
  for s in list(G.SERVICES):
   G.B.kill_group(s.proc);s.thread.join(3);G.SERVICES.remove(s)
  self.tmp.cleanup()
 def test_zero_exit_is_early_failure(self):
  s=G.Service('zero',['/bin/true'],self.root,self.root/'zero.log');s.proc.wait(timeout=3);s.thread.join(3)
  with self.assertRaisesRegex(RuntimeError,'early exit 0'):s.live()
 def test_error_categories_and_optional_legacy_hook(self):
  s=types.SimpleNamespace(name='zone',flags=set(),stop_expected=False)
  G.Service.scan(s,"Unable to read perl file 'plugin.pl'")
  for line in [' Zone | MySQL Erro | Query failure',' Zone | QuestError | bad script','[ERROR] disk full',"syntax error at file.pl line 4", "Unable to read perl file 'quests/missing.pl'"]:
   with self.assertRaises(RuntimeError):G.Service.scan(s,line)
 def test_service_log_overflow_kills_owned_group(self):
  with patch.object(G,'LOG_CAP',1000):
   s=G.Service('overflow',['/usr/bin/python3','-c','import time; print("x"*4096,flush=True); time.sleep(10)'],self.root,self.root/'overflow.log')
   s.proc.wait(timeout=3);s.thread.join(3)
  self.assertIn('log cap',s.error);self.assertLessEqual(s.path.stat().st_size,1000)
  with self.assertRaises(RuntimeError):s.live()
 def test_missing_water_marks_only_other_readiness(self):
  s=types.SimpleNamespace(name='zone',flags=set(),stop_expected=False)
  for line in ['Loaded V2 Map File [maps/base/poknowledge.map]','Loaded Navmesh V[2] file [maps/nav/poknowledge.nav]','Zone booted successfully zone_id [202] time_offset [0]']:
   G.Service.scan(s,line)
  self.assertEqual(s.flags,{'base_map','nav_map','zone'});self.assertNotEqual(s.flags,G.READINESS)
 def test_unexpected_database_write_and_schema_fail(self):
  before={'schema_sha256':'a','empty_sha256':'b','version':'9328\t0\t0','checksums':{'items':'1','eqtime':'2'}}
  after=copy.deepcopy(before);after['checksums']['eqtime']='3';self.assertEqual(G.check_state(before,after),['eqtime'])
  after['checksums']['items']='4'
  with self.assertRaises(RuntimeError):G.check_state(before,after)
  after=copy.deepcopy(before);after['schema_sha256']='c'
  with self.assertRaises(RuntimeError):G.check_state(before,after)
 def test_runtime_media_tampering(self):
  p=self.root/'file';p.write_bytes(b'ok');m=self.root/'runtime-bundle-manifest.json';m.write_text(json.dumps({'files':[{'path':'file','bytes':2,'sha256':hashlib.sha256(b'ok').hexdigest()}]}))
  with patch.object(G,'RM',self.root),patch.object(G,'RUNTIME_SHA',G.B.sha(m)):
   G.verify_runtime();p.write_bytes(b'xx')
   with self.assertRaises(RuntimeError):G.verify_runtime()
 def test_guest_guard_prevents_host_workload(self):
  with self.assertRaises(RuntimeError):G.check_guest()
 def test_cleanup_is_not_workload_success(self):
  r={'uuid':'u','ok':True,'workload_ok':True,'checks':{'host_pre_resume':True},'service_result':'success'};c={'uuid':'u','complete':True,'readonly_inputs_unchanged':True,'started_at':1,'finished_at':2};p={'ActiveState':'inactive','MainPID':'0','ControlPID':'0','Result':'success'}
  self.assertTrue(S.acceptance(r,c,p,{'uuid':'u'},True)['case_passed'])
  for target,key,value in [(r,'workload_ok',False),(c,'complete',False),(c,'readonly_inputs_unchanged',False)]:
   saved=target[key];target[key]=value;self.assertFalse(S.acceptance(r,c,p,{'uuid':'u'},True)['case_passed']);target[key]=saved
if __name__=='__main__':unittest.main()
