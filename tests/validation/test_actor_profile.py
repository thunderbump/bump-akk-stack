"""Fixed actor profile checks with synthetic native/process adapters, never a VM."""
import copy
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'validation'))
import actor
import actor_runtime
import common
import candidate
import render
import test_packaging
FACTS = test_packaging.FACTS


def native(control=None, code=0):
    return dict(version=1, scenario=actor.PROFILE, control=control,
                status='passed' if code == 0 else 'assertion-failed',
                completed_cases=sorted(actor.CASES) if code == 0 else [],
                cycles=3 if code == 0 else 0, ticks=1 if code == 0 else 0,
                id_reuse=code == 0, save_restore=code == 0, native_cleanup=True,
                elapsed_seconds=dict(boot=1, processing=1, shutdown=1))


def observation(control=None, code=0):
    return dict(profile=actor.PROFILE, fixture_manifest_sha256='a'*64, recipe=actor.RECIPE,
                result=actor.result(native(control, code), code, control),
                database_cleanup=True, outputs_unchanged=True, inputs_unchanged=True,
                elapsed_seconds=3, stage_seconds={'actor-lifecycle': 3}, shared={}, package_plan_sha256='b'*64)


def worker():
    return dict(resource_observations={'memory.events':'oom 0\noom_kill 0\n', 'pids.events':'max 0\n'},
                service_result='success', cleanup={'readonly_inputs_unchanged':True,'artifact_input_unchanged':True},
                checks={'host_pre_resume':True}, stages={'actor-lifecycle':{'state':'passed'}},
                guest_report_untrusted={'ok':True}, observations_untrusted={'actor-runtime':observation()})


class Completion(unittest.TestCase):
    def test_positive_requires_fixed_cases_processing_counts_and_native_cleanup(self):
        good = native()
        self.assertEqual(actor.completion('EQEMU_ACTOR_RESULT '+json.dumps(good), 0)['exit_code'],0)
        for change in ({'completed_cases':[]},{'cycles':0},{'ticks':0},{'id_reuse':False},
                       {'save_restore':False},{'native_cleanup':False},{'version':True},
                       {'elapsed_seconds':{'boot':float('nan'),'processing':0,'shutdown':0}}):
            with self.subTest(change=change),self.assertRaises(ValueError):actor.result(dict(good,**change),0)
        for output in ('', 'zone CLI menu', ('EQEMU_ACTOR_RESULT '+json.dumps(good)+'\n')*2,
                       'EQEMU_ACTOR_RESULT {"version":1,"version":1}'):
            with self.subTest(output=output[:50]),self.assertRaises(ValueError):actor.completion(output,0)

    def test_assertion_needs_exact_nonzero_and_clean_native_shutdown(self):
        value = native(code=1)
        self.assertEqual(actor.result(value,1)['status'],'assertion-failed')
        for rc in (-15,-11,0,2,True):
            with self.subTest(rc=rc),self.assertRaises(ValueError):actor.result(value,rc)
        with self.assertRaises(ValueError):actor.result(dict(value,native_cleanup=False),1)
        self.assertEqual(actor.result(native('assertion',1),1,'assertion')['exit_code'],1)
        with self.assertRaises(ValueError):actor.result(native(),0,'assertion')

    def test_fixed_options_reject_arbitrary_profiles_controls_and_uncoupled_reuse(self):
        actor.options('build-unit-v1');actor.options(actor.PROFILE,retain=True)
        for control in actor.CONTROLS:actor.options(actor.PROFILE,control,reuse='0123456789')
        for args in [('other',),('build-unit-v1',None,True),
                     (actor.PROFILE,'shell',False,'0123456789'),(actor.PROFILE,'assertion'),
                     (actor.PROFILE,None,False,'0123456789'),(actor.PROFILE,'assertion',True,'0123456789')]:
            with self.subTest(args=args),self.assertRaises(ValueError):actor.options(*args)

    def test_outcome_requires_completed_actor_stage_and_both_cleanup_layers(self):
        summary={'suite_passed':True,'cases_passed':True,'cases':{'producer':{'case_passed':True},'consumer':{'case_passed':True}},'cleanup':{}}
        workers={'producer':worker(),'consumer':worker()}
        self.assertEqual(common.outcome(summary,workers,True,actor.PROFILE),0)
        for mutation in ('missing-stage','missing-observation','native-cleanup','database-cleanup','host-cleanup','oom','changed-artifact'):
            altered=copy.deepcopy(workers)
            if mutation=='missing-stage':altered['consumer']['stages']={}
            if mutation=='missing-observation':altered['consumer']['observations_untrusted']={}
            if mutation=='native-cleanup':altered['consumer']['observations_untrusted']['actor-runtime']['result']['native_cleanup']=False
            if mutation=='database-cleanup':altered['consumer']['observations_untrusted']['actor-runtime']['database_cleanup']=False
            if mutation=='oom':altered['consumer']['resource_observations']['memory.events']='oom 1\noom_kill 1\n'
            if mutation=='changed-artifact':altered['consumer']['cleanup']['artifact_input_unchanged']=False
            with self.subTest(mutation=mutation):self.assertEqual(common.outcome(summary,altered,mutation!='host-cleanup',actor.PROFILE),2)
        workers['consumer']['observations_untrusted']['actor-runtime']=observation(code=1)
        workers['consumer']['stages']['actor-lifecycle']['state']='failed'
        workers['consumer']['guest_report_untrusted']={'ok':False,'error':'actor-lifecycle: exit 1\nComplete native result'}
        self.assertEqual(common.outcome(dict(summary,suite_passed=False),workers,True,actor.PROFILE),1)
        workers['consumer']['observations_untrusted']['actor-runtime']=observation('assertion',1)
        self.assertEqual(common.outcome(dict(summary,suite_passed=False),workers,True,actor.PROFILE,'assertion',True),1)
        self.assertEqual(common.outcome(summary,{'consumer':worker()},True,actor.PROFILE,'missing-map',True),2)
        self.assertEqual(common.outcome(summary,{'consumer':worker()},True,actor.PROFILE,'cancel',True),2)


class Rendering(unittest.TestCase):
    def setUp(self):
        self.fixture=test_packaging.PackagePreparation('test_rendered_workers_use_owned_inputs_without_history')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.fixture.prepare();self.package=self.fixture.root/'output'
        self.destination=self.fixture.root/'rendered';self.destination.mkdir()

    def render(self,profile=actor.PROFILE,**kw):
        inputs=json.loads((self.package/'host-inputs.json').read_text())
        if profile==actor.PROFILE:
            inputs['runtime.iso']=dict(source='/retained/runtime.iso',bytes=171806720,sha256='a'*64)
            (self.package/'host-inputs.json').write_text(json.dumps(inputs))
        def seed(argv,**_):Path(argv[1]).write_bytes(b'seed')
        with patch.object(render.subprocess,'run',side_effect=seed):
            return render.render('0123456789',FACTS,self.destination,self.package,profile_name=profile,**kw)

    def test_actor_uses_one_producer_and_offline_fresh_consumer_with_bound_helpers(self):
        result=self.render()
        worker_text=(self.destination/'consumer-worker.py').read_text()
        self.assertIn('runtime.iso',worker_text);self.assertIn('EQEMURUNTIME',(self.package/'actor_runtime.py').read_text())
        self.assertIn('3900',worker_text)
        user=json.loads((self.destination/'consumer-user-data').read_text().split('\n',1)[1])
        files={item['path']:item['content'] for item in user['write_files']}
        self.assertIn('/opt/eqemu-proof/actor_runtime.py',files)
        self.assertIn("VALIDATION_PROFILE='actor-lifecycle-v1'",files['/opt/eqemu-proof/guest_build.py'])
        self.assertIn("return {'consumer': consume_build()}",files['/opt/eqemu-proof/guest_build.py'])
        consumer=common.load('actor_rendered_consumer',self.destination/'consumer-worker.py')
        self.assertIn('runtime.iso',consumer.FILES)
        self.assertNotIn('<interface',consumer.domain({'uuid':'00000000-0000-4000-8000-000000000031','profile':'p'}))
        producer=common.load('actor_rendered_producer',self.destination/'producer-worker.py')
        self.assertNotIn('runtime.iso',producer.FILES)
        unit=common.candidate_profile(json.loads((self.package/'profile.json').read_text()),'a'*40,'b'*40)
        actor_profile=common.candidate_profile(json.loads((self.package/'profile.json').read_text()),'a'*40,'b'*40,actor.PROFILE,json.loads((self.package/'runtime-fixture.json').read_text()))
        self.assertNotIn('runtime',unit['dependencies']);self.assertIn('runtime',actor_profile['dependencies'])
        self.assertNotEqual(common.seal(unit),common.seal(actor_profile))
        self.assertEqual(len(result['build_id']),64)

    def test_reuse_runs_consumer_only_preserves_build_identity_and_original_custody(self):
        first=self.render(retain=True)
        before=(self.destination/'launcher.py').read_text()
        self.assertIn('RETAIN_ARTIFACT=True',before)
        identities=[]
        for index,control in enumerate(actor.CONTROLS):
            self.destination=self.fixture.root/('control-'+str(index));self.destination.mkdir()
            result=self.render(control=control,reuse_root=Path('/var/lib/eqemu-build/runs/1111111111'))
            identities.append(result['build_id'])
            suite=common.load('reused_suite'+str(index),self.destination/'launcher.py')
            self.assertEqual(suite.EXECUTE_CASES,('consumer',));self.assertFalse(suite.RETAIN_ARTIFACT)
            consumer=common.load('reused_consumer'+str(index),self.destination/'consumer-worker.py')
            self.assertEqual(consumer.STORE,Path('/var/lib/eqemu-build/runs/1111111111/work/retained'))
            self.assertEqual(consumer.CUSTODY,Path('/var/lib/eqemu-build/runs/1111111111/work/custody.json'))
        self.assertEqual(identities,[first['build_id']]*3)

    def test_protocol_requires_actor_positive_observation_and_rejects_wrong_fixture(self):
        self.render()
        consumer=common.load('actor_protocol_consumer',self.destination/'consumer-worker.py')
        protocol=consumer.BuildProtocol('n'*32);protocol.ready=True
        item=observation();item['fixture_manifest_sha256']=consumer.ACTOR_FIXTURE['manifest_sha256']
        value={'kind':'observation','nonce':'n'*32,'name':'actor-runtime','value':item}
        self.assertEqual(protocol.accept(value),'observation')
        with self.assertRaises(RuntimeError):protocol.accept(value)
        protocol=consumer.BuildProtocol('n'*32);protocol.ready=True
        item['fixture_manifest_sha256']='0'*64
        with self.assertRaises(RuntimeError):protocol.accept(value)
        protocol=consumer.BuildProtocol('n'*32);protocol.ready=True
        with self.assertRaisesRegex(RuntimeError,'Positive actor stage'):
            protocol.accept({'kind':'result','nonce':'n'*32,'ok':True,'consumer':{}})

    def test_actor_media_must_be_explicit_but_unit_only_render_has_no_dependency(self):
        self.render(profile='build-unit-v1')
        worker_text=(self.destination/'consumer-worker.py').read_text()
        consumer=common.load('unit_actor_optional',self.destination/'consumer-worker.py')
        self.assertNotIn('runtime.iso',consumer.FILES)
        self.assertNotIn('/opt/eqemu-proof/actor_runtime.py',(self.destination/'consumer-user-data').read_text())
        self.destination=self.fixture.root/'actor-refusal';self.destination.mkdir()
        with patch.object(render.subprocess,'run'),self.assertRaisesRegex(ValueError,'not installed'):
            render.render('0123456789',FACTS,self.destination,self.package,profile_name=actor.PROFILE)


class Processes(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.events=[]
        self.build=SimpleNamespace(DEADLINE=time.monotonic()+4000,LOGS=self.root,
                                   ENV={'PATH':'/usr/bin:/bin'},emit=self.events.append)
        self.runtime=actor_runtime.Runtime(self.build,None,{})

    def test_ordinary_commands_drain_redact_and_kill_children_when_leader_exits(self):
        self.runtime.secrets=['secret-crosses-write-boundary']
        source="import os,time; os.write(1,b'secret-crosses-');time.sleep(.05);os.write(1,b'write-boundary\\n')"
        with patch.object(self.runtime,'guard'):
            text=self.runtime.command('redaction',[sys.executable,'-c',source])
        self.assertEqual(text,'[redacted]\n');self.assertEqual((self.root/'redaction.log').read_text(),'[redacted]\n')
        # Child closes its pipe, so EOF and leader exit precede group cleanup.
        source="import os,time; p=os.fork();\nif p==0:\n os.close(1);os.close(2);time.sleep(60)\nelse:\n print(p,flush=True)"
        with patch.object(self.runtime,'guard'):
            child=int(self.runtime.command('leader-exit',[sys.executable,'-c',source]).strip())
        stat=Path('/proc')/str(child)/'stat'
        self.assertTrue(not stat.exists() or stat.read_text().rsplit(')',1)[1].split()[0]=='Z')

    def test_native_signal_unknown_result_and_timeout_are_refusal_with_cleanup(self):
        for name,source in [('signal','import os,signal;os.kill(os.getpid(),signal.SIGTERM)'),
                            ('unknown','print("menu");raise SystemExit(1)'),('timeout','import time;time.sleep(60)')]:
            with self.subTest(name=name),patch.object(self.runtime,'guard'),self.assertRaises((ValueError,RuntimeError)):
                self.runtime.command(name,[sys.executable,'-c',source],timeout=.15,actor=True)
        self.assertTrue(all(e['state']=='started' for e in self.events))

    def test_cancel_phase_is_live_and_absence_refuses(self):
        self.runtime.control='cancel'
        source='print(\'EQEMU_ACTOR_PHASE {"version":1,"phase":"actor-created"}\',flush=True);print("missing final")'
        with patch.object(self.runtime,'guard'),self.assertRaises(ValueError):
            self.runtime.command('cancel-phase',[sys.executable,'-c',source],actor=True)
        self.assertIn({'kind':'stage','name':'actor-created','state':'started'},self.events)
        with patch.object(self.runtime,'guard'),self.assertRaisesRegex(RuntimeError,'phase missing'):
            self.runtime.command('missing-phase',[sys.executable,'-c','print("no actor")'],actor=True)

    def test_budget_refuses_before_any_guest_process_and_database_failure_cleans(self):
        self.build.DEADLINE=time.monotonic()+1799
        with patch.object(actor_runtime.subprocess,'Popen') as popen,self.assertRaisesRegex(RuntimeError,'remaining'):
            actor_runtime.run(self.build,None,{}, {}, {})
        popen.assert_not_called()
        proc=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'],start_new_session=True)
        self.runtime.processes.append(proc)
        self.assertFalse(self.runtime.cleanup())
        self.assertIsNotNone(proc.returncode);self.assertEqual(self.runtime.processes,[])

    def test_missing_map_refuses_before_shared_memory_or_actor_execution(self):
        fake=self.root/'runtime';fake.mkdir()
        maps=self.root/'media/maps';maps.mkdir(parents=True)
        for directory,file in [('base','poknowledge.map'),('water','poknowledge.wtr'),('nav','poknowledge.nav')]:
            (maps/directory).mkdir();(maps/directory/file).write_bytes(b'fixture')
        (self.root/'media/opcodes').mkdir();(self.root/'media/quests').mkdir()
        import tarfile
        prefix='projecteqquests-b3e34b84457d570401ea954ddd66de19179d0e41'
        with tarfile.open(self.root/'media/quests/quests-b3e34b8.tar.gz','w:gz') as archive:
            info=tarfile.TarInfo(prefix);info.type=tarfile.DIRTYPE;archive.addfile(info)
        self.runtime.control='missing-map'
        with patch.object(actor_runtime,'ROOT',fake),patch.object(actor_runtime,'MEDIA',self.root/'media'),\
             patch.object(self.runtime,'query') as query,self.assertRaisesRegex(RuntimeError,'map missing'):
            self.runtime.configure()
        query.assert_not_called()


class InputSeals(unittest.TestCase):
    def test_media_hash_manifest_and_member_refusals_precede_any_execution(self):
        import hashlib
        entries=[{'path':'data/'+str(i),'bytes':1,'sha256':hashlib.sha256(b'x').hexdigest()} for i in range(47)]
        manifest={'files':entries};raw=json.dumps(manifest).encode()
        fixture={'iso':{'path':'runtime.iso','bytes':1,'sha256':'a'*64},'manifest':manifest,
                 'manifest_sha256':hashlib.sha256(raw).hexdigest()}
        def member(argv,**kw):
            self.assertEqual(argv[0],'/usr/bin/isoinfo')
            return SimpleNamespace(stdout=raw if argv[-1]=='/runtime-bundle-manifest.json' else b'x')
        with patch.object(actor.subprocess,'run',side_effect=member):
            evidence=actor.verify_media('/opaque',fixture,lambda *_:{'bytes':1,'sha256':'a'*64})
        self.assertEqual(evidence['files_verified'],48);self.assertFalse(evidence['executed'])
        with patch.object(actor.subprocess,'run') as run,self.assertRaisesRegex(ValueError,'ISO identity'):
            actor.verify_media('/opaque',fixture,lambda *_:{'bytes':1,'sha256':'0'*64})
        run.assert_not_called()
        with patch.object(actor.subprocess,'run',return_value=SimpleNamespace(stdout=b'changed')),self.assertRaisesRegex(ValueError,'manifest identity'):
            actor.verify_media('/opaque',fixture,lambda *_:{'bytes':1,'sha256':'a'*64})
        def changed(argv,**kw):return SimpleNamespace(stdout=raw if argv[-1]=='/runtime-bundle-manifest.json' else b'y')
        with patch.object(actor.subprocess,'run',side_effect=changed),self.assertRaisesRegex(ValueError,'member identity'):
            actor.verify_media('/opaque',fixture,lambda *_:{'bytes':1,'sha256':'a'*64})


class QualificationAdmission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_build_host
        cls.fixture=test_build_host.HostAdmission
        cls.fixture.setUpClass();cls.host=cls.fixture.host

    @classmethod
    def tearDownClass(cls):cls.fixture.tearDownClass()

    def setUp(self):
        self.root=Path('/var/lib/eqemu-build/runs/1111111111')
        self.request=dict(version=1,op='run',run_id='0123456789',profile=actor.PROFILE,candidate=FACTS,
                          reuse_artifact='1111111111',qualification_control='assertion')
        self.baseline=json.loads((ROOT/'validation/profile.json').read_text())
        self.fixture_input=json.loads((ROOT/'validation/runtime-fixture.json').read_text())
        self.manifest={'files':{'actor.py':'a'*64}}
        profile=common.candidate_profile(self.baseline,FACTS['candidate'],FACTS['tree'],actor.PROFILE,self.fixture_input)
        build_id=common.seal(dict(profile=profile,input_id=FACTS['input_id'],manifest_sha256=FACTS['manifest_sha256'],recipe=self.manifest['files']))
        self.record={'uid':os.getuid(),'run_id':'1111111111','version':str(self.host.HERE),
                     'profile':actor.PROFILE,'candidate':FACTS,'retain_artifact':True,'recipe':{'build_id':build_id}}
        self.status=dict(terminal=True,cleanup_complete=True,accepted=True,retained_artifact={'expired':False})

    def read(self,path):
        if path.name=='owner.json':return self.record
        if path.name=='profile.json':return self.baseline
        if path.name=='runtime-fixture.json':return self.fixture_input
        if path.name=='manifest.json':return self.manifest
        raise AssertionError(path)

    def reuse(self):
        with patch.object(self.host.S,'safe_path'),patch.object(self.host.S,'read_json',side_effect=self.read),\
             patch.object(self.host,'report_record',return_value=self.status):
            return self.host.reusable_artifact(self.request,os.getuid())

    def test_only_same_owner_candidate_input_profile_package_and_completed_positive_reuse(self):
        self.assertEqual(self.reuse(),self.root)
        for kind in ('owner','package','candidate','input','profile','active','cleanup','failed-positive','expired','missing-artifact'):
            record=copy.deepcopy(self.record);status=copy.deepcopy(self.status);manifest=copy.deepcopy(self.manifest)
            if kind=='owner':self.record['uid']+=1
            if kind=='package':self.manifest['files']['actor.py']='b'*64
            if kind=='candidate':self.record['candidate']=dict(FACTS,candidate='0'*40)
            if kind=='input':self.record['candidate']=dict(FACTS,input_id='0'*64)
            if kind=='profile':self.record['profile']='build-unit-v1'
            if kind=='active':self.status['terminal']=False
            if kind=='cleanup':self.status['cleanup_complete']=False
            if kind=='failed-positive':self.status['accepted']=False
            if kind=='expired':self.status['retained_artifact']['expired']=True
            if kind=='missing-artifact':self.status['retained_artifact']=None
            try:
                with self.subTest(kind=kind),self.assertRaises(ValueError):self.reuse()
            finally:self.record=record;self.status=status;self.manifest=manifest

    def test_failed_reuse_has_no_run_directory_or_uploaded_media_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);(base/'runs').mkdir()
            disk=SimpleNamespace(f_bavail=200*1024**3,f_frsize=1)
            with patch.object(self.host,'BASE',base),patch.object(self.host.os,'statvfs',return_value=disk),\
                 patch.object(self.host,'reusable_artifact',side_effect=ValueError('expired')),\
                 patch.object(self.host,'copy_upload') as copy_upload,self.assertRaisesRegex(ValueError,'expired'):
                self.host.start(self.request,os.getuid())
            self.assertEqual(list((base/'runs').iterdir()),[]);copy_upload.assert_not_called()

    def test_requests_cannot_widen_qualification_or_mutate_historical_release(self):
        self.assertEqual(self.host.parse(json.dumps(self.request)),self.request)
        for change in ({'qualification_control':'arbitrary'},{'reuse_artifact':'../owned'},{'retain_artifact':True},
                       {'profile':'build-unit-v1'},{'runtime_path':'/etc/shadow'}):
            with self.subTest(change=change),self.assertRaises(ValueError):self.host.parse(json.dumps(dict(self.request,**change)))
        for op in ('status','cancel','release'):
            self.assertEqual(self.host.parse(json.dumps({'version':1,'op':op,'run_id':'1111111111'}))['op'],op)


class ForegroundCancellation(unittest.TestCase):
    def test_actor_created_reaches_foreground_before_cancellation_and_final_nonpass(self):
        import select
        with tempfile.TemporaryDirectory() as tmp:
            process=subprocess.Popen([sys.executable,'-B',str(ROOT/'tests/validation/build_fixture.py'),tmp,'actor-cancel'],
                                     stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                events=[];end=time.monotonic()+10
                while time.monotonic()<end:
                    if select.select([process.stdout],[],[],.1)[0]:
                        line=process.stdout.readline()
                        if not line:break
                        event=json.loads(line);events.append(event)
                        if event.get('event')=='actor-created':break
                self.assertEqual([e['event'] for e in events],['submitted','actor-created'])
                self.assertIsNone(process.poll())
                process.send_signal(signal.SIGTERM)
                out,err=process.communicate(timeout=10)
                self.assertEqual(process.returncode,143,err)
                final=json.loads(out.splitlines()[-1])
                self.assertFalse(final['accepted']);self.assertTrue(final['cleanup_complete'])
                self.assertEqual(final['coverage'],['reused-compile','utility-tests','fresh-consumer','actor-lifecycle'])
                calls=(Path(tmp)/'calls').read_text().splitlines()
                self.assertEqual(calls[0],'run');self.assertEqual(calls[-1],'cancel')
                self.assertTrue(calls[1:-1] and set(calls[1:-1])=={'status'})
            finally:
                if process.poll() is None:process.kill();process.communicate(timeout=5)


class RetainedCustody(unittest.TestCase):
    setUpClass = classmethod(QualificationAdmission.setUpClass.__func__)
    tearDownClass = classmethod(QualificationAdmission.tearDownClass.__func__)
    setUp = QualificationAdmission.setUp
    def test_retained_receipt_is_truthful_and_expiry_refuses_reuse_but_allows_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'artifact.raw';path.write_bytes(b'opaque')
            now=time.time()
            custody=dict(identity=self.record['recipe']['build_id'],eligible=True,consumer_verified=True,
                         producer_uuid='producer',sha256='a'*64,manifest_sha256='b'*64,
                         retained_at=now-10,expires_at=now+86400-10)
            worker=SimpleNamespace(CUSTODY=Path(tmp)/'custody.json')
            suite=SimpleNamespace(module=lambda _:worker,retained_file=lambda _:path,
                                  ownership_released=lambda _:{'uuid':'producer'})
            with patch.object(self.host.S,'read_json',return_value=custody):
                value=self.host.retained_record(self.root,self.record,suite)
                self.assertFalse(value['expired']);self.assertEqual(value['owner_run'],'1111111111')
                custody['retained_at']=now-86410;custody['expires_at']=now-10
                self.assertTrue(self.host.retained_record(self.root,self.record,suite)['expired'])
                for key,value in [('eligible',False),('consumer_verified',False),('producer_uuid','other'),('expires_at',now+86400)]:
                    old=custody[key];custody[key]=value
                    try:
                        with self.subTest(key=key),self.assertRaises(ValueError):self.host.retained_record(self.root,self.record,suite)
                    finally:custody[key]=old

    def test_release_refuses_active_consumer_before_original_artifact_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);(base/'runs').mkdir();(base/'request.lock').touch()
            donor=base/'runs/1111111111';donor.mkdir()
            child=base/'runs/2222222222';child.mkdir()
            suite=SimpleNamespace(discard_artifact=lambda:None)
            read=lambda path:{'reuse_artifact':'1111111111','uid':os.getuid()} if path.name=='owner.json' else {}
            report=lambda run,uid:dict(terminal=run=='1111111111',cleanup_complete=run=='1111111111')
            with patch.object(self.host,'BASE',base),patch.object(self.host.S,'safe_path'),\
                 patch.object(self.host.S,'read_json',side_effect=read),patch.object(self.host,'report',side_effect=report),\
                 patch.object(self.host,'owner',return_value=(donor,self.record)),\
                 patch.object(self.host,'suite_for',return_value=suite) as suite_for,self.assertRaisesRegex(ValueError,'active or uncertain consumer'):
                self.host.dispatch({'op':'release','run_id':'1111111111'},os.getuid())
            suite_for.assert_not_called()
