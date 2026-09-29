"""Candidate admission, deterministic outcomes and rendered recipe checks."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation'))
import common
import candidate
import render

FACTS=dict(candidate='a'*40,tree='b'*40,input_id='c'*64,manifest_sha256='d'*64,
           iso_sha256='e'*64,iso_bytes=1)


class Contract(unittest.TestCase):
    def test_identity_rejects_paths_wrong_types_and_extra_policy(self):
        common.identity(FACTS)
        for change in ({'candidate':'../../etc/shadow'},{'iso_bytes':True},
                       {'iso_bytes':common.MAX_ISO+1},{'command':'true'},{'tree':'a'*40+'\n'}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                common.identity(dict(FACTS,**change))

    def test_only_complete_selected_coverage_passes(self):
        passed={'suite_passed':True,'cases_passed':True,'cases':{
            role:{'case_passed':True} for role in ('producer','consumer')}}
        self.assertEqual(common.outcome(passed,{},True),0)
        self.assertEqual(common.outcome(passed,{},False),2)
        for key in ('suite_passed','cases_passed','cases'):
            missing=dict(passed);missing.pop(key)
            self.assertEqual(common.outcome(missing,{},True),2)

    def test_completed_candidate_failure_is_distinct_from_infrastructure(self):
        worker={'checks':{'host_pre_resume':True},'service_result':'exit-code',
                'cleanup':{'readonly_inputs_unchanged':True},
                'resource_observations':{'memory.events':'oom 0\noom_kill 0','pids.events':'max 0'},
                'guest_report_untrusted':{
            'ok':False,'error':'server-build: exit 1\ncompiler error'}}
        self.assertEqual(common.outcome({}, {'producer':worker},True),1)
        for crash in (-4,-6,-7,-8,-11):
            worker['guest_report_untrusted']['error']='upstream-tests: exit '+str(crash)+'\ncrashed'
            self.assertEqual(common.outcome({}, {'producer':worker},True),1)
        for error in ('upstream-tests: exit -9\nkilled','server-build: deadline exceeded','No completion','server-build: exit 1\nNo space left on device',
                      'server-build: exit 1\nKilled signal terminated program cc1plus'):
            worker['guest_report_untrusted']['error']=error
            self.assertEqual(common.outcome({}, {'producer':worker},True),2)
        self.assertEqual(common.outcome({'cleanup':{'rescued':['producer']}},{'producer':worker},True),2)

    def test_candidate_can_change_without_changing_dependency_policy(self):
        baseline={'sources':{'eqemu':{'commit':'old','tree':'old','gitlinks':{'p':'fixed'}}},'dependencies':{'dep':'fixed'}}
        changed=common.candidate_profile(baseline,'a'*40,'b'*40)
        self.assertEqual(baseline['sources']['eqemu']['commit'],'old')
        self.assertEqual(changed['sources']['eqemu']['gitlinks'],{'p':'fixed'})
        self.assertEqual(changed['dependencies'],baseline['dependencies'])

    def test_report_cannot_pass_wrong_candidate_or_incomplete_cleanup(self):
        value=dict(version=1,run_id='0123456789',profile=common.PROFILE,candidate=FACTS,
                   build_id='f'*64,terminal=True,cleanup_complete=True,accepted=True,exit_code=0)
        candidate.checked(value,'0123456789',FACTS,'f'*64)
        for change in ({'candidate':dict(FACTS,tree='f'*40)},{'build_id':'0'*64},
                       {'cleanup_complete':False},{'terminal':False},{'exit_code':False},
                       {'accepted':False}):
            with self.subTest(change=change),self.assertRaises(ValueError):
                candidate.checked(dict(value,**change),'0123456789',FACTS,'f'*64)

    def test_generation_refuses_missing_or_duplicate_recipe_seams(self):
        self.assertEqual(render.assign('A=1\n','A',2),'A=2\n')
        for text in ('B=1\n','A=1\nA=2\n'):
            with self.assertRaises(ValueError):render.assign(text,'A',2)
        with self.assertRaises(ValueError):render.replace_once('x x','x','y')


class Foreground(unittest.TestCase):
    def test_completion_and_owned_cancellation(self):
        for mode,expected in [('pass',0),('candidate',1),('infra',2),('wrong',2),('cleanup',2),('lost',2)]:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                base=Path(directory);upload=base/'uploads'/str(os.getuid());upload.mkdir(parents=True)
                iso=base/'fake.iso';iso.write_bytes(b'x')
                calls=[]
                def request(value):
                    calls.append(value['op'])
                    if value['op']=='run':
                        if mode=='lost':raise RuntimeError('lost admission response')
                        return dict(started=True,run_id=value['run_id'],candidate=FACTS,build_id='f'*64)
                    return dict(version=1,run_id=value['run_id'],profile=common.PROFILE,
                                candidate=FACTS,build_id='0'*64 if mode=='wrong' else 'f'*64,
                                terminal=True,cleanup_complete=mode!='cleanup',accepted=mode=='pass',
                                exit_code=0 if mode=='pass' else 1 if mode=='candidate' else 2)
                with patch.object(candidate,'BASE',base),patch.object(candidate,'prepare',return_value=(iso,FACTS)),\
                     patch.object(candidate,'request',side_effect=request):
                    self.assertEqual(candidate.execute(base),expected)
                self.assertFalse(list(upload.iterdir()))
                if mode in ('wrong','lost'):self.assertEqual(calls[-1],'cancel')


@unittest.skipUnless(os.environ.get('AFK_CHECKOUT'),'Set AFK_CHECKOUT to exercise the real Validator')
class AfkBoundary(unittest.TestCase):
    def test_real_validator_success_failure_and_timeout(self):
        import subprocess
        afk=Path(os.environ['AFK_CHECKOUT'])
        sys.path.insert(0,str(afk))
        from afk_validate.evidence import validate_repairable_failure
        with tempfile.TemporaryDirectory(prefix='eqemu-afk-build-') as tmp:
            root=Path(tmp);workspace=root/'workspace';workspace.mkdir()
            for args in [('init','-q'),('-c','user.name=Test','-c','user.email=test@example.invalid',
                                      'commit','--allow-empty','-qm','clean candidate')]:
                subprocess.run(['git','-C',str(workspace),*args],check=True,capture_output=True)
            for mode,code in [('pass',0),('candidate',1),('infra',2),('wrong',2),('cleanup',2),('timeout',143)]:
                with self.subTest(mode=mode):
                    case=root/mode;case.mkdir()
                    policy=dict(schema_version=1,workspace=str(workspace),command=[sys.executable,'-B',
                        str(ROOT/'tests/validation/build_fixture.py'),str(case),mode],
                        timeout_seconds=1 if mode=='timeout' else 10,termination_grace_seconds=5,repairable_exit_codes=[1])
                    request=case/'input.json';request.write_text(json.dumps(policy));result=case/'result'
                    completed=subprocess.run([sys.executable,'-B','-m','afk_validate',str(request),str(result)],
                        cwd=afk,text=True,capture_output=True,timeout=20)
                    output=json.loads((result/'output.json').read_text())
                    self.assertEqual(output['process']['exit_code'],code,completed.stderr)
                    self.assertEqual(output['outcome'],'passed' if mode=='pass' else 'timed_out' if mode=='timeout' else 'failed')
                    if mode=='candidate':validate_repairable_failure(result,workspace,expected_policy=policy)
                    elif mode!='pass':
                        with self.assertRaises(ValueError):validate_repairable_failure(result,workspace,expected_policy=policy)
                    if mode=='timeout':self.assertEqual((case/'calls').read_text().splitlines()[-1],'cancel')
                    self.assertLess((result/'stdout.log').stat().st_size,128*1024)

if __name__=='__main__':unittest.main()
