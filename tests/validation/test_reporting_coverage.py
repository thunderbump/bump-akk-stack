"""Execute maintained guest controls and reject incomplete producer/consumer evidence."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'validation'))
import common

MODES = {'pass': (0, 1, 1, 1, 0, True, True),
         'fail': (1, 1, 1, 1, 1, True, False),
         'empty': (1, 0, 0, 0, 0, True, False),
         'setup-exception': (1, 1, 1, 0, 0, False, False),
         'body-exception': (1, 1, 1, 1, 1, True, False),
         'teardown-exception': (1, 1, 1, 0, 0, False, False)}
KEYS = ['version', 'selected', 'started', 'completed', 'failed', 'finalized', 'passed']


def recipe(name):
    path = ROOT/'validation/recipes'/name
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(path.read_text(), str(path), 'exec'), module.__dict__)
    return module


def outcome(mode):
    return dict(zip(KEYS, [1, *MODES[mode][1:]]), exit_code=MODES[mode][0])


class GuestCoverage(unittest.TestCase):
    def guest(self, name, root, events, fault=None):
        guest = recipe(name)
        guest.WORK = root; guest.LOGS = root/'logs'; guest.LOGS.mkdir()
        guest.DEADLINE = time.monotonic()+10
        guest.emit = events.append
        binary = root/'build/bin'; binary.mkdir(parents=True)
        runner = binary/'tests_runner_controls'
        runner.write_text('#!/usr/bin/python3\nimport json,sys\nfrom pathlib import Path\n'
                          'mode=sys.argv[1]\n'
                          f'outcomes={MODES!r}\n'
                          "Path(__file__).with_name('executed-'+mode).touch()\n"
                          "v=outcomes[mode]\n"
                          + ("v=outcomes['pass'] if mode=='teardown-exception' else v\n" if fault=='teardown' else '')
                          + f'keys={KEYS!r}\n'
                          "print('EQEMU_TEST_RESULT '+json.dumps(dict(zip(keys,[1,*v[1:]]))))\n"
                          'sys.exit(v[0])\n')
        runner.chmod(0o700)
        reporting = binary/'tests_reporting_controls'
        reporting.write_text('#!/usr/bin/python3\nfrom pathlib import Path\n'
                             "Path(__file__).with_name('reporting-executed').touch()\n"
                             + ("raise SystemExit(1)\n" if fault=='nonzero' else
                                "print('Reporting controls passed')\n" if fault!='empty' else ''))
        reporting.chmod(0o700)
        if fault=='omitted': reporting.unlink()
        return guest

    def test_both_guest_paths_execute_reporting_and_all_six_modes(self):
        for name in ['producer-guest.py', 'consumer-guest.py']:
            with self.subTest(role=name), tempfile.TemporaryDirectory() as tmp:
                events=[]; root=Path(tmp); guest=self.guest(name,root,events)
                guest.runner_controls(build_controls=False)
                seen={event['name']:event['value'] for event in events}
                self.assertEqual(seen, {'reporting-controls':{'passed':True,'exit_code':0},
                                        **{'runner-'+mode:outcome(mode) for mode in MODES}})
                self.assertTrue((root/'build/bin/reporting-executed').exists())
                self.assertTrue(all((root/'build/bin'/('executed-'+mode)).exists() for mode in MODES))
                builds=[]; original=guest.command
                def command(stage,args,**kwargs):
                    if stage=='runner-control-build': builds.append((args,kwargs)); return None
                    return original(stage,args,**kwargs)
                # Fresh logs because command refuses to overwrite prior evidence.
                guest.LOGS=root/'producer-logs';guest.LOGS.mkdir()
                with patch.object(guest,'command',side_effect=command):guest.runner_controls()
                self.assertEqual(len(builds),1)
                self.assertEqual(builds[0][0][3:], ['--target','tests_runner_controls',
                                                  'tests_reporting_controls','--parallel','1'])
                self.assertEqual(builds[0][1]['timeout'],600)

    def test_missing_empty_nonzero_and_wrong_teardown_never_emit_complete_coverage(self):
        for name in ['producer-guest.py','consumer-guest.py']:
            for fault in ['omitted','empty','nonzero','teardown']:
                with self.subTest(role=name,fault=fault), tempfile.TemporaryDirectory() as tmp:
                    events=[]; guest=self.guest(name,Path(tmp),events,fault)
                    with self.assertRaises((RuntimeError,OSError)):guest.runner_controls(False)
                    self.assertNotIn('reporting-controls',{event['name'] for event in events})


class HostCoverage(unittest.TestCase):
    def protocol(self, role):
        worker=recipe(role+'-worker.py.in');worker.CASE=role
        protocol=worker.BuildProtocol('nonce');protocol.ready=True;protocol.preflight=True
        return worker,protocol

    def observation(self, protocol, name, value):
        return protocol.accept(dict(kind='observation',nonce='nonce',name=name,value=value))

    def success(self, worker, protocol):
        for mode in MODES:self.observation(protocol,'runner-'+mode,outcome(mode))
        self.observation(protocol,'reporting-controls',{'exit_code':0,'passed':True})
        utility=dict(zip(KEYS,[1,79,79,79,0,True,True]))
        self.observation(protocol,'utility',utility)
        files={name:'a'*64 for name in ['world','zone','shared_memory','tests',
                                      'tests_runner_controls','tests_reporting_controls']}
        if worker.CASE=='consumer':
            prior={'guest_report_untrusted':{'binaries':files},'observations_untrusted':{},
                   'preflight_untrusted':{'after_status':'status'}}
            item=dict(identity=worker.BUILD_ID,manifest_sha256='b'*64,readonly=True,unmounted=True,
                      compiled=False,binaries=files,libraries={},after_status='status',utility=utility,
                      controls={name:protocol.observations[name] for name in ['reporting-controls',
                              *('runner-'+mode for mode in MODES)]})
            value=dict(kind='result',nonce='nonce',ok=True,consumer=item)
            return value, prior
        self.observation(protocol,'candidate',worker.CANDIDATE)
        for index in range(6):self.observation(protocol,'loader-'+str(index),{})
        for index in range(6):
            self.observation(protocol,'elf-'+str(index),dict(bytes=1,build_file=True,sha256='a'*64))
        self.observation(protocol,'measurement',dict(files=6,build_bytes=6,system_bytes=0,total_bytes=6,
                         within_payload_budget=True,artifact_eligible=False,runtime_closure_proven=False))
        files.update({name:'a'*64 for name in ['loginserver','ucs','queryserv','eqlaunch']})
        checks={name:True for name in ['inputs','packages','solver','negative_control','perl',
                                      'system_zlib','build','tests']}
        value=dict(kind='result',nonce='nonce',ok=True,checks=checks,binaries=files,
                   cache_sha256='a'*64,guest_disk_used_bytes=1,effective_cmake={},
                   artifact=dict(identity=worker.BUILD_ID,manifest_sha256='b'*64,files=6,
                                 payload_bytes=6,unmounted=True))
        return value,None

    def accept(self,worker,protocol,value,prior):
        with patch.object(worker,'producer_result',return_value=prior), \
             patch.object(worker,'custody',return_value={'manifest_sha256':'b'*64}):
            return protocol.accept(value)

    def test_producer_and_consumer_require_each_executed_control(self):
        for role in ['producer','consumer']:
            with self.subTest(role=role):
                worker,protocol=self.protocol(role);value,prior=self.success(worker,protocol)
                self.assertEqual(self.accept(worker,protocol,value,prior),'result')
            for missing in ['reporting-controls','runner-teardown-exception']:
                with self.subTest(role=role,missing=missing):
                    worker,protocol=self.protocol(role);value,prior=self.success(worker,protocol)
                    del protocol.observations[missing]
                    with self.assertRaises(RuntimeError):self.accept(worker,protocol,value,prior)
            for bad in [{'passed':False,'exit_code':0},{'passed':True,'exit_code':True},
                        {'passed':True,'exit_code':1}]:
                with self.subTest(role=role,bad=bad):
                    _,protocol=self.protocol(role)
                    with self.assertRaises(RuntimeError):self.observation(protocol,'reporting-controls',bad)
            _,protocol=self.protocol(role)
            with self.assertRaises(ValueError):self.observation(protocol,'runner-teardown-exception',outcome('pass'))

    def test_control_nonzero_is_candidate_only_with_safe_cleanup_and_resources(self):
        worker=dict(checks={'host_pre_resume':True},service_result='exit-code',
                    cleanup={'readonly_inputs_unchanged':True},
                    resource_observations={'memory.events':'oom 0\noom_kill 0','pids.events':'max 0'},
                    guest_report_untrusted={'ok':False,'error':'reporting-controls: exit 1\nassertion failed'})
        self.assertEqual(common.outcome({}, {'producer':worker},True),1)
        for error in ['reporting-controls: deadline exceeded', 'reporting-controls: exit 1\nNo space left',
                      'runner-teardown-exception: exit 0\nunexpected success',
                      'reporting-controls: missing binary']:
            broken=copy.deepcopy(worker);broken['guest_report_untrusted']['error']=error
            self.assertEqual(common.outcome({}, {'producer':broken},True),2)
        self.assertEqual(common.outcome({}, {'producer':worker},False),2)
