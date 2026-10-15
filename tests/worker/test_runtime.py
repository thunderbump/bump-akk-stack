"""Trusted Python/fake QEMU controls. These tests do not qualify a real VM or confinement."""
import json
import os
from pathlib import Path
import pwd
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'validation/worker'))
import runtime


class Readiness(unittest.TestCase):
    def test_enforcing_profile_accepts_only_known_unconfined_stack_forms(self):
        labels = {
            'eqemu-validator (enforce)': True,
            'eqemu-validator//&unconfined (enforce)': True,
            'unconfined//&eqemu-validator (enforce)': True,
            'unconfined': False,
            'unconfined (enforce)': False,
            'eqemu-validator (complain)': False,
            'eqemu-validator//&unconfined (complain)': False,
            'eqemu-validator//&unconfined (mixed)': False,
            'eqemu-validator-extra (enforce)': False,
            'eqemu-validator//child (enforce)': False,
            'eqemu-validator//&other (enforce)': False,
            'eqemu-validator//&unconfined//&other (enforce)': False,
        }
        limits = dict.fromkeys(('memory.max', 'pids.max'), '64')
        limits.update({'memory.swap.max': '0', 'cpu.max': '200000 100000',
                       'no_new_privileges': '1', 'effective_capabilities': '0'})
        base = Mock()
        base.stat.return_value.st_size = 1
        value = {'base_image': '/public/base', 'submitter': 'submitter'}
        with patch.object(runtime, 'invocation', return_value='a'*32), \
                patch.object(runtime, 'resource_state', return_value=limits), \
                patch.object(runtime, 'root_file', return_value=base), \
                patch.object(runtime.os.path, 'isfile', return_value=True), \
                patch.object(runtime.os, 'access', side_effect=lambda path, mode: path != '/home/submitter'), \
                patch.object(runtime.os, 'open', return_value=42), \
                patch.object(runtime.os, 'close'), \
                patch.object(runtime.pwd, 'getpwnam', return_value=Mock(pw_dir='/home/submitter')):
            for label, expected in labels.items():
                with self.subTest(label=label), patch.object(runtime.Path, 'read_text', return_value=label):
                    result = runtime.ready(value)
                    self.assertEqual(result['observed']['apparmor'], label)
                    self.assertIs(result['checks']['apparmor'], expected)
                    self.assertEqual(result['exit_code'], 0 if expected else 2)
                    self.assertFalse(result['vm_started'])


class Runtime(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        env=patch.dict(os.environ,INVOCATION_ID='a'*32);env.start();self.addCleanup(env.stop)
        self.state = self.root/'state'; self.state.mkdir(mode=0o700)
        self.base = self.root/'base'; self.base.write_bytes(b'trusted tiny base fixture')
        self.value = dict(version=1, user=pwd.getpwuid(os.geteuid()).pw_name,
                          worker_uid=os.geteuid(), worker_gid=os.getegid(), state_dir=str(self.state),
                          code_dir=str(ROOT), submitter=pwd.getpwuid(os.geteuid()).pw_name,
                          socket=str(self.root/'socket'), base_image=str(self.base))
        self.tools = self.root/'tools'; self.tools.mkdir()
        tool = self.tools/'prepare'
        tool.write_text('#!'+sys.executable+'\nimport pathlib,sys\n'
                        'args=sys.argv[1:]\npath=pathlib.Path(args[-2] if args[0]=="create" else args[1])\npath.touch()\n')
        tool.chmod(0o700)
        qemu = self.tools/'qemu'
        qemu.write_text('#!'+sys.executable+'\n'+'''import json,os,pathlib,re,sys,time
cfg=json.loads(pathlib.Path('user-data').read_text().split('\\n',1)[1])
script=cfg['write_files'][0]['content']
print('FAKE_QEMU_PID '+str(os.getpid()),flush=True)
if 'sleep 600' in script:time.sleep(30)
match=re.search(r"EQEMU_WORKER_RESULT (.+)' >/dev/ttyS0",script)
if match:print('EQEMU_WORKER_RESULT '+match.group(1),flush=True)
''')
        qemu.chmod(0o700)
        for name, value in [('QEMU_IMG',str(tool)),('GENISOIMAGE',str(tool)),('QEMU',str(qemu)),('SECONDS',2)]:
            p=patch.object(runtime,name,value);p.start();self.addCleanup(p.stop)
        for name, replacement in [('ready',lambda _:dict(exit_code=0)),('root_file',lambda path:Path(path)),
                                  ('service_processes',lambda:[os.getpid()])]:
            p=patch.object(runtime,name,replacement);p.start();self.addCleanup(p.stop)
        self.server, self.client = socket.socketpair()
        self.addCleanup(self.server.close);self.addCleanup(self.client.close)

    def run_control(self, control):
        result=runtime.run_vm(self.value,self.server,control)
        self.assertFalse((self.state/'active.json').exists())
        self.assertFalse(any(p.is_dir() for p in self.state.iterdir()))
        self.assertEqual(json.loads((self.state/'last-result.json').read_text()),result)
        return result

    def test_pass_and_assertion_have_real_process_result_and_owned_teardown(self):
        for control, code in [('pass',0),('assertion',1)]:
            with self.subTest(control=control):
                result=self.run_control(control)
                self.assertEqual(result['exit_code'],code,result)
                self.assertTrue(result['cleanup_complete'])
                self.assertTrue(result['vm_started'])
                self.assertEqual(result['worker_uid'],os.geteuid())
                self.assertEqual(result['scope'],'worker-smoke')
                self.assertIsNone(result['candidate'])

    def test_missing_result_and_deadline_are_infrastructure_not_candidate_failure(self):
        with patch.object(runtime,'SECONDS',.15):
            for control in ('missing-result','deadline'):
                with self.subTest(control=control):
                    result=self.run_control(control)
                    self.assertEqual(result['exit_code'],2,result)
                    self.assertTrue(result['cleanup_complete'])

    def test_client_death_cancels_process_and_persists_final_report(self):
        result={}
        thread=threading.Thread(target=lambda:result.update(runtime.run_vm(self.value,self.server,'deadline')))
        thread.start()
        time.sleep(.15);self.client.close();thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result['exit_code'],2)
        self.assertIn('Client disconnected',result['error'])
        self.assertTrue(result['cleanup_complete'])
        self.assertEqual(json.loads((self.state/'last-result.json').read_text()),result)

    def test_qemu_argv_forces_kvm_no_nic_and_owns_no_service_socket(self):
        def simulate_started(*args):
            args[-1](12345)
            return 0
        with patch.object(runtime,'supervise',side_effect=simulate_started) as supervise:
            result=self.run_control('pass')
        argv=supervise.call_args.args[0]
        self.assertIn('q35,accel=kvm',argv)
        self.assertEqual(argv[argv.index('-nic')+1],'none')
        self.assertEqual(argv[argv.index('-monitor')+1],'none')
        self.assertNotIn('-daemonize',argv)
        self.assertEqual(argv[argv.index('-object')+1],
                         'main-loop,id=main-loop,thread-pool-min=0,thread-pool-max=8')
        self.assertEqual(argv[argv.index('-sandbox')+1],
                         'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny')
        self.assertEqual(result['exit_code'],0)

    def test_seed_build_uses_iso_builder_directly_in_owned_scratch(self):
        with patch.object(runtime, 'tool', wraps=runtime.tool) as tool:
            result = self.run_control('pass')
        calls = [call.args[0] for call in tool.call_args_list]
        self.assertEqual(len(calls), 2)
        scratch = self.state / result['run_id'] / 'scratch'
        self.assertEqual(calls[1][1:], [
            '-output', str(scratch / 'seed.iso'), '-volid', 'cidata', '-joliet', '-rock',
            str(scratch / 'user-data'), str(scratch / 'meta-data'),
        ])

    def test_qemu_failure_reports_bounded_stderr_and_keeps_owned_cleanup(self):
        Path(runtime.QEMU).write_text('#!' + sys.executable + '\n'
            'import sys,time\n'
            'sys.stderr.write("x"*2000 + " QEMU_FATAL_CONTROL\\n")\n'
            'sys.stderr.flush()\n'
            'time.sleep(.1)\n'
            'raise SystemExit(7)\n')
        result = self.run_control('pass')
        self.assertEqual(result['exit_code'], 2)
        self.assertTrue(result['cleanup_complete'])
        self.assertIn('7', result['error'])
        self.assertIn('QEMU_FATAL_CONTROL', result['error'])
        self.assertLessEqual(len(result['error']), 1000)

    def test_output_overflow_and_duplicate_or_malformed_completion_never_pass(self):
        for output in ('x'*(runtime.LOG_LIMIT+1), 'EQEMU_WORKER_RESULT {}\n',
                       'EQEMU_WORKER_RESULT {}\nEQEMU_WORKER_RESULT {}\n'):
            with self.subTest(prefix=output[:30]):
                # Put large data in a temporary trusted script rather than exceeding argv limits.
                script=self.root/'output.py';script.write_text('import sys\nsys.stdout.write('+repr(output)+')\n')
                with self.assertRaises((RuntimeError,ValueError)):
                    runtime.supervise([sys.executable,'-I',str(script)],self.root,self.root/'output.log',
                                      self.server,time.monotonic()+2,'a'*32)
                (self.root/'output.log').unlink()

    def test_uncertain_process_cleanup_cannot_claim_clean_result(self):
        with patch.object(runtime,'supervise',side_effect=runtime.CleanupError('owned group remains')):
            result=runtime.run_vm(self.value,self.server)
        self.assertEqual(result['exit_code'],2)
        self.assertFalse(result['cleanup_complete'])
        self.assertTrue((self.state/'active.json').exists())
        self.assertEqual(runtime.cleanup(self.value),0)
        self.assertFalse((self.state/'active.json').exists())
        recovery=json.loads((self.state/'last-result.json').read_text())
        self.assertEqual(recovery['exit_code'],2)
        self.assertFalse(recovery['cleanup_complete'])
        self.assertTrue(recovery['scratch_removed'])

    def test_stop_hook_retains_scratch_if_another_service_process_remains(self):
        with patch.object(runtime,'supervise',side_effect=runtime.CleanupError('owned group remains')):
            runtime.run_vm(self.value,self.server)
        active=json.loads((self.state/'active.json').read_text())
        with patch.object(runtime,'service_processes',return_value=[os.getpid(),os.getpid()+1]):
            self.assertEqual(runtime.cleanup(self.value),2)
        self.assertTrue((self.state/active['run_id']/'scratch').exists())
        result=json.loads((self.state/'last-result.json').read_text())
        self.assertFalse(result['cleanup_complete'])
        self.assertFalse(result['scratch_removed'])
        self.assertFalse(result['only_cleanup_process_remains'])
        self.assertTrue((self.state/'active.json').exists())

    def test_controller_death_records_actual_child_before_sigkill(self):
        # Suppress only the destructive self-kill: the child and marker are real.
        original_kill=os.kill
        snapshots=[]
        def record_kill(pid,signum):
            self.assertEqual((pid,signum),(os.getpid(),signal.SIGKILL))
            active=json.loads((self.state/'active.json').read_text())
            original_kill(active['qemu_pid'],0)
            snapshots.append(active)
            raise RuntimeError('trusted test intercepted controller SIGKILL')
        with patch.object(runtime.os,'kill',side_effect=record_kill):
            result=self.run_control('controller-death')
        self.assertEqual(len(snapshots),1)
        self.assertEqual(snapshots[0]['control'],'controller-death')
        self.assertIsInstance(snapshots[0]['qemu_pid'],int)
        self.assertTrue(result['vm_started'])
        self.assertIn('intercepted',result['error'])
        self.assertEqual(result['exit_code'],2)

    def test_last_result_observation_does_not_change_persisted_or_active_state(self):
        report=self.run_control('pass')
        before={p.name:p.read_bytes() for p in self.state.iterdir() if p.is_file()}
        self.client.sendall(b'{"version":1,"operation":"last-result"}\n')
        result=runtime.request(self.server,self.value)
        self.assertEqual(result['result'],report)
        self.assertEqual(result['operation'],'last-result')
        self.assertEqual(result['exit_code'],0)
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.state.iterdir() if p.is_file()})

    def test_read_only_check_stop_hook_preserves_empty_state_and_older_invocation(self):
        self.assertEqual(runtime.cleanup(self.value),0)
        self.assertEqual(list(self.state.iterdir()),[])
        job=self.state/('b'*32);job.mkdir();(job/'scratch').mkdir()
        runtime.atomic_json(self.state/'active.json',dict(run_id='b'*32,invocation_id='c'*32))
        before={str(p):p.read_bytes() for p in self.state.rglob('*') if p.is_file()}
        self.assertEqual(runtime.cleanup(self.value),0)
        self.assertEqual(before,{str(p):p.read_bytes() for p in self.state.rglob('*') if p.is_file()})
        self.assertTrue((job/'scratch').exists())
        self.assertFalse((self.state/'worker.lock').exists())

    def test_actual_reaping_uncertainty_remains_distinct(self):
        process=Mock(pid=12345)
        process.wait.side_effect=subprocess.TimeoutExpired('fake qemu',10)
        with patch.object(runtime.os,'killpg'), self.assertRaises(runtime.CleanupError):
            runtime.stop_process(process)

    def test_signal_interrupting_real_child_cleanup_keeps_scratch_and_nonpass_receipt(self):
        original_popen=subprocess.Popen
        original_killpg=os.killpg
        captured=[]
        def spawn(*args,**kwargs):
            process=original_popen(*args,**kwargs)
            if args[0][0]==runtime.QEMU:captured.append(process)
            return process
        def interrupt_kill(group,signum):
            if captured and group==captured[-1].pid and signum==signal.SIGKILL:
                os.kill(os.getpid(),signal.SIGUSR1)
            return original_killpg(group,signum)
        def keyboard_interrupt(*_):raise KeyboardInterrupt()
        def system_exit(*_):raise SystemExit(2)
        previous=signal.getsignal(signal.SIGUSR1)
        try:
            for handler in (runtime.interrupted,keyboard_interrupt,system_exit):
                with self.subTest(handler=handler.__name__):
                    signal.signal(signal.SIGUSR1,handler)
                    try:
                        with patch.object(runtime.subprocess,'Popen',side_effect=spawn), \
                             patch.object(runtime.os,'killpg',side_effect=interrupt_kill), \
                             patch.object(runtime,'SECONDS',.15):
                            result=runtime.run_vm(self.value,self.server,'deadline')
                        self.assertTrue(captured,'trusted fake QEMU must actually start')
                        self.assertIsNone(captured[-1].poll(),'signal must interrupt before the real child is killed/reaped')
                        self.assertEqual(result['exit_code'],2)
                        self.assertFalse(result['cleanup_complete'])
                        active=json.loads((self.state/'active.json').read_text())
                        self.assertTrue((self.state/active['run_id']/'scratch').is_dir())
                        self.assertEqual(json.loads((self.state/'last-result.json').read_text()),result)
                    finally:
                        # The production service owns rescue after uncertain cleanup. This trusted
                        # test explicitly reaps its still-live child before exercising that hook.
                        for process in captured:
                            if process.poll() is None:
                                original_killpg(process.pid,signal.SIGKILL)
                            process.wait(timeout=3)
                            if process.stdout is not None:process.stdout.close()
                        captured.clear()
                        runtime.cleanup(self.value)
        finally:signal.signal(signal.SIGUSR1,previous)

    def test_socket_activated_child_controller_survives_client_death_for_cleanup(self):
        script=self.root/'controller.py'
        script.write_text('import json,sys\nfrom pathlib import Path\n'
            +'sys.path.insert(0,'+repr(str(ROOT/'validation/worker'))+')\nimport runtime\n'
            +'cfg=json.loads(sys.argv[1])\nruntime.config=lambda _:cfg\nruntime.ready=lambda _:dict(exit_code=0)\n'
            +'runtime.root_file=lambda value:Path(value)\n'
            +'runtime.QEMU='+repr(runtime.QEMU)+'\nruntime.QEMU_IMG='+repr(runtime.QEMU_IMG)+'\n'
            +'runtime.GENISOIMAGE='+repr(runtime.GENISOIMAGE)+'\nruntime.SECONDS=3\n'
            +"raise SystemExit(runtime.main(['serve']))\n")
        process=subprocess.Popen([sys.executable,'-I',str(script),json.dumps(self.value)],
                                 stdin=self.server,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        self.server.close()
        try:
            self.client.sendall(b'{"version":1,"operation":"smoke","control":"deadline"}\n')
            end=time.monotonic()+2;pid=None
            while time.monotonic()<end:
                logs=list(self.state.glob('*/serial.log'))
                if logs:
                    lines=logs[0].read_text().splitlines()
                    if lines:
                        pid=int(lines[0].removeprefix('FAKE_QEMU_PID '));break
                time.sleep(.01)
            self.assertIsNotNone(pid,'fake QEMU must actually start before disconnect')
            self.client.close()
            _,stderr=process.communicate(timeout=3)
            self.assertEqual(process.returncode,2,stderr)
            with self.assertRaises(ProcessLookupError):os.kill(pid,0)
            result=json.loads((self.state/'last-result.json').read_text())
            self.assertTrue(result['cleanup_complete'],result)
            self.assertEqual(result['exit_code'],2)
            self.assertFalse((self.state/'active.json').exists())
        finally:
            if process.poll() is None:
                self.client.close()
                try:process.wait(timeout=4)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            process.stderr.close()

    def test_single_lock_refuses_competing_smoke_without_creating_job(self):
        lock=runtime.acquire(self.value)
        try:
            with self.assertRaisesRegex(RuntimeError,'active'):
                runtime.run_vm(self.value,self.server)
        finally:os.close(lock)
        self.assertEqual([p.name for p in self.state.iterdir()],['worker.lock'])

    def test_protocol_requires_exact_peer_and_finite_request(self):
        self.client.sendall(b'{"version":1,"operation":"check"}\n')
        with patch.object(runtime,'ready',return_value={'read_only':True}) as ready:
            self.assertEqual(runtime.request(self.server,self.value),{'read_only':True})
            ready.assert_called_once_with(self.value)
        wrong=dict(self.value,submitter='root' if os.geteuid()!=0 else 'nobody')
        with self.assertRaisesRegex(ValueError,'peer'):
            runtime.request(self.server,wrong)
        self.client.sendall(b'{"version":1,"operation":"run-shell","command":"id"}\n')
        with self.assertRaisesRegex(ValueError,'Unsupported'):
            runtime.request(self.server,self.value)

    def test_root_worker_identity_refuses_even_matching_config(self):
        path=self.root/'config.json';path.write_text(json.dumps(dict(self.value,user='root',worker_uid=0,worker_gid=0)))
        with patch.object(runtime.os,'geteuid',return_value=0), self.assertRaisesRegex(ValueError,'nonroot'):
            runtime.config(path)


if __name__=='__main__':unittest.main()
