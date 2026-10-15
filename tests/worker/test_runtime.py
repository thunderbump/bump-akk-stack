"""Trusted Python/fake QEMU controls. These tests do not qualify a real VM or confinement."""
import json
import os
from pathlib import Path
import pwd
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


class Runtime(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root/'state'; self.state.mkdir(mode=0o700)
        self.base = self.root/'base'; self.base.write_bytes(b'trusted tiny base fixture')
        self.value = dict(version=1, user=pwd.getpwuid(os.geteuid()).pw_name,
                          worker_uid=os.geteuid(), worker_gid=os.getegid(), state_dir=str(self.state),
                          code_dir=str(ROOT), submitter=pwd.getpwuid(os.geteuid()).pw_name,
                          socket=str(self.root/'socket'), base_image=str(self.base))
        self.tools = self.root/'tools'; self.tools.mkdir()
        tool = self.tools/'prepare'
        tool.write_text('#!'+sys.executable+'\nimport pathlib,sys\n'
                        'args=sys.argv[1:]\npath=pathlib.Path(args[-2] if args[0]=="create" else args[0])\npath.touch()\n')
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
        for name, value in [('QEMU_IMG',str(tool)),('CLOUD_LOCALDS',str(tool)),('QEMU',str(qemu)),('SECONDS',2)]:
            p=patch.object(runtime,name,value);p.start();self.addCleanup(p.stop)
        for name, replacement in [('ready',lambda _:dict(exit_code=0)),('root_file',lambda path:Path(path))]:
            p=patch.object(runtime,name,replacement);p.start();self.addCleanup(p.stop)
        self.server, self.client = socket.socketpair()
        self.addCleanup(self.server.close);self.addCleanup(self.client.close)

    def run_control(self, control):
        result=runtime.smoke(self.value,self.server,control)
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
        thread=threading.Thread(target=lambda:result.update(runtime.smoke(self.value,self.server,'deadline')))
        thread.start()
        time.sleep(.15);self.client.close();thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result['exit_code'],2)
        self.assertIn('Client disconnected',result['error'])
        self.assertTrue(result['cleanup_complete'])
        self.assertEqual(json.loads((self.state/'last-result.json').read_text()),result)

    def test_qemu_argv_forces_kvm_no_nic_and_owns_no_service_socket(self):
        with patch.object(runtime,'supervise',return_value=0) as supervise:
            result=self.run_control('pass')
        argv=supervise.call_args.args[0]
        self.assertIn('q35,accel=kvm',argv)
        self.assertEqual(argv[argv.index('-nic')+1],'none')
        self.assertEqual(argv[argv.index('-monitor')+1],'none')
        self.assertNotIn('-daemonize',argv)
        self.assertEqual(argv[argv.index('-sandbox')+1],
                         'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny')
        self.assertEqual(result['exit_code'],0)

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
            result=runtime.smoke(self.value,self.server)
        self.assertEqual(result['exit_code'],2)
        self.assertFalse(result['cleanup_complete'])
        self.assertTrue((self.state/'active.json').exists())
        self.assertEqual(runtime.cleanup(self.value),0)
        self.assertFalse((self.state/'active.json').exists())
        recovery=json.loads((self.state/'last-result.json').read_text())
        self.assertEqual(recovery['exit_code'],2)
        self.assertFalse(recovery['cleanup_complete'])
        self.assertTrue(recovery['scratch_removed'])

    def test_actual_reaping_uncertainty_remains_distinct(self):
        process=Mock(pid=12345)
        process.wait.side_effect=subprocess.TimeoutExpired('fake qemu',10)
        with patch.object(runtime.os,'killpg'), self.assertRaises(runtime.CleanupError):
            runtime.stop_process(process)

    def test_socket_activated_child_controller_survives_client_death_for_cleanup(self):
        script=self.root/'controller.py'
        script.write_text('import json,sys\nfrom pathlib import Path\n'
            +'sys.path.insert(0,'+repr(str(ROOT/'validation/worker'))+')\nimport runtime\n'
            +'cfg=json.loads(sys.argv[1])\nruntime.config=lambda _:cfg\nruntime.ready=lambda _:dict(exit_code=0)\n'
            +'runtime.root_file=lambda value:Path(value)\n'
            +'runtime.QEMU='+repr(runtime.QEMU)+'\nruntime.QEMU_IMG='+repr(runtime.QEMU_IMG)+'\n'
            +'runtime.CLOUD_LOCALDS='+repr(runtime.CLOUD_LOCALDS)+'\nruntime.SECONDS=3\n'
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
                runtime.smoke(self.value,self.server)
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
