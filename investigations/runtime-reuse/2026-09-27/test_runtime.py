"""Synthetic process and bounded evidence checks. Never execute the guest scenario on the host."""
import importlib.util
import json
import inspect
import re
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parent
LOCAL=Path('/home/bump/.local/state/eqemu-vm-proof/runtime-reuse-inputs-02')

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

G=load('scenario_guest',LOCAL/'guest-runtime.py')
W=load('scenario_worker',LOCAL/'consumer-worker.py')
NONCE='1'*32
WARNING="2026-09-27  0:08:16 22 [Warning] Aborted connection 22 to db: 'eqemu_proof' user: 'eqemu' host: '127.0.0.1' (Got an error reading communication packets)"


def wait_for(check):
    end=time.monotonic()+3
    while time.monotonic()<end:
        if check():return
        time.sleep(.01)
    raise RuntimeError('Synthetic control timed out')


class Processes(unittest.TestCase):
    def spawn(self,folder,code,**kw):
        return G.CapturedService('synthetic',[sys.executable,'-u','-c',code],folder,Path(folder)/'console.log',dict(os.environ),**kw)

    def test_exact_database_warning_does_not_kill_service(self):
        with tempfile.TemporaryDirectory() as folder:
            service=self.spawn(folder,'import signal,sys,time; signal.signal(signal.SIGTERM,lambda *_:sys.exit(0)); print('+repr(WARNING)+'); time.sleep(60)',observe=G.observe)
            try:
                wait_for(lambda:service.tail.total>0);service.live();time.sleep(.05);service.live()
            finally:result=service.stop(timeout=1)
            self.assertEqual(result['return_code'],0);self.assertFalse(result['forced'])
            self.assertIn('Aborted connection',service.tail.export()['text'])

    def test_early_zero_and_nonzero_exits_remain_failure(self):
        for code in [0,3]:
            with self.subTest(code=code),tempfile.TemporaryDirectory() as folder:
                service=self.spawn(folder,'print("failure context");raise SystemExit('+str(code)+')')
                wait_for(lambda:service.proc.poll() is not None)
                with self.assertRaisesRegex(RuntimeError,'unexpected exit '+str(code)):service.live()
                result=service.stop();self.assertTrue(result['early_exit']);self.assertEqual(result['return_code'],code)
                self.assertIn('failure context',service.tail.export()['text'])

    def test_hung_shutdown_is_forced_and_not_success(self):
        with tempfile.TemporaryDirectory() as folder:
            service=self.spawn(folder,'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print("ready");time.sleep(60)')
            wait_for(lambda:service.tail.total>0);result=service.stop(timeout=.1)
            self.assertTrue(result['forced']);self.assertEqual(result['return_code'],-9)

    def test_output_limit_is_failure_with_owned_shutdown(self):
        with tempfile.TemporaryDirectory() as folder:
            service=self.spawn(folder,'import time;print("x"*1000);time.sleep(60)',cap=128)
            try:
                wait_for(lambda:service.error is not None)
                with self.assertRaisesRegex(RuntimeError,'output limit'):service.live()
            finally:service.stop(timeout=.1)

    def test_failed_start_event_keeps_service_owned(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(G,'SERVICES',[]),patch.object(G,'event',side_effect=RuntimeError('export failed')):
            with self.assertRaisesRegex(RuntimeError,'export failed'):
                G.Service('synthetic',[sys.executable,'-c','import time;time.sleep(60)'],folder,Path(folder)/'console.log')
            self.assertEqual(len(G.SERVICES),1)
            service=G.SERVICES[0]
            with self.assertRaisesRegex(RuntimeError,'export failed'):service.stop(timeout=1)
            self.assertTrue(service.stop_complete)

    def test_failed_signal_allows_cleanup_retry(self):
        with tempfile.TemporaryDirectory() as folder:
            service=self.spawn(folder,'import time;print("ready");time.sleep(60)')
            wait_for(lambda:service.tail.total>0)
            try:
                with patch.object(G.os,'killpg',side_effect=PermissionError('synthetic signal failure')):
                    with self.assertRaises(PermissionError):service.stop(timeout=.1)
                self.assertFalse(service.stop_complete)
            finally:service.stop(timeout=1)
            self.assertTrue(service.stop_complete)

    def test_surviving_descendant_is_reported_as_forced(self):
        with tempfile.TemporaryDirectory() as folder:
            service=self.spawn(folder,'import subprocess,sys;subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]);print("child started")')
            try:
                wait_for(lambda:service.proc.poll() is not None)
            finally:result=service.stop(timeout=1)
            self.assertTrue(result['forced']);self.assertTrue(result['capture_complete'])

    def test_connection_loss_fails_health_check(self):
        service=types.SimpleNamespace(live=lambda:None,pid=123,flags=set())
        with patch.object(G,'guard'),patch.object(G,'connection',return_value=False):
            with self.assertRaisesRegex(RuntimeError,'connection absent'):G.check_health(types.SimpleNamespace(service=service),service,service)

    def test_world_listener_accepts_wildcard_and_loopback(self):
        for address in ['00000000','0100007F']:
            with self.subTest(address=address):
                self.assertTrue(G.world_listener_ready('header\n0: '+address+':2328 00000000:0000 0A\n'))

    def test_world_listener_rejects_wrong_port_address_and_state(self):
        for local,state in [('00000000:2329','0A'),('0200007F:2328','0A'),('00000000:2328','01'),('0100007F:2328','06')]:
            with self.subTest(local=local,state=state):
                self.assertFalse(G.world_listener_ready('header\n0: '+local+' 00000000:0000 '+state+'\n'))
        self.assertFalse(G.world_listener_ready('header\n'))

    def test_readiness_is_not_a_port_open_phrase(self):
        service=types.SimpleNamespace(name='zone',flags=set())
        G.observe(service,'Listening for clients; ready')
        self.assertEqual(service.flags,set())
        G.observe(service,'Booting [poknowledge] ([202]:[0])')
        G.observe(service,'Zone booted successfully zone_id [202]')
        G.observe(service,'Received Message SyncWorldTime')
        self.assertEqual(service.flags,{'instance','zone_boot','world_time'})


class Diagnostics(unittest.TestCase):
    def test_late_registered_split_secret_is_scrubbed_and_bounded(self):
        tail=G.DiagnosticTail();tail.capacity=tail.limit+1024
        tail.feed(b'x'*40000+b' split-');tail.feed(b'secret failure context\x1b')
        frames=[]
        with patch.object(G,'SECRET_VALUES',['split-secret']),patch.object(G,'DIAGNOSTIC_BYTES',0),patch.object(G.B,'emit',side_effect=frames.append):
            G.diagnostic('database',tail)
        text=''.join(frame['text'] for frame in frames)
        self.assertNotIn('split-secret',text);self.assertNotIn('\x1b',text)
        self.assertIn('failure context',text);self.assertLessEqual(len(text.encode()),32768)
        self.assertTrue(frames[0]['meta']['truncated'])

    def test_export_failure_does_not_replace_first_failure(self):
        with patch.object(G,'FIRST_FAILURE',None),patch.object(G,'LATER_ERRORS',[]),patch.object(G,'event',side_effect=RuntimeError('reader blocked')):
            G.failure(RuntimeError('original assertion'));G.failure(RuntimeError('shutdown failed'))
            self.assertEqual(G.FIRST_FAILURE['reason'],'original assertion')
            self.assertIn('reader blocked',G.LATER_ERRORS);self.assertIn('shutdown failed',G.LATER_ERRORS)

    def test_expired_workload_still_has_bounded_export_grace(self):
        with patch.object(G.B,'DEADLINE',1),patch.object(G.B,'SEND_DEADLINE',float('inf')),patch.object(G.time,'monotonic',return_value=100):
            self.assertEqual(G.begin_diagnostic_export(),115)
            self.assertEqual(G.B.SEND_DEADLINE,113)

    def test_host_collection_leaves_guest_cleanup_and_export_time(self):
        host=inspect.getsource(W.collect_build);guest=inspect.getsource(G.main)
        host_budget=int(re.search(r"ready_at.*deadline=time.monotonic\(\)\+(\d+)",host).group(1))
        guest_budget=int(re.search(r"B.DEADLINE=time.monotonic\(\)\+(\d+)",guest).group(1))
        self.assertGreaterEqual(host_budget-guest_budget,3*40+15+15)
        self.assertLess(host_budget+600+30,2700)

    def protocol(self):
        protocol=W.BuildProtocol(NONCE)
        protocol.accept({'kind':'ready','nonce':None,'manifest_sha256':W.MANIFEST_SHA,'experiment_sha256':W.EXPERIMENT_SHA})
        protocol.reuse_verified=True
        return protocol

    def frame(self,index=0,chunks=1,text='known context'):
        return {'kind':'diagnostic','nonce':NONCE,'stream':'database','index':index,'chunks':chunks,'text':text,
                'meta':{'input_bytes':13,'retained_bytes':13,'truncated':False}}

    def result(self):return {'kind':'result','nonce':NONCE,'version':1,'ok':True,'diagnostic_only':True,'accepted':False,
                            'scenario':{'checks_completed':True},'first_failure':None,'later_errors':[],'evidence_complete':True}

    def test_complete_diagnostic_run_stays_unaccepted(self):
        protocol=self.protocol();protocol.accept(self.frame());protocol.accept(self.result())
        self.assertFalse(protocol.result['accepted']);self.assertTrue(protocol.result['diagnostic_only'])

    def test_missing_duplicate_wrong_run_and_truncated_evidence_rejected(self):
        with self.assertRaises(RuntimeError):self.protocol().accept(self.result())
        protocol=self.protocol();protocol.accept(self.frame(chunks=2))
        with self.assertRaises(RuntimeError):protocol.accept(self.result())
        with self.assertRaises(RuntimeError):protocol.accept(self.frame(chunks=2))
        with self.assertRaises(RuntimeError):self.protocol().accept(dict(self.frame(),nonce='2'*32))

    def test_oversized_stream_and_promotion_rejected(self):
        with self.assertRaises(RuntimeError):self.protocol().accept(self.frame(text='x'*1025))
        protocol=self.protocol();protocol.accept(self.frame())
        with self.assertRaises(RuntimeError):protocol.accept(dict(self.result(),accepted=True))


if __name__=='__main__':unittest.main()
