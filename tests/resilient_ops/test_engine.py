import base64
import copy
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('resilient_engine', Path(__file__).parents[2]/'validation/resilient_ops/engine.py')
e = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(e)


class Manager:
    def __init__(self):
        self.calls = []
        self.fail_stop = self.fail_start = False
        self.wait = None

    def observe(self, target):
        return {u: {'active': 'inactive', 'populated': False} for u in target['units']}

    def stop(self, target):
        self.calls.append('stop')
        if self.wait:
            self.wait[0].set()
            self.wait[1].wait(3)
        if self.fail_stop:
            raise e.Rejected('stuck')

    def start(self, target, before):
        self.calls.append('start')
        if self.fail_start:
            self.fail_start = False
            raise e.Rejected('health')


class Crash(BaseException):
    pass


class EngineTests(unittest.TestCase):
    def setUp(self):
        # /tmp is intentionally not a protected authority ancestor. Patch only this
        # check in filesystem simulations; test the real check separately.
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('store', 'a', 'b'):
            (self.root/name).mkdir(mode=0o711)
        self.peer = (os.getuid(), os.getgid())
        target = {'actions': ['publish','revert','recover'], 'resources':['a'], 'root':str(self.root/'a'),
                  'units':['fixture-a.service'], 'service_uid':os.getuid() or 1000, 'timeout':1,
                  'files':['worker.py','binding.json'], 'max_bytes':4096, 'max_files':20}
        other = {**target,'resources':['b'],'root':str(self.root/'b'),'units':['fixture-b.service']}
        self.policy = {'peers':[{'uid':self.peer[0],'gid':self.peer[1],'methods':['prepare','execute','status'],
                                'targets':['a','b'],'actions':['publish','revert','recover']}], 'targets':{'a':target,'b':other}}
        self.guard = patch.object(e, 'protected')
        self.guard.start()
        self.addCleanup(self.guard.stop)
        self.manager = Manager()
        self.engine = self.make()

    def make(self, fault=None):
        return e.Engine(self.policy, self.root/'store', self.manager, fault, trusted_uid=os.getuid())

    def call(self, request):
        return self.engine.handle(request, self.peer)

    def prepare(self, rid='p', target='a', generation=0, **extra):
        req = {'method':'prepare','request_id':rid,'target':target,'action':'publish','generation':generation,
               'artifact':{'worker.py':base64.b64encode(b'harmless data').decode(), 'binding.json':'e30='}}
        req.update(extra)
        return self.call(req)['plan_id']

    def execute(self, pid, oid='op'):
        return self.call({'method':'execute','plan_id':pid,'operation_id':oid})

    def test_prepare_sealed_idempotent_stale_and_exact_files(self):
        pid = self.prepare()
        self.assertEqual(pid, self.prepare())
        with self.assertRaises(e.Rejected): self.prepare(artifact={})
        result = self.execute(pid)
        self.assertEqual(result['state'],'succeeded')
        self.assertEqual(result, self.execute(pid))
        with self.assertRaises(e.Rejected): self.execute(pid,'stale')
        self.assertEqual(self.manager.calls, ['stop','start'])

    def test_peer_and_action_authorization(self):
        with self.assertRaises(e.Rejected): self.engine.handle({'method':'status'},(123456,123456))
        self.policy['peers'][0]['actions'] = []
        with self.assertRaises(e.Rejected): self.prepare()

    def test_traversal_and_tampered_release(self):
        with self.assertRaises(e.Rejected): self.prepare(artifact={'../x':'YQ=='})
        pid = self.prepare('good')
        (self.root/'a/releases'/pid/'worker.py').write_text('changed')
        self.assertEqual(self.execute(pid)['state'],'failed')
        self.assertFalse((self.root/'a/current.json').exists())

    def test_health_compensation_is_still_failure(self):
        pid = self.prepare()
        self.manager.fail_start = True
        result = self.execute(pid)
        self.assertEqual(result['state'],'failed')
        self.assertFalse(result['recovery_required'])
        self.assertIsNone(e.read(self.root/'a/current.json')['release'])
        self.assertEqual(e.read(self.root/'a/current.json')['generation'],1)
        self.assertEqual(self.execute(self.prepare('next',generation=1),'next')['state'],'succeeded')

    def test_crash_each_boundary_never_replayed_and_unrelated_allowed(self):
        for boundary in ['accepted','stop-intent','stop-effect','stop-observed','publish-intent','publish-effect','publish-observed','health-intent','health-effect','health-observed','receipt-intent','receipt-written']:
            with self.subTest(boundary=boundary):
                # separate target generation per iteration, recover test covers unblocking
                with tempfile.TemporaryDirectory() as state:
                    original = self.root
                    self.root = Path(state)
                    for name in ['store','a','b']: (self.root/name).mkdir(mode=0o711)
                    for name in ['a','b']: self.policy['targets'][name]['root'] = str(self.root/name)
                    self.engine = self.make(lambda point: (_ for _ in ()).throw(Crash()) if point == boundary else None)
                    pid = self.prepare()
                    with self.assertRaises(Crash): self.execute(pid)
                    self.engine = self.make()
                    before = list(self.manager.calls)
                    result = self.execute(pid)
                    self.assertIn(result['state'],['uncertain','succeeded'])
                    self.assertEqual(before,self.manager.calls)
                    self.assertEqual(self.execute(self.prepare('other','b'),'other')['state'],'succeeded')
                    if result['state'] == 'uncertain':
                        gen = self.engine.current(self.policy['targets']['a'])['generation']
                        with self.assertRaises(e.Rejected): self.execute(self.prepare('blocked',generation=gen),'blocked')
                    self.root = original

    def test_recovery_keeps_history_and_allows_subsequent_work(self):
        self.manager.fail_stop = True
        pid = self.prepare()
        old = self.execute(pid)
        workspace = self.root/'a/workspaces/0'
        workspace.mkdir()
        (workspace/'failure.txt').write_text('original failure')
        self.manager.fail_stop = False
        recovery = self.prepare('r',action='recover',artifact={},recovery_of='op')
        self.assertEqual(self.execute(recovery,'recover')['state'],'succeeded')
        self.assertEqual(self.call({'method':'status','operation_id':'op'}), old)
        self.assertEqual((self.root/'a/evidence/0/workspace/failure.txt').read_text(),'original failure')
        self.assertEqual(self.execute(self.prepare('after',generation=1),'after')['state'],'succeeded')

    def test_prepare_lost_response_and_partial_fsync(self):
        self.engine = self.make(lambda point: (_ for _ in ()).throw(Crash()) if point=='prepare-sealed' else None)
        with self.assertRaises(Crash): self.prepare()
        self.engine = self.make()
        self.assertEqual(self.prepare(),self.prepare())
        pid = self.prepare()
        with patch.object(e.os,'fsync',side_effect=OSError('full')):
            with self.assertRaises(OSError): self.execute(pid)
        self.assertEqual(self.manager.calls,[])

    def test_concurrent_duplicate_status_and_resource_conflict(self):
        pid = self.prepare()
        ready, finish = threading.Event(),threading.Event()
        self.manager.wait=(ready,finish)
        result=[]
        thread=threading.Thread(target=lambda:result.append(self.execute(pid)))
        thread.start()
        self.assertTrue(ready.wait(2))
        self.assertEqual(self.call({'method':'status','operation_id':'op'})['state'],'running')
        with self.assertRaises(e.Rejected): self.execute(pid)
        with self.assertRaises(e.Rejected): self.execute(pid,'conflict')
        finish.set()
        thread.join(3)
        self.assertEqual(result[0]['state'],'succeeded')

    def test_protected_ancestors_reject_tmp(self):
        self.guard.stop()
        with self.assertRaises(e.Rejected): e.protected(self.root, os.getuid())
        self.guard.start()


if __name__ == '__main__': unittest.main()

class SocketTests(unittest.TestCase):
    setUp = EngineTests.setUp
    make = EngineTests.make
    call = EngineTests.call
    prepare = EngineTests.prepare
    execute = EngineTests.execute
    def serve(self, listener, crash_at=None):
        self.engine = self.make(lambda point: os._exit(71) if point == crash_at else None)
        conn, _ = listener.accept()
        with conn:
            raw = conn.makefile('rb').readline(8*1024*1024+1)
            import struct
            _, uid, gid = struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            result = self.engine.handle(json.loads(raw),(uid,gid))
            try: conn.sendall(e.canonical(result)+b'\n')
            except BrokenPipeError: pass

    def exchange(self, request, crash_at=None, disconnect=False, nnp=False):
        path = str(self.root/'wire.sock')
        Path(path).unlink(missing_ok=True)
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(path)
            listener.listen()
            ctx = multiprocessing.get_context('fork')
            process=ctx.Process(target=self.serve,args=(listener,crash_at))
            process.start()
            if nnp:
                import subprocess, sys
                program = '''import ctypes,json,socket,sys
assert ctypes.CDLL(None).prctl(38,1,0,0,0)==0
s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall(sys.argv[2].encode()+b'\\n')
print(s.makefile('rb').readline().decode())
'''
                response=subprocess.check_output([sys.executable,'-c',program,path,json.dumps(request)])
            else:
                with socket.socket(socket.AF_UNIX) as conn:
                    conn.connect(path)
                    conn.sendall(e.canonical(request)+b'\n')
                    response=b'' if disconnect else conn.makefile('rb').readline()
            process.join(4)
            self.assertFalse(process.is_alive())
            return json.loads(response) if response else None

    def test_real_socket_nonewprivs_and_lost_receipt(self):
        self.assertTrue(self.exchange({'method':'health'},nnp=True)['healthy'])
        pid=self.prepare()
        self.exchange({'method':'execute','operation_id':'wire','plan_id':pid},disconnect=True)
        outcome=self.exchange({'method':'status','operation_id':'wire'})
        self.assertEqual(outcome['state'],'succeeded')
        self.assertEqual(outcome,self.exchange({'method':'execute','operation_id':'wire','plan_id':pid}))

    def test_real_process_death_and_unrelated_process_churn(self):
        pid=self.prepare()
        self.exchange({'method':'execute','operation_id':'wire','plan_id':pid},crash_at='publish-effect')
        outcome=self.exchange({'method':'status','operation_id':'wire'})
        self.assertEqual(outcome['state'],'uncertain')
        import subprocess
        for _ in range(8):
            child=subprocess.Popen(['/usr/bin/true'])
            self.assertTrue(self.exchange({'method':'health'})['healthy'])
            self.assertEqual(child.wait(),0)
        self.assertEqual(self.execute(self.prepare('other','b'),'other')['state'],'succeeded')

    def test_interrupted_recovery_preserves_history(self):
        self.manager.fail_stop=True
        old=self.execute(self.prepare())
        self.manager.fail_stop=False
        workspace=self.root/'a/workspaces/0'
        workspace.mkdir()
        (workspace/'failure').write_text('retained')
        pid=self.prepare('recovery',action='recover',artifact={},recovery_of='op')
        self.exchange({'method':'execute','operation_id':'recovery','plan_id':pid},crash_at='retire-effect')
        self.assertEqual(self.call({'method':'status','operation_id':'op'}),old)
        retry=self.prepare('explicit-linked',action='recover',artifact={},recovery_of='recovery')
        self.assertEqual(self.execute(retry,'finish')['state'],'succeeded')
        self.assertEqual((self.root/'a/evidence/0/workspace/failure').read_text(),'retained')
        self.assertEqual(self.execute(self.prepare('subsequent',generation=1),'subsequent')['state'],'succeeded')

class RegressionTests(unittest.TestCase):
    setUp = EngineTests.setUp
    make = EngineTests.make
    call = EngineTests.call
    prepare = EngineTests.prepare
    execute = EngineTests.execute
    def test_permission_entries_cannot_combine(self):
        peer=self.policy['peers'][0]
        self.policy['peers']=[{**peer,'methods':['prepare'],'targets':['a']},{**peer,'methods':['execute','status'],'targets':['b']}]
        pid=self.prepare()
        with self.assertRaises(e.Rejected): self.execute(pid)
        with self.assertRaises(e.Rejected): self.call({'method':'status','target':'a'})

    def test_terminal_directory_fsync_failure_stays_uncertain(self):
        pid=self.prepare()
        original=e.atomic
        def broken(path,value,*args):
            original(path,value,*args)
            if value.get('state')=='succeeded': raise OSError('final directory fsync failure')
        with patch.object(e,'atomic',side_effect=broken):
            with self.assertRaises(OSError): self.execute(pid)
        self.assertEqual(self.call({'method':'status','operation_id':'op'})['state'],'uncertain')
        self.assertEqual(self.execute(pid)['state'],'uncertain')
        with self.assertRaises(e.Rejected): self.execute(self.prepare('again',generation=1),'again')

    def test_capacity_preserves_status_and_recovery_reserve(self):
        with patch.object(e,'MAX_RECORDS',101):
            self.manager.fail_stop=True
            self.execute(self.prepare())
            self.assertEqual(self.call({'method':'status','target':'a'})['operations'][0]['state'],'failed')
            with self.assertRaises(e.Rejected): self.prepare('no-normal')
            self.manager.fail_stop=False
            recovery=self.prepare('recovery',action='recover',artifact={},recovery_of='op')
            self.assertEqual(self.execute(recovery,'recovery')['state'],'succeeded')

    def test_release_parent_search_permission(self):
        pid=self.prepare()
        for name in ['releases','workspaces']:
            self.assertEqual((self.root/'a'/name).stat().st_mode & 0o111,0o111)
        self.assertEqual((self.root/'a/releases'/pid/'worker.py').stat().st_mode & 0o444,0o444)

class LifecycleTests(unittest.TestCase):
    def test_stuck_owned_cgroup_times_out_without_kill(self):
        class Stuck(e.SystemdManager):
            def __init__(self): self.commands=[]
            def _run(self, args, timeout): self.commands.append(args); return b''
            def observe(self, target): return {'owned.service':{'active':'inactive','populated':True}}
        manager=Stuck()
        with self.assertRaises(e.Rejected): manager.stop({'units':['owned.service'],'timeout':.001})
        self.assertEqual(manager.commands,[['stop','--no-block','owned.service']])

    def test_lifecycle_rejects_unknown_service_identity(self):
        class Wrong(e.SystemdManager):
            def _run(self,args,timeout):
                return b'User=0\nActiveState=inactive\nControlGroup=\nLoadState=loaded\n'
        with self.assertRaises(e.Rejected): Wrong().observe({'units':['owned.service'],'timeout':1,'service_uid':1000})
