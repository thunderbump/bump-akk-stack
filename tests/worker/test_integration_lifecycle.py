"""Read-only mailbox and owned-process fault tests with harmless local fixtures."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'validation'))
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'validation/worker'))
import actor_integration as i
import integration_artifacts as a
from test_actor_integration import process,shard,RUN,CANDIDATE


class Mailbox(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.pop=Path(self.tmp.name);self.directory=self.pop/'integration/p0';self.directory.mkdir(parents=True,mode=0o700)
        self.collection=i.Collection(RUN)
        self.box=i.Mailbox(self.pop,process(),RUN,i.Budget(),self.collection,lambda:None);self.box.session='native-1'
        self.native=types.SimpleNamespace(closed=True,process=types.SimpleNamespace(returncode=0,pid=999999999),descriptor=dict(process(),exit_kind=1))

    def fixture(self,barrier=65535):
        value=shard();value['events']=[[0,1,1,11,0,'1',[6,0,0,2,0,'0','0','0']],[0,2,2,11,0,'1',[7,0,0,2,0,'0','0','0']]]
        value['process'].update(first_seq=1,last_seq=2)
        raw=a.encoded(value);(self.directory/a.NAME).write_bytes(raw)
        ack=dict(schema=1,run=RUN,process_index=0,session='native-1',request='0',op=0,barrier=barrier,
                 result=1,last_seq=2,shard_sha256=hashlib.sha256(raw).hexdigest(),snapshot_sequence=0)
        (self.directory/'ack.json').write_bytes(a.encoded(ack))
        return value,ack

    def test_terminal_after_orderly_reap_retains_late_unlock(self):
        value,_=self.fixture()
        live=copy.deepcopy(value);live['events']=live['events'][:1];live['process']['last_seq']=1
        self.collection.accept(live,process())
        with patch('actor_runtime.group_live',return_value=False): self.box.terminal(self.native)
        self.assertEqual([e[6][0] for e in self.collection.shards[0]['events']],[6,7])

    def test_terminal_rejects_unreaped_nonzero_kill_and_nonempty_group(self):
        self.fixture()
        for field,value in [('closed',False),('returncode',None),('returncode',-9),('exit_kind',2)]:
            native=copy.deepcopy(self.native)
            if field=='closed': native.closed=value
            elif field=='returncode': native.process.returncode=value
            else: native.descriptor[field]=value
            with self.subTest(field=field,value=value),patch('actor_runtime.group_live',return_value=False),self.assertRaises(ValueError): self.box.terminal(native)
        with patch('actor_runtime.group_live',return_value=True),self.assertRaises(ValueError): self.box.terminal(self.native)

    def test_stale_startup_ack_bad_binding_or_changed_prefix_cannot_finalize(self):
        for key,value in [('barrier',0),('result',0),('request','1'),('run','f'*32),('session','native-2'),('last_seq',3),('shard_sha256','f'*64)]:
            _,ack=self.fixture();ack[key]=value;(self.directory/'ack.json').write_bytes(a.encoded(ack))
            with self.subTest(key=key),patch('actor_runtime.group_live',return_value=False),self.assertRaises(ValueError): self.box.terminal(self.native)
        _,_=self.fixture();(self.directory/a.NAME).unlink()
        with patch('actor_runtime.group_live',return_value=False),self.assertRaises(FileNotFoundError): self.box.terminal(self.native)

    def test_timeout_is_one_request_and_latches_failure_no_retry(self):
        with patch('time.monotonic',side_effect=[0,11]),self.assertRaises(ValueError): self.box.observe()
        request=a.decode((self.directory/'request').read_bytes())
        self.assertEqual(request['request'],'1');self.assertEqual(self.box.budget.counts['flush'],1)
        with self.assertRaises(ValueError): self.box.observe()
        self.assertEqual(a.decode((self.directory/'request').read_bytes()),request)


class NativeOwnership(unittest.TestCase):
    def test_post_popen_callback_and_initialization_failures_reap_actual_child(self):
        actual_popen=subprocess.Popen
        for failure in ('callback','initialization'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as root:
                root=Path(root);binary=root/'bin';binary.mkdir();shutil.copyfile(sys.executable,binary/'world');(binary/'world').chmod(0o700)
                children=[];owned=[]
                def spawn(args,**kwargs):
                    code='import signal,time,sys; signal.signal(signal.SIGTERM,lambda *_:sys.exit(0)); print("ready",flush=True); time.sleep(30)'
                    child=actual_popen([sys.executable,'-c',code],**kwargs);children.append(child)
                    deadline=time.monotonic()+2
                    while time.monotonic()<deadline:
                        if (root/'integration-0.log').exists() and b'ready' in (root/'integration-0.log').read_bytes(): break
                        time.sleep(.01)
                    return child
                def callback(native):
                    owned.append(native)
                    if failure=='callback': raise RuntimeError('injected callback failure')
                original=Path.read_text
                failed=[False]
                def read_text(path,*args,**kwargs):
                    if failure=='initialization' and not failed[0] and str(path).startswith('/proc/') and path.name=='stat':
                        failed[0]=True;raise OSError('injected initialization failure')
                    return original(path,*args,**kwargs)
                with patch('subprocess.Popen',side_effect=spawn),patch.object(Path,'read_text',read_text),self.assertRaises((RuntimeError,OSError)):
                    i.Native('world',binary,root,root,RUN,'A',0,1,on_started=callback)
                self.assertEqual(len(children),1);self.assertEqual(children[0].poll(),0)
                self.assertFalse(Path('/proc',str(children[0].pid)).exists())
                self.assertEqual(len(owned),1);self.assertTrue(owned[0].cleanup_complete)
                self.assertTrue(owned[0].closed);self.assertEqual(owned[0].index,0)


class StagedGuest(unittest.TestCase):
    def test_completion_schema_imports_only_the_actual_staged_helper_closure(self):
        import guest
        value=dict(version=1,scope='worker-build',nonce=RUN,exit_code=2,stage='guest-launcher',
                   selected_checks=[*guest.BUILD_CHECKS[:-1],'actor-population-integration'],completed_checks=[],integration=a.SELECTION)
        config=json.loads(guest.build_user_data(RUN,integration=a.SELECTION).split('\n',1)[1])
        with tempfile.TemporaryDirectory() as root:
            root=Path(root)
            for entry in config['write_files']:
                (root/Path(entry['path']).name).write_text(entry['content'])
            self.assertFalse((root/'guest.py').exists())
            code='import sys,json;sys.path.insert(0,sys.argv[1]);import integration_artifacts as a;a.validate_guest(json.loads(sys.argv[2]))'
            result=subprocess.run([sys.executable,'-I','-B','-c',code,str(root),json.dumps(value)],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr.decode())


if __name__=='__main__': unittest.main()
