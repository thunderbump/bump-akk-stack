"""Harmless temporary files, Git objects and real unprivileged sockets only."""
import base64
import contextlib
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation/maintenance'))
import maintenance as m
spec=importlib.util.spec_from_file_location('maintenance_client_fixture',ROOT/'validation/maintenance/client.py')
client=importlib.util.module_from_spec(spec);spec.loader.exec_module(client)
sys.path.remove(str(ROOT/'validation/maintenance'))

class Host:
    def __init__(self):self.active=False;self.busy=False;self.controls=[]
    @contextlib.contextmanager
    def guard(self):
        self.quiescent();yield;self.quiescent()
    def quiescent(self):m.require(not self.busy,'worker-active')
    def socket_active(self):return self.active
    def socket(self,active):self.active=active;self.controls.append(active)

@contextlib.contextmanager
def temp_directory(path,owner=0,monitored=None):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    before=os.fstat(fd)
    try:
        def check():
            current=path.lstat();m.require((before.st_dev,before.st_ino)==(current.st_dev,current.st_ino),'parent-changed')
        yield fd,check;check()
    finally:os.close(fd)

class Transaction(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup);self.root=Path(t.name)
        self.code=self.root/'code';self.state=self.root/'state';self.code.mkdir();self.state.mkdir(mode=0o700)
        for name in (m.FIXTURE,m.RELEASE):
            p=self.code/name;p.parent.mkdir(parents=True,exist_ok=True)
        fixture=(ROOT/'validation/actor-integration-fixture.json').read_bytes()
        (self.code/m.FIXTURE).write_bytes(fixture);(self.code/m.FIXTURE).chmod(0o644)
        current=m.read(self.code/m.FIXTURE)[1]
        release=m.canonical(dict(schema=1,selection='central-cdau-integration-v1',files={m.FIXTURE:{key:current[key] for key in ('uid','gid','mode','bytes','sha256')}},source_commit='a'*40,base_runtime_sha256='b'*64))
        (self.code/m.RELEASE).write_bytes(release);(self.code/m.RELEASE).chmod(0o644)
        records={name:m.read(self.code/name)[1] for name in m.PAIR}
        self.config=dict(records=records,policies={},fixture=base64.b64encode(fixture).decode(),release=base64.b64encode(release).decode(),submitter_uid=os.getuid(),submitter_gid=os.getgid())
        self.host=Host();self.store=m.Store(self.config,self.host,self.code,self.state,os.getuid())
        self.enterContext(patch.object(m,'directory',temp_directory))
        self.enterContext(patch.object(m,'prove_source'))
        self.request=dict(schema=1,id='1'*32,op='publish',expected=m.sha(m.canonical(records)),source=dict(commit='a'*40,tree='b'*40,rust_tree='c'*40),proof={})
    def publish(self):return m.dispatch(self.request,self.config,self.store)
    def rollback(self):return m.dispatch(dict(schema=1,id='2'*32,op='rollback',transaction=self.request['id']),self.config,self.store)
    def test_publish_actual_binding_validator_and_release_then_inode_rollback(self):
        before={name:m.read(self.code/name) for name in m.PAIR}
        self.publish();self.assertEqual(self.store.overview()['source']['commit'],'a'*40)
        sys.path.insert(0,str(ROOT/'validation/worker'))
        import actor_integration
        fixture=m.decode(m.read(self.code/m.FIXTURE)[0])
        with patch.object(actor_integration,'local_contract',return_value=fixture):
            actor_integration.validate_build_binding(dict(candidate='a'*40,tree='b'*40))
            with self.assertRaises(ValueError):actor_integration.validate_build_binding(dict(candidate='0'*40,tree='b'*40))
        self.rollback()
        for name in m.PAIR:self.assertEqual(m.read(self.code/name),before[name])
    def test_active_worker_or_stale_expected_refuses_without_socket_control(self):
        self.host.busy=True
        with self.assertRaises(m.Refusal):self.publish()
        self.host.busy=False;self.request['expected']='0'*64
        with self.assertRaises(m.Refusal):self.publish()
        self.assertEqual(self.host.controls,[])
    def test_fault_each_asset_replace_rollback_is_supported(self):
        original=m.os.replace
        for failure in (1,2):
            self.request['id']=format(failure,'032x')
            self.request['expected']=self.store.overview()['expected']
            count=0
            def fail(*a,**kw):
                nonlocal count
                count+=1;original(*a,**kw)
                if count==failure:raise OSError('injected')
            with patch.object(m.os,'replace',side_effect=fail):
                with self.assertRaises(OSError):self.publish()
            self.assertEqual(self.store.overview()['state'],'interrupted');self.rollback()
    def test_rollback_head_temporary_and_receipt_interruption_can_complete(self):
        self.publish();original=m.os.replace
        def fail(*a,**kw):
            if a[1]=='head.json':raise OSError('crash-before-head-replace')
            return original(*a,**kw)
        with patch.object(m.os,'replace',side_effect=fail):
            with self.assertRaises(OSError):self.rollback()
        self.assertTrue((self.state/('1'*32)/'rollback.json').exists())
        self.assertTrue((self.state/'.head.json.new').exists())
        self.rollback();self.assertEqual(self.store.overview()['state'],'ready')
    def test_publish_head_temporary_rollback_adopts_only_known_bytes(self):
        original=m.os.replace
        def fail(*a,**kw):
            if a[1]=='head.json':raise OSError('crash')
            return original(*a,**kw)
        with patch.object(m.os,'replace',side_effect=fail):
            with self.assertRaises(OSError):self.publish()
        self.rollback();self.assertEqual(self.store.overview()['source']['commit'],m.decode(base64.b64decode(self.config['fixture']))['server_source']['commit'])
    def test_unknown_head_temporary_or_target_drift_is_never_removed(self):
        self.publish();(self.state/'.head.json.new').write_bytes(b'unknown');(self.state/'.head.json.new').chmod(0o600)
        with self.assertRaises(m.Refusal):self.rollback()
        self.assertEqual((self.state/'.head.json.new').read_bytes(),b'unknown')
    def test_corrupt_retained_rollback_receipt_refuses_before_any_control(self):
        self.host.active=True;self.publish();self.host.controls.clear()
        tx=self.state/self.request['id']
        with temp_directory(self.state) as (fd,_):m.write_new(fd,'pending.json',m.canonical({'id':self.request['id']}))
        receipt=tx/'rollback.json';receipt.write_bytes(b'{}');receipt.chmod(0o600)
        after={name:m.read(self.code/name)[1] for name in m.PAIR}
        with self.assertRaisesRegex(m.Refusal,'receipt-drift'):self.rollback()
        self.assertEqual(self.host.controls,[])
        self.assertEqual({name:m.read(self.code/name)[1] for name in m.PAIR},after)
        receipt.write_bytes(m.canonical(dict(state='rolled-back',transaction=self.request['id'])));receipt.chmod(0o644)
        with self.assertRaisesRegex(m.Refusal,'receipt-drift'):self.rollback()
        self.assertEqual(self.host.controls,[])
    def test_cross_mount_and_max_request_do_not_create_unreadable_intent(self):
        self.request['proof']={'opaque':'x'*190000}
        with patch.object(m,'mount_identity',side_effect=[1,2,1,1]):
            with self.assertRaisesRegex(m.Refusal,'cross-mount'):self.publish()
        self.assertFalse((self.state/self.request['id']).exists())
        self.publish()
        self.assertLess((self.state/self.request['id']/'intent.json').stat().st_size,65536)
        self.rollback()
    def test_unknown_restore_temporary_refuses(self):
        self.publish();parent=(self.code/m.FIXTURE).parent
        (parent/'.maintenance-restore-0').write_bytes(b'unknown')
        with self.assertRaisesRegex(m.Refusal,'restore-temporary-drift'):self.rollback()
        self.assertEqual((parent/'.maintenance-restore-0').read_bytes(),b'unknown')
    def test_symlink_state_pointer_is_not_absence(self):
        (self.state/'pending.json').symlink_to(self.root/'absent')
        with self.assertRaises(OSError):self.store.overview()
    def test_postguard_failure_never_reports_success(self):
        @contextlib.contextmanager
        def guard():yield;raise m.Refusal('exit-check')
        self.host.guard=guard
        with self.assertRaisesRegex(m.Refusal,'exit-check'):self.publish()
    def test_real_peer_socket_no_new_privileges_child(self):
        endpoint=self.root/'fixture.sock';server=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);server.bind(str(endpoint));server.listen()
        errors=[]
        def fixture():
            try:
                connection,_=server.accept()
                with connection:m.serve(connection,self.config,self.store)
            except Exception as error:errors.append(error)
            finally:server.close()
        thread=threading.Thread(target=fixture);thread.start()
        code='''import ctypes,sys,os,json
sys.path.insert(0,sys.argv[1]);import client
assert ctypes.CDLL(None).prctl(38,1,0,0,0)==0
assert 'NoNewPrivs:\\t1' in open('/proc/self/status').read()
r=client.exchange({'schema':1,'id':'3'*32,'op':'health'},sys.argv[2],server_uid=os.getuid());assert r['ok'];print(json.dumps(r))'''
        child=subprocess.run([sys.executable,'-I','-B','-c',code,str(ROOT/'validation/maintenance'),str(endpoint)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        thread.join(10);self.assertEqual(child.returncode,0,child.stderr.decode());self.assertFalse(errors);self.assertFalse(thread.is_alive())
    def test_peer_denied_and_unknown_schema(self):
        one,two=socket.socketpair()
        with one,two:
            denied=dict(self.config,submitter_uid=os.getuid()+1)
            m.serve(one,denied,self.store);self.assertFalse(m.decode(two.recv(4096))['ok'])
        for value in [dict(self.request,command='evil'),dict(self.request,op='archive'),dict(self.request,id='../bad')]:
            with self.assertRaises(m.Refusal):m.validate_request(value)

class Proof(unittest.TestCase):
    def test_real_git_objects_no_candidate_execution(self):
        # The owning frozen Server source is read only through Git object reads.
        repo=Path('/home/bump/.t3/worktrees/bump-EQEmu/feature-actor-progression-hostile-travel')
        if not repo.exists():self.skipTest('local source object fixture unavailable')
        commit=client.git(repo,'rev-parse','HEAD').decode().strip()
        source,proof=client.source_request(repo,commit)
        fixture=m.decode((ROOT/'validation/actor-integration-fixture.json').read_bytes())
        m.prove_source(source,proof,fixture)
        source['tree']='0'*40
        with self.assertRaises(m.Refusal):m.prove_source(source,proof,fixture)
    def test_active_record_inspection_denial_is_not_absence(self):
        from types import SimpleNamespace
        real=Path.lstat
        def denied(path,*a,**kw):
            if path.name=='active.json':raise PermissionError('injected denied inspection')
            return real(path,*a,**kw)
        with patch.object(m.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'')),patch.object(Path,'lstat',new=denied):
            with self.assertRaises(PermissionError):m.Host().quiescent()
    def test_duplicate_keys_and_limits(self):
        with self.assertRaises(m.Refusal):m.decode(b'{"schema":1,"schema":2}')
        with self.assertRaises(m.Refusal):m.prove_source({}, {}, {})


class Consumer(unittest.TestCase):
    def test_actual_public_layout_and_full_installed_inventory_consumer(self):
        """Read actual public bytes, then mutate ONLY a temporary simulated-root copy."""
        actual=m.CODE
        if not actual.exists():self.skipTest('public installed closure unavailable')
        flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
        def public_read(path,limit=131072):
            with path.open('rb') as stream:
                info=os.fstat(stream.fileno());raw=stream.read(limit+1);after=os.fstat(stream.fileno())
            self.assertEqual((info.st_ino,info.st_size,info.st_mtime_ns),(after.st_ino,after.st_size,after.st_mtime_ns))
            return raw,dict(m.metadata(after),bytes=len(raw),sha256=m.sha(raw))
        with patch.object(m,'FLAGS',flags),patch.object(m,'read',side_effect=public_read):
            release=m.read(actual/m.RELEASE)[0];manifest=m.decode(release)
            records={name:m.read(actual/name)[1] for name in (*manifest['files'],m.RELEASE)}
            fixture=m.read(actual/m.FIXTURE)[0]
            config=dict(records=records,policies={},fixture=base64.b64encode(fixture).decode(),release=base64.b64encode(release).decode(),monitored_directories={str(actual/'scripts'):m.metadata((actual/'scripts').lstat())})
            self.assertEqual((actual/'scripts').lstat().st_uid,1000)
            m.Store(config).snapshot(records)  # Real root/bump directory ownership, no mutation.
        with tempfile.TemporaryDirectory() as temporary:
            code=Path(temporary)/'code';code.mkdir();state=Path(temporary)/'state';state.mkdir(mode=0o700)
            for name in records:
                path=code/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((actual/name).read_bytes());path.chmod(records[name]['mode'])
            for directory in (code,code/'validation',code/'validation/worker'):directory.chmod(0o755)
            real_read=m.read
            def logical(path,*args,**kw):
                raw,item=real_read(path,*args,**kw)
                try:name=str(Path(path).relative_to(code))
                except ValueError:name=None
                if name in records:item.update(uid=records[name]['uid'],gid=records[name]['gid'])
                elif Path(path).name.startswith(('old','new')):item.update(uid=0,gid=0)
                return raw,item
            with patch.object(m,'read',side_effect=logical),patch.object(m,'directory',temp_directory),patch.object(m,'prove_source'):
                config=dict(config,records={name:logical(code/name)[1] for name in records},monitored_directories={})
                host=Host();store=m.Store(config,host,code,state,os.getuid())
                # Only journal ownership is current UID in the harmless fixture.
                original_load=store.load
                def load(path):
                    if path.name.startswith(('intent','head','pending')):return m.decode(real_read(path)[0])
                    return original_load(path)
                store.load=load
                request=dict(schema=1,id='7'*32,op='publish',expected=m.sha(m.canonical(config['records'])),source=dict(commit='a'*40,tree='b'*40,rust_tree='c'*40),proof={})
                m.dispatch(request,config,store)
                sys.path.insert(0,str(ROOT/'validation/worker'))
                import integration_artifacts as ia
                real_lstat=Path.lstat
                def lstat(path,*a,**kw):
                    info=real_lstat(path,*a,**kw)
                    if path in (code,code/'validation',code/'validation/worker'):
                        fields=list(info);fields[4:6]=[0,0];return os.stat_result(fields)
                    return info
                class OS:
                    def __getattr__(self,key):return getattr(os,key)
                    def open(self,path,*a,**kw):
                        fd=os.open(path,*a,**kw);opened[fd]=Path(path);return fd
                    def fstat(self,fd):
                        info=os.fstat(fd);path=opened.get(fd)
                        if path==code/m.RELEASE:
                            fields=list(info);fields[4:6]=[0,0];return os.stat_result(fields)
                        if path and path.is_relative_to(code):
                            name=str(path.relative_to(code));fields=list(info);fields[4:6]=[records[name]['uid'],records[name]['gid']];return os.stat_result(fields)
                        return info
                opened={}
                with patch.object(ia,'os',OS()),patch.object(Path,'lstat',new=lstat):
                    self.assertEqual(len(ia.installed_inventory(code)),19)
                    import identity
                    etc=Path(temporary)/'etc'
                    for relative in ('systemd/system/eqemu-validator@.service','systemd/system/eqemu-validator.socket','apparmor.d/eqemu-validator'):
                        target=etc/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(b'harmless policy fixture')
                    image=Path(temporary)/'image';image.write_bytes(b'harmless input fixture')
                    cfg=Path(temporary)/'config.json';cfg.write_text(json.dumps(dict(code_dir=str(code),base_image=str(image))))
                    with patch.object(identity,'POLICY_ROOT',etc):
                        recipe=identity.identity(ROOT,cfg,image,image)['identity']
                    self.assertTrue(recipe.startswith('eqemu-worker-v1:'))
                import actor_integration as actor
                current=m.decode((code/m.FIXTURE).read_bytes())
                with patch.object(actor,'local_contract',return_value=current):
                    actor.validate_build_binding(dict(candidate='a'*40,tree='b'*40))

    def test_export_actual_full_frontend_with_large_trusted_blob(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);clone=root/'stack'
            subprocess.run(['/usr/bin/git','clone','--quiet','--shared',str(ROOT),str(clone)],check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
            fixture=(ROOT/'validation/actor-integration-fixture.json').read_bytes()
            binding=dict(fixture=base64.b64encode(fixture).decode(),sha256=m.sha(fixture))
            result=client.frontend(clone,root/'frontend',binding)
            exported=root/'frontend/validation/worker/actor_integration.py'
            self.assertGreater(exported.stat().st_size,65536)
            self.assertEqual(result['fixture_sha256'],m.sha(fixture))
            self.assertEqual(exported.read_bytes(),client.git(clone,'show','HEAD:validation/worker/actor_integration.py',limit=1048576))

if __name__=='__main__':unittest.main()
