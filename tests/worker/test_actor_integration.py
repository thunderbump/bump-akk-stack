"""Source-only controls with synthetic public records and harmless subprocesses."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'validation/worker'))
import actor_integration as i
import integration_artifacts as a

ROOT=Path(__file__).resolve().parents[2]
CANDIDATE='a'*40
TREE='c'*40
RUN='b'*32


def context(proc=0,kind=3):
    return [proc,0,*(['0']*7),0,0,0,2,kind,0]


def process(proc=0):
    return dict(index=proc,native_pid=os.getpid(),process_start_identity='1',role_world_source_destination='source',
                zone=2,binary_sha256='f'*64,first_seq=0,last_seq=0,exit_kind=1,complete_prefix=True)


def admission():
    return dict(actors=[[0,'0'*64,0,0,'0',0] for _ in range(3)],connection=[False,0,0,0,*(['0']*6)],
                native_route_flags=0,geometry=[False,0,0,0,*(['0']*9),0])


def artifact():
    summary=i.initial_summary();summary.update(outcome=2,failure_cause=11,process_count=1,context_count=1,complete_prefixes=1)
    return dict(schema=a.SELECTION,contract_sha256=a.CONTRACT_SHA,fixture_sha256=a.FIXTURE_SHA,processes=[process()],
                contexts=[context()],events=[],snapshots=[],manifest=dict(server_commit=CANDIDATE,server_tree=TREE,stack_commit='d'*40,
                fixture_selection_sha256='cec8c281604549b7c4d54259ff7760ffe37dae26dc09e5fa4462ef2823c86871',
                public_fixture_sha256=a.FIXTURE_SHA,event_contract_sha256=a.CONTRACT_SHA,interface_sha256=i.INTERFACE_SHA,
                run=RUN,admission_by_case=[[admission(),admission()] for _ in range(3)]),summary=summary,complete=True,overflow=False,gaps=0)


def shard(proc=0):
    return dict(schema=a.SELECTION,contract_sha256=a.CONTRACT_SHA,run=RUN,case=0,process=process(proc),
                contexts=[[0,context(proc)]],events=[],snapshots=[],admission=admission(),complete=True,overflow=False,gaps=0)


class Schema(unittest.TestCase):
    def test_exact_protocol_bytes_and_separate_ack_widths(self):
        hashes={'integration-v1.4.json':'c604e154baf96908e2d6707714875924a198793438ec219565f05dc4e6cf6eb0', 'integration-v1.json':'94680ff125aca23a1076cbbed5a729eee195744e0e8d9b03015bf9fa4a6f8988',
                'integration-v1.1.json':'debb2b98f3e79ebe6a363d821c760e133f99decae8968a451693e90ebec55d37',
                'integration-v1.2.json':'2a5fcc58f46cde55e3d6af3cc65a8ef77b86b5a4d3f6b73b10768bd41c93b7a0',
                'integration-v1.3.json':'1b523bbea868a59ad798cd13a1a5f50c4aa7e5f40bca7c49829d0c558bfd4615'}
        for name,digest in hashes.items(): self.assertEqual(hashlib.sha256((ROOT/'validation/worker'/name).read_bytes()).hexdigest(),digest)
        request=dict(schema=1,run=RUN,process_index=23,session='s'*48,request=str(2**64-1),op=1,barrier=65535)
        ack=dict(request,result=9,last_seq=4096,shard_sha256='f'*64,snapshot_sequence=12)
        self.assertEqual(len(a.encoded(request))+1,190)
        self.assertEqual(len(a.encoded(ack))+1,322)
        self.assertLessEqual(len(a.encoded(request)),256)
        self.assertLessEqual(len(a.encoded(ack)),1024)
        durable=dict(version=1,run_id=RUN,sha256='f'*64,bytes=a.CAP,durable=True)
        self.assertLessEqual(len(a.encoded(durable))+1,256)
        witness=json.loads((Path(__file__).parent/'fixtures/integration-width.json').read_bytes())
        witness['manifest_max_witness']['interface_sha256']=i.INTERFACE_SHA
        self.assertEqual(len(a.encoded(witness['manifest_max_witness'])),6510)
        self.assertEqual(len(a.encoded(witness['summary_max_witness'])),398)

    def test_exact_schema_rejects_unearned_summary_and_hidden_text(self):
        value=artifact();i.validate_artifact(a.encoded(value))
        for mutate in ('extra','summary','process','context','admission','fixture'):
            bad=copy.deepcopy(value)
            if mutate=='extra': bad['environment']='credential'
            elif mutate=='summary': bad['summary'].update(outcome=1,failure_cause=0,case_outcomes=[1]*3,check_results=[1]*12)
            elif mutate=='process': bad['processes'][0]['argv']='credential'
            elif mutate=='context': bad['contexts'][0][13]=4
            elif mutate=='admission': bad['manifest']['admission_by_case'][0][0]['native_route_flags']=128
            else: bad['fixture_sha256']='0'*64
            with self.subTest(mutate=mutate),self.assertRaises(ValueError): i.validate_artifact(a.encoded(bad))

    def test_offline_seed_is_unearned_and_all_empty_native_route(self):
        records=[a.decode(raw) for raw in i.seed_records()]
        self.assertEqual([r['saved']['experience'] for r in records],[0]*3)
        self.assertEqual([r['saved']['level'] for r in records],[1]*3)
        self.assertEqual([r['saved']['inventory'] for r in records],[[]]*3)
        earned=records[0];earned['saved'].update(experience=1500,level=2,completed=3,reputation={'306':-10})
        derived=[a.decode(raw) for raw in i.seed_records(a.encoded(earned),inventory=True)]
        for key in ('experience','level','completed','reputation'): self.assertEqual(derived[0]['saved'][key],earned['saved'][key])
        self.assertEqual(len(derived[0]['saved']['inventory']),8)
        self.assertTrue(all(item['serial']==0 for item in derived[0]['saved']['inventory']))
        self.assertTrue(all(len(item)==23 for item in derived[0]['saved']['inventory']))
        raw=[a.encoded(r).decode() for r in derived]
        snapshot=dict(process_index=0,sequence=1,raw_record_sha256_by_actor=i.checksums(raw),raw_json_by_actor=raw)
        i.validate_snapshot(snapshot)
        for record in derived: i.validate_record_values(record)
        bad=copy.deepcopy(snapshot);bad['raw_json_by_actor'][0]+=' '
        with self.assertRaises(ValueError): i.validate_snapshot(bad)
        bad=copy.deepcopy(derived[0]);bad['saved']['inventory'][0]['custom']='secret-unknown'
        with self.assertRaises(ValueError): i.validate_record_values(bad)

    def test_fixture_missing_changed_symlink_and_real_sealed_package(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'fixture.tar'
            with self.assertRaises(FileNotFoundError): i.verify_fixture(path)
            path.write_bytes(b'x'*i.FIXTURE_BYTES)
            with self.assertRaises(ValueError): i.verify_fixture(path)
            link=Path(root)/'link';link.symlink_to(path)
            with self.assertRaises(OSError): i.verify_fixture(link)
        selected=Path('/home/bump/.local/state/eqemu-cdau-validation/fixture-contract-prep-ce4f-20261104/v1/public-fixture-data.tar')
        if selected.exists(): self.assertEqual(len(i.verify_fixture(selected)),27)

    def test_cumulative_prefix_rewrite_and_global_context_overrun(self):
        collection=i.Collection(RUN)
        first=shard();collection.accept(first,process())
        second=shard(1);collection.accept(second,process(1))
        contexts,events,snapshots,admissions=collection.merged()
        self.assertEqual([c[0] for c in contexts],[0,1])
        self.assertEqual(admissions[1]['geometry'][1:4],[1]*3)
        bad=copy.deepcopy(first);bad['contexts'][0][1][2]='1'
        with self.assertRaises(ValueError): collection.accept(bad,process())
        huge=shard(2);huge['contexts']=[[n,context(2)] for n in range(128)]
        for n,pair in enumerate(huge['contexts']): pair[1][2]=str(n);pair[1][13]=0;pair[1][1]=1
        with self.assertRaises(ValueError): collection.accept(huge,process(2))

    def test_two_shard_event_and_geometry_refs_are_remapped(self):
        collection=i.Collection(RUN)
        for proc in (0,1):
            value=shard(proc);value['events']=[[proc,1,1,6,0,'1',[0,0,False,5,1,'100','100']]]
            value['process'].update(first_seq=1,last_seq=1)
            collection.accept(value,process(proc))
        contexts,events,_,admissions=collection.merged()
        self.assertEqual(events[1][4],1);self.assertEqual(events[1][6][0],1)
        self.assertEqual(admissions[1]['actors'][0][0],1)
        self.assertEqual(len(contexts),2)

    def test_fixed_launcher_and_recovery_conditions(self):
        for role,args in [('world',['/bin/world']),('source',['/bin/zone','qeynos2','cdau','0']),('destination',['/bin/zone','dynamic_cdau4','cdau','0'])]:
            actual,env=i.launch_spec(role,Path('/bin'),Path('/fixture'),Path('/population'),RUN,'A',0,1)
            self.assertEqual(actual,args)
            self.assertFalse(any(k.startswith('EQEMU_') for k in env) if role=='world' else False)
        args,_=i.launch_spec('destination',Path('/bin'),Path('/fixture'),Path('/population'),RUN,'C',1,1,recovery=True)
        self.assertEqual(args,['/bin/zone','qeytoqrg','cdau','0'])
        with self.assertRaises(ValueError): i.launch_spec('destination',Path('/bin'),Path('/fixture'),Path('/population'),RUN,'B',1,1,recovery=True)


class Retention(unittest.TestCase):
    def make(self,state,run,ack=True):
        job=state/run;job.mkdir(mode=0o700)
        sink=a.Sink(job/'integration',CANDIDATE,run)
        raw=artifact();raw['manifest']['run']=run;raw=a.encoded(raw)
        for frame in a.frames(raw,CANDIDATE,run,complete=True,gaps=False,overflow=False): sink.accept(frame)
        receipt=sink.finish(sink.ack() if ack else None)
        sink.close()
        return job,receipt

    def test_retained_receipt_and_later_readonly_export_preserve_original_uncertainty(self):
        with tempfile.TemporaryDirectory() as root:
            state=Path(root);job,receipt=self.make(state,RUN,False)
            path=a.retain(job,state,RUN)
            before={p.name:(p.stat().st_ino,p.read_bytes()) for p in path.iterdir()}
            (state/'last-result.json').write_text('{"ordinary":"later"}')
            left,right=socket.socketpair();result={}
            def send():
                try: result.update(a.replay(path,RUN,left))
                finally: left.close()
            thread=threading.Thread(target=send);thread.start()
            stream=right.makefile('rb')
            while True:
                frame=a.decode(stream.readline()[len(a.PREFIX):])
                if frame['kind']=='end': break
            ack=dict(version=1,run_id=RUN,sha256=frame['sha256'],bytes=frame['bytes'],durable=True)
            right.sendall(a.encoded(ack)+b'\n');thread.join(2);stream.close();right.close()
            self.assertFalse(thread.is_alive())
            self.assertTrue(result['reexport_complete'])
            self.assertEqual(result['integration_receipt'],receipt)
            self.assertEqual(receipt['original_transfer'],'uncertain')
            self.assertEqual(before,{p.name:(p.stat().st_ino,p.read_bytes()) for p in path.iterdir()})

    def test_partial_retention_rename_can_finish_without_replacing_unknown_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            state=Path(root);first,_=self.make(state,RUN);a.retain(first,state,RUN)
            second,receipt=self.make(state,'c'*32)
            rename=os.rename;calls=[]
            def fault(src,dst):
                calls.append((src,dst))
                if len(calls)==2: raise OSError('injected publication stop')
                rename(src,dst)
            with patch.object(a.os,'rename',side_effect=fault),self.assertRaises(OSError): a.retain(second,state,'c'*32)
            self.assertTrue((second/'previous-integration').is_dir())
            path=a.retain(second,state,'c'*32)
            self.assertEqual(a.retained(path)[1],receipt)
            self.assertFalse((second/'previous-integration').exists())
            (path/'unknown').write_bytes(b'public')
            with self.assertRaises(ValueError): a.retained(path)


if __name__=='__main__': unittest.main()


class MaximumEncoding(unittest.TestCase):
    def test_complete_global_event_context_process_snapshot_and_envelope_limits(self):
        value=artifact();maximum=str(2**64-1);signed=str(-2**63)
        value['processes']=[dict(process(n),native_pid=2**32-1-n,process_start_identity=maximum,
                                 role_world_source_destination='destination' if n else 'source',zone=4 if n else 2) for n in range(24)]
        value['contexts']=[context() for _ in range(128)]
        for n,ctx in enumerate(value['contexts']): ctx[2:9]=[str(2**64-1-n)]*7;ctx[9:13]=[2**32-1]*3+[2];ctx[13]=0;ctx[1]=1
        value['contexts'][0]=context()
        payloads={5:[10,False,2**32-1,255,maximum,maximum,65535,'f'*64],6:[127,1,False,9,3,signed,str(2**63-1)],
                  7:[65535,-2**31,-2**31,2**31-1],8:[2,65535,0,'1',maximum,maximum,maximum,maximum],
                  9:[2,255,255,maximum,maximum],10:[127,-2**31,-2**31,-2**31,-2**31,9,255,2**32-1],
                  11:[8,65535,127,2**32-1,255,maximum,maximum,maximum],12:[1,2,maximum,65535,12,maximum,maximum,maximum]}
        events=[]
        for kind,cap in i.KINDS.items():
            for number in range(cap):
                payload=copy.deepcopy(payloads[kind])
                if kind==8 and 4<=number<8: payload=[1,65535,127,maximum,maximum,maximum,maximum,5]
                elif kind==8 and number>=8: payload=[0,65535,127,127,'0','0','0','0']
                events.append([0,len(events)+1,1800000000,kind,127,maximum,payload])
        value['events']=events;value['processes'][0].update(first_seq=1,last_seq=len(events))
        records=[a.decode(raw) for raw in i.seed_records()]
        records[0]['saved'].update(level=2,experience=1000,completed=3)
        records=[a.decode(raw) for raw in i.seed_records(a.encoded(records[0]),inventory=True)]
        for record in records:
            record['revision']=2**64-1
            record['saved'].update(owner_epoch=2**64-1,experience=2**64-1,completed=2**64-1,yielded=2**64-1,failed=2**64-1,
                                   hp=2**63-1,max_hp=2**63-1,reputation={str(2**31-1-n):32767 for n in range(20)})
        raw=[a.encoded(record).decode() for record in records]
        snapshot=dict(process_index=0,sequence=1,raw_record_sha256_by_actor=i.checksums(raw),raw_json_by_actor=raw)
        value['snapshots']=[dict(snapshot,sequence=n) for n in range(1,13)]
        value['summary'].update(i.counters(events),process_count=24,context_count=128,snapshot_count=12,complete_prefixes=24)
        encoded=a.encoded(value)
        i.validate_artifact(encoded)
        self.assertLessEqual(len(encoded),841588)
        self.assertLessEqual(len(encoded),a.CAP)
        self.assertEqual(len(value['events']),3184)
        self.assertEqual(len(value['snapshots']),12)
        normal=dict(scope=a.SELECTION,exit_code=2,binaries={name:'f'*64 for name in ('world','zone','shared_memory')},fixture_sha256=a.FIXTURE_SHA,
                    process_outcomes=[[n,4,-255] for n in range(24)],native_cleanup=False,database_cleanup=False,summary=value['summary'])
        from guest import BUILD_CHECKS
        selected=[*BUILD_CHECKS[:-1],'actor-population-integration']
        guest=dict(version=1,scope='worker-build',nonce=RUN,exit_code=2,stage='actor-population-integration',selected_checks=selected,completed_checks=selected,
                   integration=a.SELECTION,normal_world=normal,zone_sha256='f'*64,
                   utilities=dict(version=1,selected=2**32-1,started=2**32-1,completed=2**32-1,failed=2**32-1,finalized=False,passed=False),error='e'*3498)
        a.validate_guest(guest)
        self.assertLessEqual(len(a.encoded(guest))+len(b'EQEMU_WORKER_RESULT ')+1,9714)
        a.validate_outer(dict(version=1,integration=a.SELECTION,guest=guest,integration_receipt={'error':'integration-incomplete'},error='e'*1000))
        bad=copy.deepcopy(value);bad['summary']['credited_kills']=0
        with self.assertRaises(ValueError): i.validate_artifact(a.encoded(bad))


class FixedInputsAndPrivacy(unittest.TestCase):
    def test_only_selected_rust_bytes_and_lock_are_accepted(self):
        contract=i.dependency_contract()
        selected={key:contract[key] for key in ('bytes','sha256')}
        i.verify_dependencies({'files':{'rust-inputs.tar':selected}})
        with self.assertRaises(ValueError): i.verify_dependencies({'files':{'rust-inputs.tar':dict(selected,sha256='0'*64)}})
        with patch.object(i,'read_public',return_value=b'changed lock'),self.assertRaises(ValueError): i.verify_dependencies({'files':{'rust-inputs.tar':selected}},Path('/source'))
        import prepare
        with patch.object(prepare,'record',return_value=selected): self.assertEqual(prepare.verify_rust(Path('/fixture'),integration=True),selected)
        with patch.object(prepare,'record',return_value=selected),self.assertRaises(ValueError): prepare.verify_rust(Path('/fixture'))
        self.assertEqual(prepare.ADDITIONAL_RUST,{'7bc2a72f9b8a3ebcea3dfcb879ab2d5bb0a23d5ab4913e85f9acd728a5ce932e':171284480})

    def test_known_secrets_are_refused_after_decoding_escapes(self):
        secret='a'*48
        value=artifact();value['processes'][0]['binary_sha256']=secret+'b'*16
        raw=a.encoded(value);i.validate_artifact(raw)
        with self.assertRaises(ValueError): i.public_artifact(raw,[secret])
        escaped=raw.replace((secret+'b'*16).encode(),(r'\u0061'*48+'b'*16).encode())
        with self.assertRaises(ValueError): i.public_artifact(escaped,[secret])
