"""Real local Unix sockets exercise client durability without a worker or VM."""
import hashlib
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'validation/worker'))
import client
import integration_artifacts as a
from test_actor_integration import artifact,CANDIDATE,TREE,RUN


class ClientTransfer(unittest.TestCase):
    def serve(self,root,callback):
        path=Path(root)/'socket';listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(path));listener.listen(1)
        errors=[]
        def work():
            try:
                connection,_=listener.accept();connection.settimeout(2)
                with connection: callback(connection)
            except BaseException as error: errors.append(error)
            finally: listener.close()
        thread=threading.Thread(target=work);thread.start()
        return path,thread,errors

    def request(self): return dict(version=1,operation='build',candidate=CANDIDATE,tree=TREE,bytes=0,sha256='f'*64,integration=a.SELECTION)

    def test_disconnect_retains_verified_prefix_and_uncertain_receipt(self):
        with tempfile.TemporaryDirectory() as root:
            raw=a.encoded(artifact());frames=list(a.frames(raw,CANDIDATE,RUN,complete=True,gaps=False,overflow=False))
            def send(connection):
                self.assertTrue(connection.recv(4096).endswith(b'\n'))
                for frame in frames[:-1]: connection.sendall(a.wire(frame))
            path,thread,errors=self.serve(root,send)
            output=Path(root)/'output'
            with self.assertRaises(RuntimeError): client.exchange(path,self.request(),integration_output=output)
            thread.join(2);self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
            prefix,receipt=a.retained(output,RUN)
            self.assertEqual(prefix,raw);self.assertFalse(receipt['complete']);self.assertEqual(receipt['original_transfer'],'uncertain')

    def test_one_durable_ack_follows_complete_file_fsync_and_final_report(self):
        with tempfile.TemporaryDirectory() as root:
            raw=a.encoded(artifact());acks=[]
            def send(connection):
                self.assertTrue(connection.recv(4096).endswith(b'\n'))
                for frame in a.frames(raw,CANDIDATE,RUN,complete=True,gaps=False,overflow=False): connection.sendall(a.wire(frame))
                data=bytearray()
                while not data.endswith(b'\n'): data.extend(connection.recv(1))
                self.assertLessEqual(len(data),256);acks.append(a.decode(data))
                # Workload remains nonpass even though this artifact transfer is durable.
                connection.sendall(a.encoded(dict(version=1,exit_code=2,run_id=RUN,integration_receipt={'complete':True}))+b'\n')
            path,thread,errors=self.serve(root,send);output=Path(root)/'output'
            result=client.exchange(path,self.request(),integration_output=output)
            thread.join(2);self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
            self.assertEqual(result['exit_code'],2);self.assertEqual(len(acks),1)
            self.assertEqual(acks[0],dict(version=1,run_id=RUN,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),durable=True))
            self.assertTrue(a.retained(output,RUN)[1]['complete'])

    def test_empty_or_incomplete_terminal_export_preserves_final_nonpass_without_ack(self):
        for raw,complete,gaps,overflow in [(b'',False,True,False), (b'',True,False,False),
                                           (b'partial public prefix',False,True,False),
                                           (a.encoded(artifact()),False,False,True)]:
            with self.subTest(raw=raw[:10],complete=complete),tempfile.TemporaryDirectory() as root:
                report=dict(version=1,exit_code=2,run_id=RUN,cleanup_complete=True,
                            guest={'error':'integration-nonpass'},integration_receipt={'complete':False})
                received=[]
                def send(connection):
                    self.assertTrue(connection.recv(4096).endswith(b'\n'))
                    for frame in a.frames(raw,CANDIDATE,RUN,complete=complete,gaps=gaps,overflow=overflow):
                        connection.sendall(a.wire(frame))
                    connection.settimeout(.03)
                    # Model the existing worker's bounded ACK wait before its final report.
                    with self.assertRaises(TimeoutError): connection.recv(257)
                    connection.settimeout(2)
                    connection.sendall(a.encoded(report)+b'\n')
                    # EOF after the final report, never a durable ACK for incomplete bytes.
                    received.append(connection.recv(257))
                path,thread,errors=self.serve(root,send);output=Path(root)/'output'
                result=client.exchange(path,self.request(),integration_output=output)
                thread.join(2);self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
                self.assertEqual(result,report);self.assertEqual(received,[b''])
                prefix,receipt=a.retained(output,RUN)
                self.assertEqual(prefix,raw);self.assertFalse(receipt['client_durable'])
                self.assertFalse(receipt['complete']);self.assertEqual(receipt['original_transfer'],'uncertain')

    def test_empty_export_cannot_promote_a_claimed_success(self):
        with tempfile.TemporaryDirectory() as root:
            normal=dict(scope=a.SELECTION,exit_code=0,binaries={n:'f'*64 for n in ('world','zone','shared_memory')},
                        fixture_sha256=a.FIXTURE_SHA,process_outcomes=[],native_cleanup=True,database_cleanup=True,
                        summary=dict(__import__('actor_integration').initial_summary(),outcome=1,case_outcomes=[1]*3,check_results=[1]*12))
            request=self.request()
            report=dict(version=1,exit_code=0,run_id=RUN,scope='worker-build',operation='build',cleanup_complete=True,
                        vm_started=True,candidate=CANDIDATE,tree=TREE,payload_sha256=request['sha256'],
                        guest=dict(normal_world=normal,zone_sha256='f'*64),coverage=['actor-population-integration'])
            def send(connection):
                connection.recv(4096)
                for frame in a.frames(b'',CANDIDATE,RUN,complete=False,gaps=True,overflow=False): connection.sendall(a.wire(frame))
                connection.sendall(a.encoded(report)+b'\n')
                self.assertEqual(connection.recv(257),b'')
            path,thread,errors=self.serve(root,send);output=Path(root)/'output'
            with self.assertRaisesRegex(ValueError,'Integration export incomplete'):
                client.exchange(path,request,integration_output=output)
            thread.join(2);self.assertFalse(thread.is_alive());self.assertEqual(errors,[])
            self.assertFalse(a.retained(output,RUN)[1]['client_durable'])


if __name__=='__main__': unittest.main()
