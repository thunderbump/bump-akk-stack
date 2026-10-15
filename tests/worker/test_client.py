"""Socket-level foreground results and failures, without root or a worker service."""
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation/worker'))
import client


class Client(unittest.TestCase):
    def test_execution_requests_are_never_retried_after_connection_reset(self):
        for operation in ('build', 'smoke'):
            with self.subTest(operation=operation), patch.object(client, 'exchange_once', side_effect=ConnectionResetError) as once:
                with self.assertRaises(ConnectionResetError):
                    client.exchange('/unused', dict(version=1,operation=operation))
                once.assert_called_once()

    def exchange(self,result,request=None):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'worker.sock'
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
                server.bind(str(path));server.listen(1)
                def respond():
                    connection,_=server.accept()
                    with connection:
                        self.received=json.loads(connection.recv(4096))
                        connection.sendall(result)
                thread=threading.Thread(target=respond);thread.start()
                try:return client.exchange(path,request or {'version':1,'operation':'check'})
                finally:thread.join(2)

    def test_readiness_retries_a_connection_dropped_during_previous_service_cleanup(self):
        report = dict(version=1,scope='worker-readiness',operation='check',exit_code=0,
                      vm_started=False,checks={'kvm':True})
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'busy.sock'
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
                server.bind(str(path));server.listen(2);server.settimeout(.8)
                errors = []
                def respond():
                    try:
                        first,_ = server.accept()
                        first.close()  # Mirrors systemd MaxConnections dropping a new connection.
                        second,_ = server.accept()
                        with second:
                            second.recv(4096)
                            second.sendall((json.dumps(report)+'\n').encode())
                    except Exception as error:
                        errors.append(error)
                thread=threading.Thread(target=respond);thread.start()
                try:
                    self.assertEqual(client.exchange(path,dict(version=1,operation='check')),report)
                finally:
                    thread.join(2)
                self.assertFalse(errors,errors)

    def test_read_only_request_and_readiness_report(self):
        report=dict(version=1,scope='worker-readiness',operation='check',exit_code=0,vm_started=False,checks={'kvm':True})
        self.assertEqual(self.exchange((json.dumps(report)+'\n').encode()),report)
        self.assertEqual(self.received,dict(version=1,operation='check'))

    def test_smoke_exit_matches_checked_report(self):
        for code in (0,1,2):
            report=dict(version=1,scope='worker-smoke',operation='smoke',exit_code=code,
                        vm_started=True,cleanup_complete=True,control='assertion')
            self.assertEqual(self.exchange((json.dumps(report)+'\n').encode(),
                             dict(version=1,operation='smoke',control='assertion'))['exit_code'],code)

    def test_build_result_binds_candidate_tree_and_payload(self):
        request = dict(version=1, operation='build', candidate='a'*40, tree='b'*40, bytes=3, sha256='c'*64)
        report = dict(version=1, scope='worker-build', operation='build', exit_code=0,
                      vm_started=True, cleanup_complete=True, candidate=request['candidate'],
                      tree=request['tree'], payload_sha256=request['sha256'])
        self.assertEqual(self.exchange((json.dumps(report)+'\n').encode(), request), report)
        for field in ('candidate', 'tree', 'payload_sha256', 'cleanup_complete'):
            changed = dict(report, **{field: False})
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'mismatched build'):
                self.exchange((json.dumps(changed)+'\n').encode(), request)

    def test_last_result_observation_preserves_nested_smoke_failure(self):
        report=dict(version=1,scope='worker-observation',operation='last-result',exit_code=0,
                    result={'exit_code':2,'cleanup_complete':False})
        self.assertEqual(self.exchange((json.dumps(report)+'\n').encode(),
                         dict(version=1,operation='last-result')),report)
        self.assertEqual(self.received['operation'],'last-result')
        with self.assertRaisesRegex(RuntimeError,'Incomplete last-result'):
            self.exchange(b'{"version":1,"exit_code":0}\n',dict(version=1,operation='last-result'))

    def test_missing_large_malformed_and_incomplete_success_refuse(self):
        for data in (b'',b'{}\n',b'x'*(client.REPORT_LIMIT+1)+b'\n',
                     b'{"version":1,"exit_code":0}\n'):
            with self.subTest(prefix=data[:30]),self.assertRaises((RuntimeError,ValueError)):
                self.exchange(data)


if __name__=='__main__':unittest.main()
