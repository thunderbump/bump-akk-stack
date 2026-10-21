"""Socket-level foreground results and failures, without root or a worker service."""
import contextlib
import io
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
from test_normal_world import baseline


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
                      tree=request['tree'], payload_sha256=request['sha256'],
                      coverage=['normal-world'], guest={'normal_world': baseline(), 'zone_sha256': 'b'*64})
        self.assertEqual(self.exchange((json.dumps(report)+'\n').encode(), request), report)
        for field in ('candidate', 'tree', 'payload_sha256', 'cleanup_complete'):
            changed = dict(report, **{field: False})
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'mismatched build'):
                self.exchange((json.dumps(changed)+'\n').encode(), request)

    def test_large_failed_native_result_survives_socket(self):
        request = dict(version=1, operation='build', candidate='a'*40, tree='b'*40, sha256='c'*64)
        report = dict(version=1, scope='worker-build', operation='build', exit_code=1,
                      vm_started=True, cleanup_complete=True, candidate='a'*40,
                      tree='b'*40, payload_sha256='c'*64,
                      guest={'normal_world': {'exit_code': 1, 'failure_evidence': {'console': 'x'*20000}}})
        self.assertEqual(self.exchange((json.dumps(report)+'\n').encode(), request), report)
        self.assertEqual(self.exchange((json.dumps(dict(version=1, operation='last-result', scope='worker-observation',
            exit_code=0, result=report))+'\n').encode(), dict(version=1, operation='last-result'))['result'], report)

    def test_old_build_only_worker_cannot_pass_normal_world(self):
        request = dict(version=1, operation='build', candidate='a'*40, tree='b'*40, sha256='c'*64)
        report = dict(version=1, operation='build', scope='worker-build', exit_code=0,
                      vm_started=True, cleanup_complete=True, candidate='a'*40, tree='b'*40, payload_sha256='c'*64)
        with self.assertRaises(ValueError):
            self.exchange((json.dumps(report)+'\n').encode(), request)

    def test_progress_can_be_coalesced_with_final_nonpass_report(self):
        event = dict(version=1, kind='progress', name='normal-world-ready')
        report = dict(version=1, exit_code=2, error='cancelled')
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            result = self.exchange((json.dumps(event)+'\n'+json.dumps(report)+'\n').encode(),
                                   dict(version=1, operation='build'))
        self.assertEqual(result, report)
        self.assertEqual(output.getvalue(), 'EQEMU_STAGE normal-world-ready\n')

    def test_progress_is_bounded_and_cannot_substitute_for_final_report(self):
        event = b'{"version":1,"kind":"progress","name":"normal-world-ready"}\n'
        for data, operation in ((event, 'check'), (event+event, 'build'), (event, 'build'),
                                (event.replace(b'normal-world-ready', b'arbitrary'), 'build')):
            with self.subTest(data=data, operation=operation), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(RuntimeError):
                self.exchange(data, dict(version=1, operation=operation))

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
