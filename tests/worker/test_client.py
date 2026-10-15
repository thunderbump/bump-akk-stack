"""Socket-level foreground results and failures, without root or a worker service."""
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation/worker'))
import client


class Client(unittest.TestCase):
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

    def test_missing_large_malformed_and_incomplete_success_refuse(self):
        for data in (b'',b'{}\n',b'x'*(client.REPORT_LIMIT+1)+b'\n',
                     b'{"version":1,"exit_code":0}\n'):
            with self.subTest(prefix=data[:30]),self.assertRaises((RuntimeError,ValueError)):
                self.exchange(data)


if __name__=='__main__':unittest.main()
