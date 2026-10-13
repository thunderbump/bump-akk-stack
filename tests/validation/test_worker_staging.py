"""Execute each maintained input-copy loop without launching a worker, guest or service."""
import ast
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from test_reporting_coverage import recipe


class WorkerStaging(unittest.TestCase):
    def test_both_real_initial_loops_bound_dirty_windows_and_verify_destination(self):
        for role in ('producer','consumer'):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                worker=recipe(role+'-worker.py.in')
                tree=ast.parse(Path(worker.__file__).read_text())
                fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='worker')
                loop=next(n for n in ast.walk(fn) if isinstance(n,ast.For) and isinstance(n.target,ast.Tuple))
                code=compile(ast.Module(body=[loop],type_ignores=[]),'actual-'+role+'-input-loop','exec')
                root=Path(tmp);source=root/'source';dest=root/'dest';source.mkdir();dest.mkdir()
                data=b'x'*(20*1024**2);(source/'input').write_bytes(data)
                worker.INPUTS=source;worker.DATA=dest;worker.FILES={'copied':('input',len(data),hashlib.sha256(data).hexdigest())}
                worker.report={'inputs':{}}
                pending=0;peak=0;synced=[];advice=[]
                realwrite=os.fdopen
                class Stream:
                    def __init__(self,stream):self.stream=stream
                    def __enter__(self):return self
                    def __exit__(self,*args):return self.stream.__exit__(*args)
                    def write(self,body):
                        nonlocal pending,peak
                        count=self.stream.write(body);pending+=count;peak=max(peak,pending);return count
                    def __getattr__(self,name):return getattr(self.stream,name)
                def fdopen(fd,mode,*a,**k):
                    stream=realwrite(fd,mode,*a,**k)
                    return Stream(stream) if mode=='wb' else stream
                originalopen=Path.open
                def opened(path,mode='r',*a,**k):
                    stream=originalopen(path,mode,*a,**k)
                    return Stream(stream) if mode=='xb' else stream
                def sync(fd):
                    nonlocal pending
                    synced.append(pending);pending=0
                with patch.object(os,'fdopen',side_effect=fdopen),patch.object(Path,'open',opened),\
                     patch.object(os,'fdatasync',side_effect=sync),patch.object(os,'posix_fadvise',side_effect=lambda *a:advice.append(a)):
                    exec(code,worker.__dict__)
                self.assertLessEqual(peak,16*1024**2)
                self.assertEqual(synced,[16*1024**2,4*1024**2])
                self.assertEqual((dest/'copied').read_bytes(),data)
                self.assertTrue(advice)
                self.assertEqual(worker.report['inputs']['copied'],hashlib.sha256(data).hexdigest())

    def test_digest_completed_read_windows_and_controller_caps(self):
        for role in ('producer','consumer'):
            worker=recipe(role+'-worker.py.in')
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'input';data=b'x'*(20*1024**2);path.write_bytes(data);advice=[]
                with patch.object(os,'posix_fadvise',side_effect=lambda *a:advice.append(a)):
                    self.assertEqual(worker.digest(path),hashlib.sha256(data).hexdigest())
                self.assertEqual([(a[1],a[2]) for a in advice],[(0,16*1024**2),(16*1024**2,4*1024**2)])
                text=Path(worker.__file__).read_text()
                self.assertIn('MemoryMax=960M',text);self.assertIn('MemorySwapMax=0',text)


if __name__=='__main__':unittest.main()
