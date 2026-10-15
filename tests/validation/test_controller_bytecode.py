"""Actual isolated generated controllers must not add bytecode to sealed helper directories."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_packaging as packaging


class ControllerBytecode(unittest.TestCase):
    def test_isolated_workers_and_launcher_disable_bytecode_before_helper_imports(self):
        fixture = packaging.PackagePreparation(); fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.prepare(); package = fixture.root/'output'
        destination = fixture.root/'rendered'; destination.mkdir()
        def seed(args, **options):Path(args[1]).write_bytes(b'synthetic seed')
        with patch.object(packaging.render.subprocess, 'run', side_effect=seed):
            packaging.render.render('0123456789', packaging.FACTS, destination, package)
        code = '''import json,runpy,sys
from pathlib import Path
script=Path(sys.argv[1]);controller=runpy.run_path(str(script),run_name='controller_probe')
if script.name=='launcher.py':
    worker=controller['module']('producer',local=True)
    namespace=worker.__dict__
else:namespace=controller
protocol=namespace['BuildProtocol']('nonce');protocol.ready=True;protocol.preflight=True
scope=type(protocol).accept.__globals__
consumer=script.name=='consumer-worker.py'
if consumer:scope['VALIDATION_PROFILE']='actor-lifecycle-v1'
try:
    protocol.accept({'kind':'observation','nonce':'nonce',
                     'name':'actor-runtime' if consumer else 'rust-preflight','value':{}})
except (ValueError,RuntimeError):pass
assert ('actor' if consumer else 'rust') in sys.modules
print(json.dumps({'isolated':sys.flags.isolated,'disabled':sys.dont_write_bytecode,
                  'cache':any(Path(sys.argv[2]).rglob('__pycache__')) or any(script.parent.rglob('__pycache__'))}))
'''
        for name in ('producer-worker.py','consumer-worker.py','launcher.py'):
            with self.subTest(entry=name):
                # -I ignores this environment setting; the controller must set the flag itself.
                result = subprocess.run([sys.executable, '-I', '-c', code,
                                         str(destination/name), str(package)],
                    env={**os.environ, 'PYTHONDONTWRITEBYTECODE':'1'},
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), {'isolated':1,'disabled':True,'cache':False})


if __name__ == '__main__':unittest.main()
