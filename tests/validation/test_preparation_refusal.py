"""Actual process and final-event agreement when preparation raises an internal error."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]


class PreparationRefusal(unittest.TestCase):
    def test_internal_errors_are_process_two_with_diagnostics_and_no_admission(self):
        for exception in ('TypeError','KeyError'):
            with self.subTest(exception=exception):
                code="""import sys,json,tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
import candidate
with tempfile.TemporaryDirectory() as tmp:
 root=Path(tmp);(root/'uploads/1000').mkdir(parents=True)
 (root/'profile.json').write_text(json.dumps({'rust':True}))
 with patch.object(candidate,'BASE',root),patch.object(candidate,'HERE',root),patch.object(candidate.os,'geteuid',return_value=1000),patch.object(candidate,'prepare',side_effect=getattr(__import__('builtins'),sys.argv[2])('controlled preparation defect')),patch.object(candidate,'request') as request:
  result=candidate.execute(root)
  assert not request.called
 raise SystemExit(result)
"""
                result=subprocess.run([sys.executable,'-B','-c',code,str(ROOT/'validation'),exception],capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,2,result.stderr)
                final=json.loads(result.stdout.strip())
                self.assertEqual(final['event'],'final');self.assertEqual(final['exit_code'],result.returncode)
                self.assertFalse(final['accepted']);self.assertIsNone(final['run_id'])
                self.assertIn('controlled preparation defect',final['error'])
                self.assertNotIn('Traceback',result.stderr)


if __name__=='__main__':unittest.main()
