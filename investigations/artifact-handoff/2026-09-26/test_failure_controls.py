import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest


class PublicationTests(unittest.TestCase):
    def exercise(self, inject):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'producer';root.mkdir()
            evidence=root/'evidence';evidence.mkdir()
            def write(path,value):path.write_text(json.dumps(value))
            namespace={'ROOT':root,'EVIDENCE':evidence,'GIB':1024**3,'CASE':'producer',
                       'cleanup':lambda preserve:0,'json':json,'os':os,'write_json':write,
                       'digest':lambda p:hashlib.sha256(p.read_bytes()).hexdigest()}
            exec(Path(__file__).with_name('worker_extension.py').read_text(),namespace)
            custody=namespace['CUSTODY'];write(custody,{'eligible':False})
            write(evidence/'report.json',{'ok':True,'workload_ok':True})
            write(evidence/'cleanup.json',{'complete':True})
            if inject:
                exec(Path(__file__).with_name('control_worker.py').read_text().replace('@CONTROL@','publish'),namespace)
            result=namespace['cleanup']()
            report=json.loads((evidence/'report.json').read_text())
            pending=json.loads(custody.read_text())
            if inject:
                self.assertEqual(result,1)
                self.assertFalse(pending['eligible'])
                self.assertFalse(report['ok'])
                self.assertTrue(report['workload_ok'])
                self.assertEqual(report['publication_error'],'Intentional custody finalization failure')
                self.assertTrue(json.loads((evidence/'cleanup.json').read_text())['complete'])
                self.assertTrue((evidence/'publication-fault.json').exists())
            else:
                self.assertEqual(result,0)
                self.assertTrue(pending['eligible'])
                self.assertEqual(stat.S_IMODE(custody.stat().st_mode),0o600)

    def test_finalization_failure_preserves_pending_and_completed_cleanup(self):self.exercise(True)
    def test_successful_finalization_is_atomic_and_private(self):self.exercise(False)


class AcceptanceTests(unittest.TestCase):
    def test_only_intended_failure_and_complete_cleanup_pass(self):
        namespace={'quiescent':lambda props:props.get('ActiveState')=='inactive'}
        exec(Path(__file__).with_name('control_suite.py').read_text(),namespace)
        accept=namespace['control_acceptance']
        cleanup={'uuid':'fixed','complete':True,'readonly_inputs_unchanged':True,'started_at':1,'finished_at':2}
        props={'ActiveState':'inactive','Result':'exit-code'}
        for case in ['cancel','publish']:
            report={'uuid':'fixed','ok':False,'checks':{'host_pre_resume':True},'workload_ok':case=='publish'}
            if case=='cancel':report.update(export_started=True,error='Controller interrupted')
            else:report['publication_error']='Intentional custody finalization failure'
            pending=None if case=='cancel' else {'eligible':False}
            fault=None if case=='cancel' else {'injected':True,'operation':'finalize-custody'}
            def call(r=report,c=cleanup,p=pending,f=fault,cancel=True,absent=True):
                return accept(case,r,c,props,{'uuid':'fixed'},absent,p,f,cancel)['case_passed']
            self.assertTrue(call())
            self.assertFalse(call(r=dict(report,ok=True)))
            self.assertFalse(call(c=dict(cleanup,complete=False)))
            self.assertFalse(call(p={'eligible':True}))
            self.assertFalse(call(absent=False))
            if case=='cancel':
                self.assertFalse(call(cancel=False))
                self.assertFalse(call(r=dict(report,error='Unexpected crash')))
                self.assertFalse(call(r=dict(report,export_started=False)))
            else:
                self.assertFalse(call(f=None))
                self.assertFalse(call(r=dict(report,publication_error='Unexpected crash')))


if __name__=='__main__':unittest.main()
