"""Small checks for cancellation evidence and the cleanup-before-repeat ordering."""
import importlib.util
import json
import os
import hashlib
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

L=load('lifecycle',SOURCE/'lifecycle.py')
C=load('cancel_suite',Path('/home/bump/.local/state/eqemu-vm-proof/runtime-reuse-inputs-05/launcher.py'))
R=load('repeat_suite',Path('/home/bump/.local/state/eqemu-vm-proof/runtime-reuse-inputs-06/launcher.py'))


class Lifecycle(unittest.TestCase):
    def test_launcher_reader_rejects_fifo_symlink_oversize_and_wrong_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);regular=root/'valid.py';data=b'VALUE=7\n';regular.write_bytes(data)
            digest=hashlib.sha256(data).hexdigest()
            self.assertEqual(L.load_verified(regular,digest).VALUE,7)
            fifo=root/'fifo';os.mkfifo(fifo)
            link=root/'link';link.symlink_to(regular)
            oversized=root/'oversized';oversized.write_bytes(b'x'*(256*1024+1))
            for path,expected in [(fifo,digest),(link,digest),(oversized,digest),(regular,'0'*64)]:
                with self.subTest(path=path),self.assertRaises((RuntimeError,OSError)):L.load_verified(path,expected)

    def values(self):
        report={'uuid':'fixed','ok':False,'workload_ok':False,'error':'Controller interrupted'}
        suite={'suite_passed':False,'cancel_requested_at':12,'error':'Supervisor interrupted'}
        cleanup={'complete':True,'rescued':[]};ledger={'active':{}}
        request={'uuid':'fixed','requested_at':12,'ready':{'name':'ready','value':{'zone_connection':True}}}
        return report,suite,cleanup,ledger,request

    def test_expected_cancellation_is_verified_without_promoting_workload(self):
        values=self.values();L.check_outcome('cancel',*values)
        self.assertFalse(values[0]['ok']);self.assertFalse(values[1]['suite_passed'])

    def test_unrelated_failure_and_incomplete_cleanup_are_rejected(self):
        for index,key,value in [(0,'error','disk full'),(0,'ok',True),(1,'error','deadline'),(2,'complete',False),(2,'rescued',['consumer']),(3,'active',{'consumer':{}}),(4,'uuid','wrong')]:
            with self.subTest(key=key,value=value):
                args=list(self.values());args[index][key]=value
                with self.assertRaises(RuntimeError):L.check_outcome('cancel',*args)
        with self.assertRaises(RuntimeError):L.check_outcome('cancel',*self.values()[:4])

    def test_repeat_requires_complete_positive_guest_evidence(self):
        report,suite,cleanup,ledger,_=self.values()
        report.update(diagnostic_complete=True,guest_report_untrusted={'ok':True,'accepted':False,'first_failure':None,'later_errors':[], 'evidence_complete':True,'scenario':{'checks_completed':True}})
        L.check_outcome('repeat',report,suite,cleanup,ledger)
        report['guest_report_untrusted']['evidence_complete']=False
        with self.assertRaises(RuntimeError):L.check_outcome('repeat',report,suite,cleanup,ledger)

    def test_repeat_cannot_start_after_failed_cancellation_verification(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);local=root/'inputs';local.mkdir();calls=[];children={}
            for kind,number in [('cancel','05'),('repeat','06')]:
                (local/('offline-runtime-reuse-'+number+'.py')).write_text('# trusted synthetic launcher\n')
                childroot=root/number
                def setup(kind=kind,childroot=childroot):calls.append(kind);childroot.mkdir()
                children[number]=types.SimpleNamespace(_verified_bytes=b'# trusted synthetic launcher\n',ROOT=childroot,UNIT=number,prerequisites=lambda:None,module=lambda *a,**k:None,
                    setup=setup,properties=lambda _: {},quiescent=lambda _:True,run=lambda *a,**k:None)
            def child(path,expected):return children['05' if '05' in path.name else '06']
            with patch.object(L,'ROOT',root/'result'),patch.object(L,'LOCAL',local),patch.object(L,'LAUNCHERS',{'05':'a','06':'b'}),patch.object(L,'load_verified',side_effect=child),patch.object(L.os,'geteuid',return_value=0),patch.object(L.os,'umask'),patch.object(L.resource,'setrlimit'),patch.object(L.signal,'signal'),patch.object(L,'inspect_finished',side_effect=RuntimeError('cleanup failed')),patch('builtins.print'):
                self.assertEqual(L.main(),1)
            self.assertEqual(calls,['cancel'])

    def test_cancellation_stops_suite_after_readiness(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);evidence=root/'evidence';evidence.mkdir();(evidence/'report.json').write_text('{}')
            worker=types.SimpleNamespace(UNIT='owned-worker',EVIDENCE=evidence)
            props={'Slice':C.CTL,'MemoryMax':str(960*1024**2),'MemorySwapMax':'0'}
            with patch.object(C,'ROOT',root),patch.object(C,'controller_budget'),patch.object(C,'admit',return_value=worker),patch.object(C,'properties',return_value=props),patch.object(C,'quiescent',return_value=False),patch.object(C,'ownership',return_value={'uuid':'fixed'}),patch.object(C,'read',return_value={'scenario_events_untrusted':[{'name':'ready','value':{'zone_connection':True}}]}),patch.object(C,'run',side_effect=RuntimeError('Supervisor interrupted')) as run,patch.object(C.signal,'signal'):
                self.assertEqual(C.supervise(),1)
            run.assert_called_once_with(['systemctl','stop','--no-block',C.UNIT])
            self.assertEqual(json.loads((root/'cancel-request.json').read_text())['uuid'],'fixed')
            self.assertEqual(json.loads((root/'suite-result.json').read_text())['error'],'Supervisor interrupted')

    def test_repeat_has_no_cancellation_or_zone_exit_injection(self):
        import inspect
        self.assertNotIn('cancel-request.json',inspect.getsource(R.supervise))
        for number in ['05','06']:
            guest=load('guest'+number,Path('/home/bump/.local/state/eqemu-vm-proof')/('runtime-reuse-inputs-'+number)/'guest-runtime.py')
            self.assertFalse(guest.STOP_ZONE_AFTER_HEALTH)


if __name__=='__main__':unittest.main()
