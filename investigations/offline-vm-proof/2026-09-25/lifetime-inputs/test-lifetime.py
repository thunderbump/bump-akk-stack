import copy,importlib.util,pathlib,unittest
P=pathlib.Path
path=P('/home/bump/.local/state/eqemu-vm-proof/lifetime-tests.py')
spec=importlib.util.spec_from_file_location('suite',path);s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
class Outcomes(unittest.TestCase):
    def facts(self,case):
        result,status={'timeout':('timeout','1'),'cancel':('exit-code','1'),'death':('signal','9')}[case]
        return [case,{'ready_at':2,'checks':{'host_pre_resume':True},'service_result':result,'ok':False,'workload_ok':False,'uuid':'owned','error':'Controller interrupted'},
          {'complete':True,'uuid':'owned','started_at':4,'finished_at':6,'readonly_inputs_unchanged':True},
          {'Result':result,'ExecMainStatus':status,'ExecMainCode':'2' if case=='death' else '1','ActiveState':'failed','MainPID':'0','ControlPID':'0'},
          {'uuid':'owned','at':3,'live_qemu':True,'domain_running':True},True]
    def test_expected(self):
        for case in s.CASES:self.assertTrue(s.classify(*self.facts(case))['case_passed'])
    def test_rejects_false_success(self):
        for case in s.CASES:
            facts=self.facts(case);facts[1]['ok']=True
            self.assertFalse(s.classify(*facts)['case_passed'])
    def test_rejects_missing_or_late_readiness(self):
        for value in [None,4]:
            facts=self.facts('timeout');facts[1]['ready_at']=value
            self.assertFalse(s.classify(*facts)['case_passed'])
    def test_rejects_wrong_result_and_signal(self):
        for key,value in [('Result','success'),('ExecMainStatus','15'),('ExecMainCode','1')]:
            facts=self.facts('death');facts[3][key]=value
            self.assertFalse(s.classify(*facts)['case_passed'])
    def test_rejects_cleanup_failures(self):
        for key,value in [('complete',False),('uuid','other'),('finished_at',200),('readonly_inputs_unchanged',False)]:
            facts=self.facts('cancel');facts[2][key]=value
            self.assertFalse(s.classify(*facts)['case_passed'])
    def test_rejects_live_resources(self):
        for value in ['1','42']:
            facts=self.facts('death');facts[3]['ControlPID']=value
            self.assertFalse(s.classify(*facts)['case_passed'])
        facts=self.facts('death');facts[-1]=False
        self.assertFalse(s.classify(*facts)['case_passed'])
    def test_wrong_target_refused(self):
        from unittest.mock import patch,Mock
        m=Mock();m.UNIT='owned.service';m.SCRIPT=P('/wrong/controller.py')
        with patch.object(s.os,'pidfd_open',return_value=99),patch.object(s.os,'close'),patch.object(s,'properties',return_value={'MainPID':str(s.os.getpid()),'ActiveState':'active'}),patch.object(s.signal,'pidfd_send_signal') as send:
            with self.assertRaises(RuntimeError):s.kill_controller(m,{'MainPID':str(s.os.getpid())})
            send.assert_not_called()
    def test_residual_domain_reaches_rescue(self):
        from unittest.mock import Mock
        m=Mock();m.virsh.return_value.stdout='owned\n'
        self.assertFalse(s.absent(m,{'uuid':'owned'}))
    def test_management_error_never_means_absent(self):
        from unittest.mock import Mock
        m=Mock();m.virsh.side_effect=RuntimeError('management error')
        with self.assertRaises(RuntimeError):s.absent(m,{'uuid':'owned'})
    def test_first_case_failure_stops_suite(self):
        from unittest.mock import patch
        with patch.object(s,'properties',return_value={'MemoryMax':str(64*1024**2),'MemorySwapMax':'0'}),patch.object(s,'write'),patch.object(s,'execute_case',side_effect=RuntimeError('failed')) as execute,patch.object(s.signal,'signal'):
            self.assertEqual(s.supervise(),1);self.assertEqual(execute.call_count,1)
if __name__=='__main__':unittest.main()
