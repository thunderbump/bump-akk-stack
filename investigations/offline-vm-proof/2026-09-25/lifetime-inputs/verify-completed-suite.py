"""Read-only follow-up of completed receipts and observable host resources."""
from pathlib import Path
import datetime,hashlib,json,subprocess
P=Path
root=P('/var/lib/eqemu-vm-proof/lifetime-tests')
def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def unit(name):
 p=subprocess.run(['systemctl','show',name,'-p','ActiveState','-p','Result','-p','MainPID','-p','ControlPID','-p','ExecMainStatus'],check=True,text=True,capture_output=True)
 return dict(x.split('=',1) for x in p.stdout.splitlines())
suite=read(root/'suite-result.json');cleanup=read(root/'suite-cleanup.json')
assert suite['suite_passed'] is True and suite['cases_passed'] is True and suite['service_result']=='success'
assert cleanup['complete'] is True and cleanup['rescued']==[]
u=unit('eqemu-vm-lifetime-suite.service');assert u['MainPID']==u['ControlPID']=='0' and u['ActiveState']=='inactive'
domains=subprocess.run(['virsh','--readonly','-c','qemu:///system','list','--all','--uuid'],check=True,capture_output=True,text=True).stdout.split()
summary={'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'suite_passed':True,'suite_started_at':suite['started_at'],'suite_finished_at':cleanup['finished_at'],'cases':{},'hashes':{x:sha(root/x) for x in ['suite-result.json','suite-cleanup.json']}}
for case,expected,status in [('timeout','timeout','1'),('cancel','exit-code','1'),('death','signal','9')]:
 e=root/case/'evidence';result=read(e/'case-result.json');attempt=read(e/'report.json');c=read(e/'cleanup.json');ident=attempt['uuid']
 assert result['case_passed'] is True and all(v is True for v in result['checks'].values())
 assert attempt['ok'] is False and attempt['workload_ok'] is False and attempt['service_result']==expected
 assert c['complete'] and c['readonly_inputs_unchanged'] and ident not in domains
 assert not (root/case/'data').exists()
 for parent in ['/run/systemd/system','/sys/fs/cgroup']:assert not P(parent,'eqemuvmlifetime'+case+'.slice').exists()
 u=unit('eqemu-vm-lifetime-'+case+'.service');assert u['MainPID']==u['ControlPID']=='0' and u['Result']==expected and u['ExecMainStatus']==status
 p=P('/proc',str(result['injection']['qemu_pid']),'cmdline')
 assert not p.exists() or ident.encode() not in p.read_bytes().split(b'\0')
 assert attempt['guest_report_untrusted']['ok'] is True and len(attempt['guest_report_untrusted']['checks'])==10
 summary['cases'][case]={'uuid':ident,'started_at':result['started_at'],'ready_at':attempt['ready_at'],'finished_at':result['finished_at'],'cleanup_seconds':c['finished_at']-c['started_at'],'result':expected,'status':status,'case_passed':True,'unit_properties':u,'resources_before_injection':result['resources_before_injection'],'serial_bytes':(e/'serial.log').stat().st_size,'evidence_bytes':sum(p.stat().st_size for p in e.rglob('*') if p.is_file()),'hashes':{x:sha(e/x) for x in ['report.json','cleanup.json','case-result.json','serial.log']}}
summary['baseline_report_unchanged']=sha(P('/var/lib/eqemu-vm-proof/first-trial/evidence/report.json'))=='84cb67af1b454509da2f5a2cd9a3f194d6401e07a1703f67de484c5fb772c16a'
assert summary['baseline_report_unchanged']
summary['profile_absence_authority']='privileged cleanup receipts; not independently readable without root'
P('/home/bump/.local/state/eqemu-vm-proof/lifetime-inputs/completed-suite-verification.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
