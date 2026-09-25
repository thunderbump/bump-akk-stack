#!/usr/bin/python3
"""Replay the observed partition mismatch and reject incorrect io.max limits."""
import importlib.util,json,os,tempfile
from pathlib import Path
root=Path('/home/bump/.local/state/eqemu-vm-proof')
spec=importlib.util.spec_from_file_location('trial',root/'first-vm-trial.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
receipt=json.loads(Path('/var/lib/eqemu-vm-proof/first-trial/evidence/report.json').read_text())
expected=m.io_device_number(os.stat('/var/lib').st_dev)
assert expected=='259:0'
m.verify_io_limits(receipt['limits']['io.max'],expected)
cases=['','259:9 rbps=104857600 wbps=52428800','259:0 rbps=max wbps=52428800','259:0 rbps=1048576000 wbps=52428800','259:0 rbps=104857600 wbps=524288000','259:0 rbps=104857600','259:0 rbps=104857600 rbps=0 wbps=52428800',receipt['limits']['io.max']+'\n'+receipt['limits']['io.max']]
for data in cases:
 try:m.verify_io_limits(data,expected)
 except RuntimeError:pass
 else:raise AssertionError('Incorrect limits accepted: '+data)
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'disk/p2').mkdir(parents=True);(p/'disk/dev').write_text('259:0\n');(p/'disk/p2/dev').write_text('259:2\n');(p/'disk/p2/partition').write_text('2\n');(p/'259:2').symlink_to(p/'disk/p2');(p/'259:0').symlink_to(p/'disk')
 assert m.io_device_number(os.makedev(259,2),p)=='259:0'
 assert m.io_device_number(os.makedev(259,0),p)=='259:0'
 (p/'disk/dev').write_text('not-a-device')
 try:m.io_device_number(os.makedev(259,2),p)
 except RuntimeError:pass
 else:raise AssertionError('Invalid sysfs identity accepted')
print(json.dumps({'captured_case_passed':True,'negative_limit_cases':len(cases),'partition_and_disk_mapping':True,'invalid_mapping_rejected':True,'vm_started':False}))
