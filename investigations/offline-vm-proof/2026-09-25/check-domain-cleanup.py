#!/usr/bin/python3
"""Replay asynchronous domain removal and failure without libvirt mutations."""
import importlib.util,json,subprocess
from pathlib import Path
r=Path('/home/bump/.local/state/eqemu-vm-proof');spec=importlib.util.spec_from_file_location('trial',r/'first-vm-trial.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
ident='3cdaaa02-2622-431d-9b71-4903641ea4d0'
responses=iter([ident+'\n',ident+'\n',''])
calls=[]
def query(*args,**kw):
 assert args==('list','--all','--uuid');calls.append(args);return subprocess.CompletedProcess([],0,next(responses),'')
m.virsh=query;m.time.sleep=lambda _:None
m.wait_domain_absent(ident);assert len(calls)==3
m.virsh=lambda *a,**k:subprocess.CompletedProcess([],0,ident+'\n','')
try:m.wait_domain_absent(ident,seconds=0)
except RuntimeError:pass
else:raise AssertionError('Persistent registration accepted')
def broken(*a,**k):raise RuntimeError('Management unavailable')
m.virsh=broken
try:m.wait_domain_absent(ident)
except RuntimeError:pass
else:raise AssertionError('Management failure accepted')
print(json.dumps({'asynchronous_removal':True,'persistent_registration_rejected':True,'management_failure_rejected':True,'vm_started':False}))
