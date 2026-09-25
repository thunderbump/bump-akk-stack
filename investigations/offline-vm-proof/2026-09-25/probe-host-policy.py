#!/usr/bin/python3
"""Bounded AppArmor prerequisite probe; no VM, production access or persistent policy.

Run --check without sudo to compile the temporary policy without loading it.
Run with sudo to gather libvirt capabilities, apply a unique temporary profile,
compare synthetic positive/negative controls, then remove profile and scratch.
JSON on stdout is the only retained output. No arbitrary command/path arguments.
"""
import argparse
import errno
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET

ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
PARSER = '/usr/sbin/apparmor_parser'
ROOT = Path('/var/lib/eqemu-vm-proof')


def command(argv, *, data=None, timeout=30):
    return subprocess.run(argv, input=data, text=True, capture_output=True,
                          timeout=timeout, env=ENV, cwd='/', check=False)


def policy(name, directory):
    # These added deny rules will also be needed by the later VM profile.
    # Python permissions below exist only to run this synthetic host probe.
    return f'''#include <tunables/global>
profile {name} flags=(attach_disconnected) {{
  #include <abstractions/libvirt-qemu>
  /usr/bin/python3.12 rix,
  /usr/lib/python3.12/** r,
  /usr/lib/python3.12/lib-dynload/*.so mr,
  {directory}/probe.py r,
  {directory}/allowed.txt r,
  {directory}/scratch.txt rw,
  {directory}/allowed.sock rw,
  unix (create, connect, send, receive) type=stream,
  # Explicit synthetic denial overrides any inherited allowance.
  audit deny {directory}/denied.txt rwkl,
  audit deny {directory}/sibling.txt rwkl,
  audit deny {directory}/denied.sock rw,
  audit deny network inet,
  audit deny network inet6,
  audit deny /home/** rwkl,
  audit deny /root/** rwkl,
  audit deny /mnt/** rwkl,
  audit deny /media/** rwkl,
  audit deny /var/lib/docker/** rwkl,
  audit deny /{{var/,}}run/docker.sock rw,
  audit deny /{{var/,}}run/libvirt/libvirt*-sock* rw,
  audit deny /{{var/,}}run/libvirt/virt*-sock* rw,
}}
'''


PROBE = r'''import errno,json,os,socket,sys
from pathlib import Path
root=Path(sys.argv[1]); checks={}
checks['uid']=os.getuid()
for name in ['allowed.txt','denied.txt','sibling.txt']:
    try: checks[name]={'read':(root/name).read_text()=='synthetic-canary\n'}
    except OSError as e:checks[name]={'errno':e.errno}
try:
    (root/'scratch.txt').write_text('synthetic-output\n');checks['scratch_write']=True
except OSError as e:checks['scratch_write']={'errno':e.errno}
for name in ['allowed.sock','denied.sock']:
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(2);s.connect(str(root/name));checks[name]={'connected':True}
    except OSError as e:checks[name]={'errno':e.errno}
for family,label in [(socket.AF_INET,'ipv4'),(socket.AF_INET6,'ipv6')]:
    try:
        with socket.socket(family,socket.SOCK_STREAM) as s:checks[label]={'created':True}
    except OSError as e:checks[label]={'errno':e.errno}
print(json.dumps(checks,sort_keys=True))
'''


def require_directory(path):
    st=path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError('Unsafe root-owned directory: '+str(path))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    if args.check:
        r=command([PARSER,'-Q','-K','-j','1'],data=policy('eqemu-vm-proof-syntax','/var/lib/eqemu-vm-proof/syntax'))
        print(json.dumps({'syntax_exit':r.returncode,'diagnostic':r.stderr,'kernel_policy_loaded':False}))
        return r.returncode
    if os.geteuid()!=0:
        print('Run with sudo for this bounded host-policy probe, or --check for syntax only.',file=sys.stderr)
        return 2
    os.umask(0o077)
    account=pwd.getpwnam('libvirt-qemu')
    if account.pw_uid==0:raise RuntimeError('QEMU identity must be non-root')
    name='eqemu-vm-proof-probe-'+uuid.uuid4().hex
    report={'schema_version':1,'profile':name,'vm_started':False,'complete':False,
            'scope':'synthetic host AppArmor deny-rule prerequisite; not complete VM isolation',
            'cleanup':{},'checks':{}}
    directory=None;listeners=[];created_root=False
    try:
        for label,argv in [
            ('capabilities',['/usr/bin/virsh','-c','qemu:///system','capabilities']),
            ('domain_capabilities',['/usr/bin/virsh','-c','qemu:///system','domcapabilities','--virttype','kvm','--arch','x86_64','--machine','pc-q35-8.2']),
        ]:
            r=command(argv)
            if r.returncode:raise RuntimeError(label+': '+r.stderr.strip())
            report[label]=r.stdout
        caps=ET.fromstring(report['capabilities'])
        models=[x.findtext('model') for x in caps.findall('./host/secmodel')]
        if 'apparmor' not in models:raise RuntimeError('AppArmor not advertised by libvirt')
        dc=ET.fromstring(report['domain_capabilities'])
        if dc.findtext('domain')!='kvm':raise RuntimeError('KVM domain required')
        if not ROOT.exists():
            ROOT.mkdir(mode=0o755);created_root=True
            ROOT.chmod(0o755)  # Restore traversal after the restrictive process umask.
        require_directory(ROOT)
        directory=Path(tempfile.mkdtemp(prefix='policy-probe-',dir=ROOT));directory.chmod(0o755)
        for filename in ['allowed.txt','denied.txt','sibling.txt']:
            p=directory/filename;p.write_text('synthetic-canary\n');p.chmod(0o644)
        p=directory/'probe.py';p.write_text(PROBE);p.chmod(0o644)
        p=directory/'scratch.txt';p.touch();os.chown(p,account.pw_uid,account.pw_gid);p.chmod(0o600)
        for filename in ['allowed.sock','denied.sock']:
            s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listeners.append(s)
            s.bind(str(directory/filename));os.chmod(directory/filename,0o666);s.listen(8)
        argv=['/usr/sbin/runuser','-u','libvirt-qemu','--','/usr/bin/python3','-I','-S',str(directory/'probe.py'),str(directory)]
        r=command(argv)
        if r.returncode:raise RuntimeError('Unconfined probe failed: '+r.stderr)
        positive=json.loads(r.stdout);report['positive']=positive
        expected_files=all(positive.get(x)=={'read':True} for x in ['allowed.txt','denied.txt','sibling.txt'])
        expected_sockets=all(positive.get(x)=={'connected':True} for x in ['allowed.sock','denied.sock'])
        expected_network=all(positive.get(x)=={'created':True} for x in ['ipv4','ipv6'])
        if not (positive.get('uid')==account.pw_uid and expected_files and expected_sockets and expected_network and positive.get('scratch_write') is True):
            raise RuntimeError('Positive controls did not pass')
        profile=policy(name,str(directory))
        r=command([PARSER,'-a','-K','-j','1'],data=profile)
        if r.returncode:raise RuntimeError('Profile load failed: '+r.stderr)
        active=Path('/sys/kernel/security/apparmor/profiles').read_text()
        if name+' (enforce)' not in active:raise RuntimeError('Profile is not enforcing')
        argv=['/usr/sbin/runuser','-u','libvirt-qemu','--','/usr/bin/aa-exec','-p',name,'--','/usr/bin/python3','-I','-S',str(directory/'probe.py'),str(directory)]
        r=command(argv)
        report['confined_process']={'exit_code':r.returncode,'stderr':r.stderr[:8192]}
        if r.returncode:raise RuntimeError('Confined probe did not run; not denial proof')
        confined=json.loads(r.stdout);report['confined']=confined
        report['checks']['positive_inside_profile']=confined.get('uid')==account.pw_uid and confined.get('allowed.txt')=={'read':True} and confined.get('scratch_write') is True and confined.get('allowed.sock')=={'connected':True}
        for item in ['denied.txt','sibling.txt','denied.sock','ipv4','ipv6']:
            report['checks'][item]=confined.get(item,{}).get('errno') in [errno.EACCES,errno.EPERM]
        report['checks']['sentinels_unchanged']=all((directory/x).read_text()=='synthetic-canary\n' for x in ['allowed.txt','denied.txt','sibling.txt'])
        if not all(report['checks'].values()):raise RuntimeError('One or more confinement checks failed')
        report['complete']=True
    except Exception as exc:
        report['error']=str(exc)
    finally:
        try:
            present=name in Path('/sys/kernel/security/apparmor/profiles').read_text()
            if present:
                r=command([PARSER,'-R','-K','-j','1'],data=policy(name,str(directory)))
                report['cleanup']['profile_remove_exit']=r.returncode
            report['cleanup']['profile_absent']=name not in Path('/sys/kernel/security/apparmor/profiles').read_text()
        except Exception as exc:
            report['cleanup']['profile_absent']=False
            report['cleanup']['profile_error']=str(exc)
        for s in listeners:s.close()
        try:
            if directory is not None:
                # Exact mkdtemp-owned tree only; no user-selected deletion paths.
                require_directory(directory)
                if report['cleanup']['profile_absent']:
                    shutil.rmtree(directory);report['cleanup']['scratch_absent']=not directory.exists()
                else:
                    report['cleanup']['scratch_absent']=False
                    report['retained_scratch']=str(directory)
            else:report['cleanup']['scratch_absent']=True
            if created_root and ROOT.exists() and not any(ROOT.iterdir()):ROOT.rmdir()
        except Exception as exc:
            report['cleanup']['scratch_absent']=False
            report['cleanup']['scratch_error']=str(exc)
        report['complete']=report['complete'] and report['cleanup']['profile_absent'] and report['cleanup']['scratch_absent']
        print(json.dumps(report,indent=2))
    return 0 if report['complete'] else 1


if __name__=='__main__':sys.exit(main())
