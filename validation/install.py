#!/usr/bin/python3 -I
"""Install the separate fixed build helper; leave the diagnostic runner untouched."""
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import types
import subprocess
import sys

HERE=Path(__file__).resolve().parent
BASE=Path('/var/lib/eqemu-build')
LIB=Path('/usr/local/lib/eqemu-build')
ENTRY=Path('/usr/local/sbin/eqemu-build-request')
CLIENT=Path('/usr/local/bin/eqemu-validate')
POLICY=Path('/etc/sudoers.d/eqemu-build')
RULE='%eqemu-test ALL=(root) NOPASSWD: NOSETENV: /usr/local/sbin/eqemu-build-request ""\n'


def verified_package(directory):
    # Bootstrap without importing any code from the mutable preparation directory.
    def read(path,limit):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size>limit:raise ValueError('Invalid package file')
            data=stream.read(limit+1)
            if len(data)>limit:raise ValueError('Package file grew')
            return data
    raw=read(directory/'manifest.json',16384)
    manifest=json.loads(raw);package={}
    for name,digest in manifest['files'].items():
        if not re.fullmatch('[a-zA-Z0-9_.-]+',name):raise ValueError('Invalid package name')
        data=read(directory/name,256*1024)
        if hashlib.sha256(data).hexdigest()!=digest:raise ValueError('Package changed: '+name)
        package[name]=data
    return raw,package


def install():
    if os.geteuid()!=0 or len(sys.argv)!=1:
        raise ValueError('Run this reviewed installer once with sudo; no arguments')
    os.umask(0o077)
    # This package is explicitly reviewed by the administrator. Its hashes detect
    # changes after preparation; they are not a substitute for that review.
    raw,package=verified_package(HERE)
    support=types.ModuleType('installer_support')
    support.__file__=str(HERE/'installer_support.py')
    exec(compile(package['installer_support.py'],support.__file__,'exec'),support.__dict__)
    account=pwd.getpwnam('bump');group=grp.getgrnam('eqemu-test')
    if account.pw_name not in group.gr_mem and account.pw_gid!=group.gr_gid:
        raise ValueError('Existing diagnostic submitter group is required')
    for path in (BASE,LIB,ENTRY,CLIENT,POLICY):
        support.parent_safe(path)
        if path.exists() or path.is_symlink():raise ValueError('Refuse existing installation: '+str(path))
    if shutil.disk_usage('/var/lib').free<180*1024**3:raise ValueError('Need 180 GiB free disk')
    release=hashlib.sha256(raw).hexdigest()[:16];version=LIB/release
    inputs=json.loads(package['host-inputs.json'])
    if set(inputs) not in ({'base.qcow2','fixture.iso'}, {'base.qcow2','fixture.iso','runtime.iso'}) or sum(x['bytes'] for x in inputs.values())>2*1024**3:
        raise ValueError('Unexpected installed input budget')
    support.make_dir(BASE,0o711);support.make_dir(LIB,0o755);support.make_dir(version,0o755)
    record={'enabled':False,'version':str(version),'manifest_sha256':hashlib.sha256(raw).hexdigest()}
    def save():
        (BASE/'installation.json').write_text(json.dumps(record)+'\n');(BASE/'installation.json').chmod(0o600)
    save()
    try:
        for name,data in package.items():support.write(version/name,data,0o644)
        support.write(version/'manifest.json',raw,0o644)
        for name,mode in [('runs',0o711),('inputs',0o700),('uploads',0o711)]:support.make_dir(BASE/name,mode)
        support.make_dir(BASE/'uploads'/str(account.pw_uid),0o700)
        os.chown(BASE/'uploads'/str(account.pw_uid),account.pw_uid,account.pw_gid)
        support.write(BASE/'request.lock',b'',0o600)
        for name,facts in inputs.items():support.copy_input(facts['source'],BASE/'inputs'/name,facts)
        helper='#!/bin/sh\n[ "$#" -eq 0 ] || exit 2\nexec /usr/bin/python3 -I '+str(version/'host.py')+'\n'
        client='#!/bin/sh\nexec /usr/bin/python3 -I '+str(version/'candidate.py')+' "$@"\n'
        support.write(ENTRY,helper.encode(),0o755);support.write(CLIENT,client.encode(),0o755)
        # Validate installed module imports and manifest before granting access.
        code='import sys; sys.path.insert(0,'+repr(str(version))+'); import host; host.S.verify_installation()'
        support.run(['/usr/bin/python3','-I','-c',code])
        draft=BASE/'sudoers.checked';support.write(draft,RULE.encode(),0o440)
        support.run(['/usr/sbin/visudo','-cf',str(draft)])
        support.write(POLICY,RULE.encode(),0o440);support.run(['/usr/sbin/visudo','-c'])
        record['enabled']=True;save()
        print(json.dumps({'installed':True,'version':str(version),'vm_started':False,
                          'rollback':'sudo python3 -I '+str(version/'disable.py')}))
    except BaseException:
        if POLICY.is_file() and not POLICY.is_symlink() and POLICY.read_text()==RULE:POLICY.unlink()
        record['enabled']=False;save()
        raise

if __name__=='__main__':
    install()
