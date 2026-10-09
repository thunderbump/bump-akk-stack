#!/usr/bin/python3 -I
"""Finite debugger package upgrade, one failed-receipt archive and reversible runtime-media swap. Never starts jobs."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
sys.dont_write_bytecode = True
PREP = Path('/home/bump/.local/state/eqemu-debugger-inputs-20261008/activation-v1')
PACKAGE = Path('/home/bump/.local/state/eqemu-debugger-inputs-20261008/package-v3')
MANIFEST = '5f0f76f3b6cb4d7a427efc24672171ea75681fcba9940f03f528779cf3237055'
FINAL_PACKAGE_APPROVED = True # independently reviewed source and successful offline provisioning proof
OLD_HASH = '9f298e87d6e466e54e6e58e10dcd643d2d2700b7d94a4ab2960a5620aec17812'
BASE = Path('/var/lib/eqemu-build')
LIB = Path('/usr/local/lib/eqemu-build')
OLD = LIB/OLD_HASH[:16]
NEW = LIB/MANIFEST[:16]
STAGE = LIB/('.debugger-20261008-'+MANIFEST[:16])
BACKUP = BASE/'activation-backup-20261008-central-t0e1.4.2.5'
INITIAL = BASE/'activation-backup-20261006-central-t0e1.4.2.4'
INITIAL_ARCHIVED = ['14bf4ace36']
ARCHIVE = BACKUP/'archived-runs'
RUNS = ['0c7f619915','298c315718','9924578091','a83098b0d0','bdf35611d3']
ARCHIVED = ['9924578091']
RETAINED = [r for r in RUNS if r not in ARCHIVED]
HELPER = Path('/usr/local/sbin/eqemu-build-request')
CLIENT = Path('/usr/local/bin/eqemu-validate')
STATE = BASE/'installation.json'
POLICY = Path('/etc/sudoers.d/eqemu-build')
RULE = b'%eqemu-test ALL=(root) NOPASSWD: NOSETENV: /usr/local/sbin/eqemu-build-request ""\n'
RUNTIME = {'source':'/home/bump/.local/state/eqemu-vm-proof/runtime-debugger-inputs-20261008/runtime-inputs.iso',
           'bytes':196659200,'sha256':'a714115dcd1c654df9fcbdad41d41d367cebf042f57b8813b8dee7d203f731bb'}
AFK = {Path('/home/bump/.config/afk/config.toml'):'e56445debe8e232e40d4ac91783f84c685c6dfc4443fa508bf2df42beb2aa44c',
       Path('/home/bump/.config/afk/config.json'):'38e57f04ff5a6c43902e77bc6242ef055b95d9f1b2f9d83453772173adfbb552'}
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}
PROOF = Path('/var/lib/eqemu-vm-proof/debugger-proof-20261008b')
PROOF_UUID = '361f97c0-fa4a-4f65-86b3-d3d7edf12ada'
PROOF_REPORT_SHA = 'ff937e27d583e75015012fd5468f2a7005237c64c5775307203bba2a21bd7b4b'


def sha(data): return hashlib.sha256(data).hexdigest()
def canonical(value): return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def exists(path): return path.exists() or path.is_symlink()
def safe(path, directory=False):
    for parent in reversed(path.parents):
        s=parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:
            raise RuntimeError('Unsafe administrator ancestor '+str(parent))
    s=path.lstat()
    if s.st_uid!=0 or s.st_mode&0o022 or not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)):
        raise RuntimeError('Unsafe administrator path '+str(path))
    return s


def opened(path, limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    stream=os.fdopen(fd,'rb')
    try:
        s=os.fstat(stream.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_size>limit: raise RuntimeError('Invalid bounded file '+str(path))
        return stream,s
    except BaseException: stream.close();raise


def read(path, limit=256*1024, administrator=True):
    if administrator: safe(path)
    stream,before=opened(path,limit)
    with stream:
        data=stream.read(limit+1);after=os.fstat(stream.fileno())
        if len(data)>limit or len(data)!=before.st_size or (before.st_ino,before.st_dev,before.st_mtime_ns)!=(after.st_ino,after.st_dev,after.st_mtime_ns):
            raise RuntimeError('Bounded file changed '+str(path))
        return data


def facts(path, limit=512*1024**2, administrator=True):
    if administrator: safe(path)
    stream,before=opened(path,limit)
    with stream:
        h=hashlib.sha256();count=0;deadline=time.monotonic()+120
        while block:=stream.read(1024**2):
            if time.monotonic()>deadline: raise RuntimeError('Bounded hashing deadline')
            count+=len(block)
            if count>limit: raise RuntimeError('File grew past bound')
            h.update(block)
        after=os.fstat(stream.fileno())
        if count!=before.st_size or (before.st_ino,before.st_dev,before.st_mtime_ns)!=(after.st_ino,after.st_dev,after.st_mtime_ns):
            raise RuntimeError('Hashed file changed')
    return {'bytes':count,'sha256':h.hexdigest(),'mode':stat.S_IMODE(after.st_mode),'uid':after.st_uid,'gid':after.st_gid}


def write_new(path,data,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);os.fchmod(stream.fileno(),mode);stream.flush();os.fsync(stream.fileno())


def sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def atomic(path,data,mode):
    previous=safe(path)
    with tempfile.TemporaryDirectory(prefix='.actor-activation-',dir=path.parent) as tmp:
        staged=Path(tmp)/'replacement';write_new(staged,data,mode);os.chown(staged,previous.st_uid,previous.st_gid);os.replace(staged,path)
    sync_dir(path.parent)


def wrappers(version):
    return {HELPER:('#!/bin/sh\n[ "$#" -eq 0 ] || exit 2\nexec /usr/bin/python3 -I '+str(version/'host.py')+'\n').encode(),
            CLIENT:('#!/bin/sh\nexec /usr/bin/python3 -I '+str(version/'candidate.py')+' "$@"\n').encode()}


def package(directory=PACKAGE):
    raw=read(directory/'manifest.json',16384,administrator=False)
    if sha(raw)!=MANIFEST: raise RuntimeError('Reviewed package manifest changed')
    value=json.loads(raw)
    if set(value)!={'files','version'} or value['version']!=1 or not isinstance(value['files'],dict): raise RuntimeError('Package shape')
    if set(p.name for p in directory.iterdir())!=set(value['files'])|{'manifest.json'}: raise RuntimeError('Package inventory changed')
    files={}
    for name,digest in value['files'].items():
        if not re.fullmatch('[A-Za-z0-9_.-]+',name) or name=='manifest.json': raise RuntimeError('Package path')
        data=read(directory/name,administrator=False)
        if sha(data)!=digest: raise RuntimeError('Package file changed '+name)
        files[name]=data
    return raw,files


def release(directory,digest):
    safe(directory,True);raw=read(directory/'manifest.json',16384)
    if sha(raw)!=digest: raise RuntimeError('Sealed installed release changed')
    m=json.loads(raw)
    for name,wanted in m['files'].items():
        if not re.fullmatch('[A-Za-z0-9_.-]+',name) or sha(read(directory/name))!=wanted: raise RuntimeError('Installed release file changed')
    if set(p.name for p in directory.iterdir())!=set(m['files'])|{'manifest.json'}: raise RuntimeError('Installed release inventory changed')
    return m


def tree(root):
    safe(root,True);value={};total=0
    for p in sorted(root.rglob('*')):
        if len(value)>=20000 or len(p.relative_to(root).parts)>16: raise RuntimeError('Audit inventory exceeds bounds')
        s=safe(p,p.is_dir() and not p.is_symlink())
        if stat.S_ISDIR(s.st_mode): value[str(p.relative_to(root))]={'directory':True,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid}
        else:
            value[str(p.relative_to(root))]=facts(p);total+=s.st_size
            if total>8*1024**3: raise RuntimeError('Audit bytes exceed bound')
    return value


def run(args): return subprocess.run(args,check=True,text=True,capture_output=True,env=ENV,cwd='/',timeout=240)
def idle():
    r=run(['/usr/sbin/runuser','-u','bump','--','/usr/bin/env','XDG_RUNTIME_DIR=/run/user/1000',
           'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus','/usr/bin/systemctl','--user','list-units',
           '--type=service','--state=active,activating,deactivating','--no-pager','--no-legend','afk*'])
    if r.stdout.strip(): raise RuntimeError('AFK services active')


def policies():
    result={str(p):facts(p,administrator=False) for p in AFK}
    if any(result[str(p)]['sha256']!=digest for p,digest in AFK.items()): raise RuntimeError('AFK configuration changed')
    for p in [Path('/etc/passwd'),Path('/etc/group'),Path('/etc/nsswitch.conf'),Path('/etc/sudoers')]: result[str(p)]=facts(p,2*1024**2)
    directory=Path('/etc/sudoers.d');safe(directory,True)
    result[str(directory)]=tree(directory)
    return result


def run_inventory(expected):
    safe(BASE/'runs',True)
    if sorted(p.name for p in (BASE/'runs').iterdir())!=sorted(expected): raise RuntimeError('Unexpected complete run-root inventory')
    snapshot={identifier:tree(BASE/'runs'/identifier) for identifier in expected}
    if len(canonical(snapshot))>6*1024**2: raise RuntimeError('Complete audit metadata exceeds bound')
    return snapshot


# Embedded reviewed bytes are carried into isolated probes, never reread from the mutable preparatory script.
CONTROLLER_PROBE = "import os as _cg_os, stat as _cg_stat, re as _cg_re\nfrom pathlib import Path as _CgPath\n\n\ndef _cg_info(info, directory=False):\n    if info.st_uid != 0 or info.st_mode & 0o022 or not (_cg_stat.S_ISDIR(info.st_mode) if directory else _cg_stat.S_ISREG(info.st_mode)):\n        raise RuntimeError('Unsafe controller cgroup owner/mode/type')\n    if not directory and info.st_size > 65536:\n        raise RuntimeError('Controller cgroup file exceeds bound')\n\n\ndef _cg_read(parent_fd, name):\n    fd = _cg_os.open(name, _cg_os.O_RDONLY | _cg_os.O_NOFOLLOW | _cg_os.O_NONBLOCK, dir_fd=parent_fd)\n    with _cg_os.fdopen(fd, 'rb') as stream:\n        before = _cg_os.fstat(stream.fileno()); _cg_info(before)\n        data = stream.read(65537)\n        after = _cg_os.fstat(stream.fileno()); _cg_info(after)\n        if len(data) > 65536 or (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid) != (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_gid):\n            raise RuntimeError('Controller cgroup read is oversized/uncertain')\n        return data\n\n\ndef _cg_events(parent_fd):\n    value = {}\n    for line in _cg_read(parent_fd, 'cgroup.events').decode('ascii').splitlines():\n        parts = line.split()\n        if len(parts) != 2 or parts[0] in value or parts[0] not in ('populated', 'frozen') or parts[1] not in ('0', '1'):\n            raise RuntimeError('Malformed controller cgroup events')\n        value[parts[0]] = parts[1]\n    if set(value) != {'populated', 'frozen'} or value['populated'] != '0' or value['frozen'] != '0':\n        raise RuntimeError('Controller cgroup populated/unknown')\n    return value\n\n\ndef _cg_children(parent_fd):\n    children = []\n    count = 0\n    with _cg_os.scandir(parent_fd) as entries:\n        for entry in entries:\n            count += 1\n            if count > 128 or entry.is_symlink():\n                raise RuntimeError('Controller cgroup inventory oversized/unsafe')\n            info = entry.stat(follow_symlinks=False)\n            directory = _cg_stat.S_ISDIR(info.st_mode)\n            _cg_info(info, directory)\n            if directory:\n                if not _cg_re.fullmatch('[A-Za-z0-9_.:@-]{1,128}', entry.name):\n                    raise RuntimeError('Unknown controller cgroup descendant name')\n                children.append(entry.name)\n    return sorted(children)\n\n\ndef _cg_identity(info):\n    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)\n\n\ndef _cg_named(parent_fd, name, expected):\n    current = _cg_os.stat(name, dir_fd=parent_fd, follow_symlinks=False)\n    _cg_info(current, True)\n    if _cg_identity(current) != _cg_identity(expected):\n        raise RuntimeError('Named controller cgroup identity changed')\n\n\ndef _cg_slice_properties(suite):\n    props = suite.properties(suite.CTL)\n    names = ('LoadState', 'ActiveState', 'SubState', 'FragmentPath', 'DropInPaths', 'Transient')\n    view = {name: props.get(name) for name in names}\n    if (view['LoadState'] not in ('loaded', 'not-found') or view['ActiveState'] not in ('active', 'inactive')\n            or view['SubState'] != ('active' if view['ActiveState'] == 'active' else 'dead')\n            or view['FragmentPath'] != '' or view['DropInPaths'] != '' or view['Transient'] != 'no'):\n        raise RuntimeError('Controller slice state/definition uncertain')\n    return view\n\n\ndef _cg_unit_finished(suite, expected_suite, expected_slice):\n    props = suite.properties(suite.UNIT)\n    if not suite.quiescent(props) or props.get('ActiveState') != expected_suite:\n        raise RuntimeError('Suite service changed during probe')\n    if _cg_slice_properties(suite) != expected_slice:\n        raise RuntimeError('Controller slice state changed during probe')\n    if suite.CTLFILE.exists() or suite.CTLFILE.is_symlink():\n        raise RuntimeError('Controller unit file appeared during probe')\n\n\ndef _controller_probe(suite, identifier, root=None):\n    # The optional private root supports scratch-only controls; production callers always use the fixed kernel root.\n    if not _cg_re.fullmatch('[a-f0-9]{10}', identifier) or suite.CTL != 'eqemuvmb' + identifier + 'ctl.slice':\n        raise RuntimeError('Controller cgroup does not match the sealed run identity')\n    suite_props = suite.properties(suite.UNIT)\n    if not suite.quiescent(suite_props):\n        raise RuntimeError('Suite service is active/uncertain')\n    suite_state = suite_props.get('ActiveState')\n    slice_props = _cg_slice_properties(suite)\n    if suite.CTLFILE.exists() or suite.CTLFILE.is_symlink():\n        raise RuntimeError('Controller unit file remains')\n    root = _CgPath('/sys/fs/cgroup') if root is None else root\n    root_fd = _cg_os.open(root, _cg_os.O_RDONLY | _cg_os.O_DIRECTORY | _cg_os.O_NOFOLLOW)\n    held = []\n    names = []\n    try:\n        root_info = _cg_os.fstat(root_fd); _cg_info(root_info, True)\n        def root_named():\n            current = root.stat(follow_symlinks=False); _cg_info(current, True)\n            if _cg_identity(current) != _cg_identity(root_info):\n                raise RuntimeError('Controller cgroup root identity changed')\n        try:\n            fd = _cg_os.open(suite.CTL, _cg_os.O_RDONLY | _cg_os.O_DIRECTORY | _cg_os.O_NOFOLLOW, dir_fd=root_fd)\n        except FileNotFoundError:\n            _cg_unit_finished(suite, suite_state, slice_props)\n            root_named()\n            try: _cg_os.stat(suite.CTL, dir_fd=root_fd, follow_symlinks=False)\n            except FileNotFoundError:\n                if slice_props['ActiveState'] != 'inactive':\n                    raise RuntimeError('Active controller slice has no readable group')\n                return {'name': suite.CTL, 'state': 'absent', 'groups_checked': 0, 'debt': None,\n                        'suite_service_state': suite_state, 'controller_slice_state': slice_props['ActiveState']}\n            raise RuntimeError('Controller cgroup reappeared during absence probe')\n        held.append(fd)\n        checked = 0\n        def visit(group_fd, parent_fd, name, depth):\n            nonlocal checked\n            checked += 1\n            if checked > 32 or depth > 4:\n                raise RuntimeError('Controller cgroup descendants exceed bound')\n            opened = _cg_os.fstat(group_fd); _cg_info(opened, True)\n            before = _cg_events(group_fd)\n            if _cg_read(group_fd, 'cgroup.procs') != b'':\n                raise RuntimeError('Controller cgroup process list nonempty/malformed')\n            children = _cg_children(group_fd)\n            if children:\n                raise RuntimeError('Controller slice descendants are outside this finite activation scope')\n            names.append((parent_fd, name, group_fd, opened, before, children))\n            for child in children:\n                child_fd = _cg_os.open(child, _cg_os.O_RDONLY | _cg_os.O_DIRECTORY | _cg_os.O_NOFOLLOW, dir_fd=group_fd)\n                held.append(child_fd)\n                visit(child_fd, group_fd, child, depth + 1)\n            if _cg_children(group_fd) != children or _cg_events(group_fd) != before or _cg_read(group_fd, 'cgroup.procs') != b'':\n                raise RuntimeError('Controller cgroup changed during empty probe')\n        visit(fd, root_fd, suite.CTL, 0)\n        _cg_unit_finished(suite, suite_state, slice_props)\n        root_named()\n        # Unit checks may take time. Recheck names AND observed contents/hierarchy afterward.\n        for parent_fd, name, group_fd, opened, expected_events, expected_children in names:\n            current_fd = _cg_os.fstat(group_fd); _cg_info(current_fd, True)\n            if _cg_identity(current_fd) != _cg_identity(opened):\n                raise RuntimeError('Opened controller cgroup metadata changed')\n            _cg_named(parent_fd, name, opened)\n        for parent_fd, name, group_fd, opened, expected_events, expected_children in names:\n            _cg_named(parent_fd, name, opened)\n            if _cg_children(group_fd) != expected_children or _cg_events(group_fd) != expected_events or _cg_read(group_fd, 'cgroup.procs') != b'':\n                raise RuntimeError('Controller cgroup contents/hierarchy changed during final unit query')\n            _cg_named(parent_fd, name, opened)\n        if suite.CTLFILE.exists() or suite.CTLFILE.is_symlink():\n            raise RuntimeError('Controller unit file appeared during final content check')\n        return {'name': suite.CTL, 'state': 'empty', 'groups_checked': checked, 'debt': 'central-168c',\n                'suite_service_state': suite_state, 'controller_slice_state': slice_props['ActiveState']}\n    finally:\n        for fd in reversed(held): _cg_os.close(fd)\n        _cg_os.close(root_fd)\n"

def prior_gate(version,expected):
    # The finite sealed current/prior readers query live owned cleanup and never rewrite receipts.
    before=run_inventory(expected)
    code='import sys,json;sys.dont_write_bytecode=True;sys.path.insert(0,'+repr(str(version))+');import host;host.S.verify_installation();results=[]\n'
    code+=CONTROLLER_PROBE+'\n'
    code+='for identifier in '+repr(list(expected))+':\n root=host.BASE/"runs"/identifier;record=host.S.read_json(root/"owner.json");result=(host.report_record(root,record,identifier,persist=False) if record["version"]==str(host.HERE) else host.prior_report(root,record));assert result["terminal"] is True and result["cleanup_complete"] is True;suite=host.suite_for(root,record);assert suite.ROOT==root/"work";result["controller_group"]=_controller_probe(suite,identifier);results.append(result)\n'
    code+='print(json.dumps(results))'
    output=run(['/usr/bin/python3','-I','-c',code]).stdout
    if len(output.encode())>256*1024: raise RuntimeError('Finite prior report output exceeds bound')
    results=json.loads(output)
    if [r['run_id'] for r in results]!=list(expected) or run_inventory(expected)!=before: raise RuntimeError('Prior gate identity/evidence changed')
    return results


def input_inventory(expected):
    safe(BASE/'inputs',True)
    if sorted(p.name for p in (BASE/'inputs').iterdir())!=sorted(expected): raise RuntimeError('Installed input inventory changed')
    observed={}
    for name,wanted in expected.items():
        observed[name]=facts(BASE/'inputs'/name,1024**3)
        if any(observed[name][k]!=wanted[k] for k in ('bytes','sha256')): raise RuntimeError('Installed input bytes changed')
    return observed


def media_identity(path, wanted):
    observed = facts(path, 1024**3)
    if any(observed[k] != wanted[k] for k in ('bytes','sha256')):
        raise RuntimeError('Runtime media identity changed')
    return observed


def install_media(plan):
    """Save the exact prior medium before selecting the authenticated replacement."""
    source = Path(plan['desired_inputs']['runtime.iso']['source'])
    wanted = plan['desired_inputs']['runtime.iso']
    staged = BACKUP/'runtime.iso.new'
    stream, before = opened(source, 512*1024**2)
    with stream:
        if before.st_size != wanted['bytes']: raise RuntimeError('Runtime source size changed')
        digest = hashlib.sha256(); total = 0; deadline = time.monotonic()+120
        fd = os.open(staged, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'wb') as destination:
            while block := stream.read(1024**2):
                total += len(block)
                if (total > wanted['bytes'] or time.monotonic() > deadline
                        or shutil.disk_usage(BASE).free < 180*1024**3):
                    raise RuntimeError('Runtime source copy budget')
                destination.write(block); digest.update(block)
            after = os.fstat(stream.fileno())
            if (total != wanted['bytes'] or digest.hexdigest() != wanted['sha256']
                    or (before.st_dev,before.st_ino,before.st_mtime_ns) != (after.st_dev,after.st_ino,after.st_mtime_ns)):
                raise RuntimeError('Runtime source copy changed')
            destination.flush(); os.fsync(destination.fileno()); os.fchmod(destination.fileno(),0o400)
    media_identity(staged,wanted)
    original = BASE/'inputs/runtime.iso'
    media_identity(original,plan['old_inputs']['runtime.iso'])
    saved = BACKUP/'runtime.iso.original'
    if exists(saved): raise RuntimeError('Original media backup occupied')
    os.rename(original,saved); sync_dir(original.parent); sync_dir(BACKUP)
    os.rename(staged,original); sync_dir(original.parent); sync_dir(BACKUP)
    input_inventory(plan['desired_inputs'])


def restore_media(receipt):
    """Restore prior bytes even after a failure between the two selection renames."""
    current = BASE/'inputs/runtime.iso'
    saved = BACKUP/'runtime.iso.original'
    old = receipt['old_inputs']['runtime.iso']; new = receipt['desired_inputs']['runtime.iso']
    if not exists(saved):
        # Failure occurred before media selection. Leave a partial new copy as audit.
        input_inventory(receipt['old_inputs']); return
    observed = media_identity(saved,old)
    original = receipt['inputs']['runtime.iso']
    if any(observed[k] != original[k] for k in ('mode','uid','gid')):
        raise RuntimeError('Original media metadata changed')
    if exists(current):
        media_identity(current,new)
        retired = BACKUP/'runtime.iso.retired'
        if exists(retired): raise RuntimeError('Retired media audit occupied')
        os.rename(current,retired); sync_dir(current.parent); sync_dir(BACKUP)
    os.rename(saved,current); sync_dir(current.parent); sync_dir(BACKUP)
    input_inventory(receipt['old_inputs'])


def proof_complete():
    """Activation requires the exact successful provisioning and cleanup receipt."""
    raw = read(PROOF/'evidence/report.json',64*1024)
    if sha(raw) != PROOF_REPORT_SHA: raise RuntimeError('Exact debugger proof receipt changed')
    value = json.loads(raw)
    cleanup = json.loads(read(PROOF/'evidence/cleanup.json',64*1024))
    guest = value.get('guest_report_untrusted',{})
    checks = {'guest_root','no_virtual_nic','approved_inputs','runtime_install',
              'matching_debug_packages','gdb_python','source_trace','no_private_values','bounded_controls','no_cores'}
    if (value.get('uuid') != PROOF_UUID or value.get('ok') is not True
            or value.get('workload_ok') is not True or value.get('service_result') != 'success'
            or cleanup != value.get('cleanup') or cleanup.get('complete') is not True
            or cleanup.get('uuid') != PROOF_UUID
            or any(cleanup.get(k) is not True for k in ('domain_absent','profile_absent','slice_file_absent','data_absent'))
            or guest.get('ok') is not True or set(guest.get('checks',{})) != checks
            or any(v is not True for v in guest['checks'].values())
            or value.get('inputs',{}).get('runtime.iso') != RUNTIME['sha256']):
        raise RuntimeError('Debugger provisioning/cleanup proof incomplete or changed')
    if exists(PROOF/'data') or exists(Path('/run/systemd/system/eqemuvmdebugger20261008b.slice')):
        raise RuntimeError('Debugger proof resource remains')
    props = dict(line.split('=',1) for line in run(['/usr/bin/systemctl','show',
                 'eqemu-vm-debugger-proof-20261008b.service','-p','ActiveState','-p','MainPID','-p','ControlPID']).stdout.splitlines())
    if props.get('ActiveState') != 'inactive' or props.get('MainPID') != '0' or props.get('ControlPID') != '0':
        raise RuntimeError('Debugger proof service is not quiescent')
    for p in Path('/proc').glob('[0-9]*/cmdline'):
        try: data=p.read_bytes()
        except (FileNotFoundError,ProcessLookupError,PermissionError): continue
        if PROOF_UUID.encode() in data: raise RuntimeError('Debugger proof process remains')
    return facts(PROOF/'evidence/report.json',64*1024)


def uploads_empty():
    safe(BASE/'uploads',True);p=BASE/'uploads/1000';s=p.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=1000 or stat.S_IMODE(s.st_mode)!=0o700 or any(p.iterdir()): raise RuntimeError('Outstanding/unsafe submitter upload directory')


def initial_preserved():
    safe(INITIAL,True);safe(INITIAL/'archived-runs',True)
    record=json.loads(read(INITIAL/'receipt.json',8*1024**2))
    if record.get('new_version')!=str(OLD) or record.get('new_manifest_sha256')!=OLD_HASH or record.get('archived_ids')!=INITIAL_ARCHIVED:
        raise RuntimeError('Initial activation audit identity changed')
    if sorted(p.name for p in (INITIAL/'archived-runs').iterdir())!=INITIAL_ARCHIVED:
        raise RuntimeError('Initial two-archive inventory changed')
    for identifier in INITIAL_ARCHIVED:
        if tree(INITIAL/'archived-runs'/identifier)!=record['run_snapshot'][identifier]: raise RuntimeError('Initial archived receipt bytes changed')
        archived_absence(identifier, INITIAL/'archived-runs'/identifier)
    return tree(INITIAL)


def preflight():
    idle()
    qualified = proof_complete()
    for p in [BASE,LIB,OLD]: safe(p,True)
    if shutil.disk_usage(BASE).free-RUNTIME['bytes'] < 180*1024**3:
        raise RuntimeError('Runtime staging would consume the admission disk reserve')
    for p in [BACKUP,NEW,STAGE]:
        if exists(p): raise RuntimeError('Occupied finite backup/release stage')
    raw,files=package();old_manifest=release(OLD,OLD_HASH)
    original={p:read(p) for p in [HELPER,CLIENT,STATE,POLICY]}
    if json.loads(original[STATE])!={'enabled':True,'version':str(OLD),'manifest_sha256':OLD_HASH}: raise RuntimeError('Original installation selection changed')
    if original[POLICY]!=RULE or any(original[p]!=v for p,v in wrappers(OLD).items()): raise RuntimeError('Original wrapper/policy changed')
    old_inputs=json.loads(read(OLD/'host-inputs.json'));desired=json.loads(files['host-inputs.json'])
    if (set(old_inputs)!={'base.qcow2','fixture.iso','runtime.iso'} or set(desired)!=set(old_inputs)
            or any(desired[name]!=old_inputs[name] for name in ('base.qcow2','fixture.iso'))
            or desired['runtime.iso']!=RUNTIME): raise RuntimeError('Input closure widened/changed')
    source = facts(Path(RUNTIME['source']),512*1024**2,administrator=False)
    if any(source[k]!=RUNTIME[k] for k in ('bytes','sha256')): raise RuntimeError('Prepared runtime media changed')
    inputs=input_inventory(old_inputs)
    preserved=policies();initial=initial_preserved();snapshot=run_inventory(RUNS);reports=prior_gate(OLD,RUNS);uploads_empty()
    failed=next(r for r in reports if r['run_id']=='9924578091')
    if failed.get('exit_code')!=2 or failed.get('accepted') is not False or failed.get('actor_runtime') is not None or failed.get('retained_artifact'):
        raise RuntimeError('Exact failed actor receipt/custody changed')
    if failed.get('candidate',{}).get('candidate')!='6dc738d5db018401370709c5b6c683b334233207': raise RuntimeError('Failed actor source changed')
    if run_inventory(RUNS)!=snapshot or policies()!=preserved or initial_preserved()!=initial: raise RuntimeError('Preflight preservation drift')
    if (BASE/'runs').stat().st_dev!=BASE.stat().st_dev or (BASE/'inputs').stat().st_dev!=BASE.stat().st_dev: raise RuntimeError('Archival/input moves require the same mounted root')
    return {'raw':raw,'files':files,'original':original,'modes':{p:stat.S_IMODE(p.stat().st_mode) for p in original},
            'inputs':inputs,'old_inputs':old_inputs,'desired_inputs':desired,'policies':preserved,'snapshot':snapshot,'reports':reports,'initial_snapshot':initial,'proof':qualified}


def verify_distribution(snapshot):
    current=sorted(p.name for p in (BASE/'runs').iterdir());archived=sorted(p.name for p in ARCHIVE.iterdir())
    if set(current)|set(archived)!=set(RUNS) or set(current)&set(archived) or any(r not in ARCHIVED for r in archived): raise RuntimeError('Archive/retained selection changed')
    for identifier in RUNS:
        root=(BASE/'runs'/identifier) if identifier in current else ARCHIVE/identifier
        if tree(root)!=snapshot[identifier]: raise RuntimeError('Original receipt/audit bytes changed')
    return current,archived


def move(source,target):
    safe(source,True);safe(target.parent,True)
    if exists(target) or source.stat().st_dev!=target.parent.stat().st_dev: raise RuntimeError('Unsafe owned archival move')
    os.rename(source,target);sync_dir(source.parent);sync_dir(target.parent)


def normal_submitter_identity():
    result=subprocess.run(['/usr/sbin/runuser','-u','bump','--','/usr/local/bin/eqemu-validate','--identity'],
                          check=True,text=True,capture_output=True,env=ENV,cwd='/',timeout=30)
    if len(result.stdout.encode())>4096 or len(result.stderr.encode())>4096: raise RuntimeError('Normal submitter identity output exceeds bound')
    def unique(pairs):
        value={}
        for name,item in pairs:
            if name in value: raise RuntimeError('Duplicate normal submitter identity field')
            value[name]=item
        return value
    if json.loads(result.stdout,object_pairs_hook=unique)!={'schema_version':1,'identity':'sha256:'+MANIFEST}:
        raise RuntimeError('Normal submitter installed identity mismatch')


def _apply(plan):
    # Durable immutable undo evidence precedes admission changes. No job can enter request.lock here.
    BACKUP.mkdir(mode=0o700);ARCHIVE.mkdir(mode=0o700);captured=BACKUP/'reviewed-package';captured.mkdir(mode=0o700)
    for name,data in plan['files'].items(): write_new(captured/name,data,0o600)
    write_new(captured/'manifest.json',plan['raw'],0o600)
    for p,data in plan['original'].items(): write_new(BACKUP/(p.name+'.original'),data,0o600)
    receipt={'version':1,'old_version':str(OLD),'new_version':str(NEW),'new_manifest_sha256':MANIFEST,'archived_ids':ARCHIVED,
             'original_paths':{str(p):{'sha256':sha(v),'mode':plan['modes'][p],'uid':p.stat().st_uid,'gid':p.stat().st_gid,'backup':p.name+'.original'} for p,v in plan['original'].items()},
             'inputs':plan['inputs'],'old_inputs':plan['old_inputs'],'desired_inputs':plan['desired_inputs'],'policies':plan['policies'],
             'run_snapshot':plan['snapshot'],'prior_reports':plan['reports'],'initial_snapshot':plan['initial_snapshot'],
             'proof':plan['proof'],'archive_lookup':'immutable audit only; normal run-ID lookup no longer applies'}
    write_new(BACKUP/'receipt.json',canonical(receipt),0o600);sync_dir(BACKUP)
    disabled={'enabled':False,'version':str(OLD),'manifest_sha256':OLD_HASH}
    atomic(STATE,canonical(disabled),plan['modes'][STATE])
    # Every later failure keeps admission disabled, with bytes available to the exact undo.
    STAGE.mkdir(mode=0o755)
    stage_fd=os.open(STAGE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        safe(STAGE,True)
        os.fchmod(stage_fd,0o755);os.fsync(stage_fd)
    finally:os.close(stage_fd)
    for name,data in plan['files'].items(): write_new(STAGE/name,data,0o644)
    write_new(STAGE/'manifest.json',plan['raw'],0o644);release(STAGE,MANIFEST)
    os.rename(STAGE,NEW);sync_dir(LIB)
    if policies()!=plan['policies'] or initial_preserved()!=plan['initial_snapshot'] or run_inventory(RUNS)!=plan['snapshot']: raise RuntimeError('Preservation drift before archival')
    for identifier in ARCHIVED: move(BASE/'runs'/identifier,ARCHIVE/identifier)
    current,archived=verify_distribution(plan['snapshot'])
    if current!=RETAINED or archived!=ARCHIVED: raise RuntimeError('Archive headroom incomplete')
    install_media(plan)
    input_inventory(plan['desired_inputs']);prior_gate(NEW,RETAINED)
    if proof_complete()!=plan['proof']: raise RuntimeError('Provisioning proof changed during activation')
    if policies()!=plan['policies']: raise RuntimeError('Preserved configuration/policy changed')
    idle();uploads_empty()
    for p,data in wrappers(NEW).items(): atomic(p,data,plan['modes'][p])
    if policies()!=plan['policies'] or initial_preserved()!=plan['initial_snapshot'] or verify_distribution(plan['snapshot'])!=(RETAINED,ARCHIVED): raise RuntimeError('Final preservation drift')
    idle();normal_submitter_identity()
    write_new(BACKUP/'commit-ready.json',canonical({'version':1,'package_verified':True,'headroom':4,'archived_ids':ARCHIVED,'jobs_started':False}),0o600);sync_dir(BACKUP)
    atomic(STATE,canonical({'enabled':True,'version':str(NEW),'manifest_sha256':MANIFEST}),plan['modes'][STATE])
    result={'activated':True,'manifest_sha256':MANIFEST,'archived_ids':ARCHIVED,'retained_ids':RETAINED,'headroom':4,'backup':str(BACKUP),'controller_groups':[r['controller_group'] for r in plan['reports']],'runtime_media_replaced':True,'old_media_preserved':True,'vm_started':False}
    return result


def disable_failed(modes):
    selected=json.loads(read(STATE))
    allowed=[{'enabled':v,'version':str(path),'manifest_sha256':digest} for path,digest in [(OLD,OLD_HASH),(NEW,MANIFEST)] for v in (True,False)]
    if selected not in allowed: raise RuntimeError('Failed transaction state drift; retain evidence')
    atomic(STATE,canonical({**selected,'enabled':False}),modes[STATE])


def apply(plan):
    try: return _apply(plan)
    except BaseException:
        if exists(BACKUP/'receipt.json'): disable_failed(plan['modes'])
        raise


def archived_absence(identifier, audit_root=None):
    # Audit code was frozen/sealed before moving. Probe ORIGINAL live resources, never rewrite archived receipts.
    root=ARCHIVE/identifier if audit_root is None else audit_root;record=json.loads(read(root/'owner.json',1024**2));original=BASE/'runs'/identifier
    code='import sys,json,pathlib;sys.dont_write_bytecode=True;sys.path.insert(0,'+repr(str(OLD))+');import host;root=pathlib.Path('+repr(str(root))+');original=pathlib.Path('+repr(str(original))+');record='+repr(record)+'\n'
    code+=CONTROLLER_PROBE+'\n'
    code+='suite=host.suite_for(root,record);assert suite.ROOT==original/"work";assert tuple(suite.CASES)==("producer","consumer");assert suite.quiescent(suite.properties(suite.UNIT));controller=_controller_probe(suite,record["run_id"]);assert not host.S.read_json(root/"work/leases.json")["active"]\n'
    code+='for role in suite.CASES:\n path=root/"prepared"/(role+"-worker.py");worker=host.load("archive_"+role,path);assert worker.ROOT==original/"work"/role;statepath=root/"work"/role/"state.json"\n if statepath.exists():\n  state=host.S.read_json(statepath);assert state["name"]==worker.NAME;assert state["profile"]=="libvirt-"+state["uuid"];assert suite.quiescent(suite.properties(worker.UNIT));assert suite.absent(worker,state)\n else:\n  assert host.unstarted_absent(suite,worker)\n'
    code+='print(json.dumps({"archived_run":record["run_id"],"original_worker_resources_absent":True,"controller_group":controller}))'
    observed=json.loads(run(['/usr/bin/python3','-I','-c',code]).stdout)
    if observed.get('archived_run')!=identifier or observed.get('original_worker_resources_absent') is not True or observed.get('controller_group',{}).get('state') not in ('absent','empty'): raise RuntimeError('Archived resource cleanup identity')
    return observed


def partial_stage(files,raw):
    if not exists(STAGE): return
    safe(STAGE,True);expected={**files,'manifest.json':raw}
    for p in STAGE.iterdir():
        if p.name not in expected or not expected[p.name].startswith(read(p)): raise RuntimeError('Partial release stage changed')


def undo():
    safe(BACKUP,True);safe(ARCHIVE,True);receipt=json.loads(read(BACKUP/'receipt.json',8*1024**2))
    if receipt.get('version')!=1 or receipt.get('old_version')!=str(OLD) or receipt.get('new_version')!=str(NEW) or receipt.get('new_manifest_sha256')!=MANIFEST or receipt.get('archived_ids')!=ARCHIVED or set(receipt['original_paths'])!={str(p) for p in [HELPER,CLIENT,STATE,POLICY]}: raise RuntimeError('Undo finite selection changed')
    raw,files=package(BACKUP/'reviewed-package');partial_stage(files,raw)
    if exists(NEW): release(NEW,MANIFEST)
    release(OLD,OLD_HASH);original={};modes={}
    for p in [HELPER,CLIENT,STATE,POLICY]:
        selected=receipt['original_paths'][str(p)]
        if selected['backup']!=p.name+'.original': raise RuntimeError('Undo original path changed')
        original[p]=read(BACKUP/selected['backup']);modes[p]=selected['mode']
        if sha(original[p])!=selected['sha256']: raise RuntimeError('Undo original bytes changed')
    if original[POLICY]!=RULE or json.loads(original[STATE])!={'enabled':True,'version':str(OLD),'manifest_sha256':OLD_HASH} or any(original[p]!=v for p,v in wrappers(OLD).items()): raise RuntimeError('Undo original identity changed')
    current,archived=verify_distribution(receipt['run_snapshot']);idle();uploads_empty()
    if policies()!=receipt['policies'] or initial_preserved()!=receipt['initial_snapshot']: raise RuntimeError('Undo preserved policy/configuration/initial-audit drift')
    prior_gate(NEW if json.loads(read(STATE))['version']==str(NEW) else OLD,current)
    for identifier in archived: archived_absence(identifier)
    selected=json.loads(read(STATE));allowed=[{'enabled':v,'version':str(path),'manifest_sha256':digest} for path,digest in [(OLD,OLD_HASH),(NEW,MANIFEST)] for v in [True,False]]
    if selected not in allowed or any(read(p) not in [original[p],wrappers(NEW)[p]] for p in [HELPER,CLIENT]): raise RuntimeError('Undo current wrapper/state changed')
    atomic(STATE,canonical({'enabled':False,'version':str(OLD),'manifest_sha256':OLD_HASH}),modes[STATE])
    restore_media(receipt)
    for p,data in wrappers(OLD).items(): atomic(p,data,modes[p])
    for identifier in archived: move(ARCHIVE/identifier,BASE/'runs'/identifier)
    if run_inventory(RUNS)!=receipt['run_snapshot']: raise RuntimeError('Undo restored evidence changed')
    prior_gate(OLD,RUNS)
    input_inventory(receipt['old_inputs'])
    for p,data in wrappers(OLD).items(): atomic(p,data,modes[p])
    if policies()!=receipt['policies'] or initial_preserved()!=receipt['initial_snapshot']: raise RuntimeError('Undo final policy/initial-audit drift')
    idle()
    ready=canonical({'version':1,'original_runs_restored':True,'original_inputs_restored':True,'jobs_started':False})
    if exists(BACKUP/'undo-ready.json'):
        if read(BACKUP/'undo-ready.json')!=ready: raise RuntimeError('Undo-ready receipt changed')
    else: write_new(BACKUP/'undo-ready.json',ready,0o600)
    sync_dir(BACKUP);atomic(STATE,original[STATE],modes[STATE])
    result={'undone':True,'archived_runs_restored':archived,'new_release_retained_as_audit':True,'existing_inputs_unchanged':True,'vm_started':False}
    return result


def main():
    parser=argparse.ArgumentParser();g=parser.add_mutually_exclusive_group();g.add_argument('--apply',action='store_true');g.add_argument('--undo',action='store_true');args=parser.parse_args()
    if not FINAL_PACKAGE_APPROVED: raise RuntimeError('Draft transaction unarmed: final reviewed visibility package is not selected')
    if os.geteuid()!=0: raise RuntimeError('Host OS root authentication is required; script never escalates itself')
    os.umask(0o077);safe(BASE/'request.lock')
    fd=os.open(BASE/'request.lock',os.O_RDWR|os.O_NOFOLLOW)
    with os.fdopen(fd,'r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if args.undo: print(json.dumps(undo()));return
        plan=preflight()
        print(json.dumps({'preflight':'PASS','manifest_sha256':MANIFEST,'verified_prior_ids':RUNS,'archive_ids':ARCHIVED,'prospective_headroom':4,'controller_groups':[r['controller_group'] for r in plan['reports']],'applied':args.apply,'vm_started':False}))
        if args.apply: print(json.dumps(apply(plan)))

if __name__=='__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'error':str(error),'activated':False,'vm_started':False}),file=sys.stderr);raise SystemExit(2)
