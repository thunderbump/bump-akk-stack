"""Finite forward-only validator release upgrade. Imports no replacement code before verification."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

OLD = '810730e94fe14f123c36ab9ad26bfc4543a4f23918b3bef48fc0e1f76f9feb24'
ACTIVATION_PROFILE_SHA256 = None
PROOF_UUID = '5ca42214-8aed-4335-bdde-f9f7074a57c8'
PROOF_REPORT = '52389eefbf0e393ec6d7059f0d99b578d8652e94e17a3319fa205479d16ab3f0'
PROOF_CLEANUP = '57aacb2faeceb92d65f32da91204012088340a4c8c434330ee4b34ecc5a4d7a3'
NAMES = {'common.py','render.py','host.py','candidate.py','install.py','disable.py','host_support.py',
         'installer_support.py','inputs.py','profile.json','actor.py','actor_runtime.py','runtime-fixture.json',
         'debugger.py','debugger-gdb.py','rust.py','rust_guest.py','rust-toolchain.json','producer-user.json',
         'consumer-user.json','producer-guest.py','consumer-guest.py','producer-worker.py.in','consumer-worker.py.in',
         'suite.py.in','recipe-binding.json','host-inputs.json','client-config.json'}
OLD_NAMES = NAMES
RULE = b'%eqemu-test ALL=(root) NOPASSWD: NOSETENV: /usr/local/sbin/eqemu-build-request ""\n'
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}
DECLARATION = None


def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate upgrade field')
        result[key]=value
    return result


def decode(data):return json.loads(data,object_pairs_hook=unique)
def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


class Paths:
    def __init__(self,root=Path('/'),uid=0):
        self.root=Path(root);self.uid=uid
        self.base=self.root/'var/lib/eqemu-build';self.lib=self.root/'usr/local/lib/eqemu-build'
        self.client=self.root/'usr/local/bin/eqemu-validate';self.helper=self.root/'usr/local/sbin/eqemu-build-request'
        self.state=self.base/'installation.json';self.policy=self.root/'etc/sudoers.d/eqemu-build'
        self.proof=self.root/'var/lib/eqemu-vm-proof/rust-proof-20261012b/evidence'
        self.cgroups=self.root/'sys/fs/cgroup';self.units=self.root/'run/systemd/system'
        self.afk=[self.root/'home/bump/.config/afk'/name for name in ('config.toml','config.json')]


def safe(path,uid=0,directory=False):
    path=Path(path)
    if uid==0:
        for parent in path.parents:
            ancestor=parent.lstat()
            if not stat.S_ISDIR(ancestor.st_mode) or ancestor.st_uid!=0 or ancestor.st_mode&0o022:
                raise ValueError('Unsafe administrator ancestor')
    info=path.lstat()
    if info.st_uid!=uid or info.st_mode&0o022 or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise ValueError('Unsafe upgrade path: '+str(path))
    return info


def read(path,limit=256*1024,uid=None):
    if uid is not None:safe(path,uid)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size>limit:raise ValueError('Upgrade file bound/type')
        data=stream.read(limit+1)
        if len(data)!=info.st_size or len(data)>limit:raise ValueError('Upgrade file changed')
    return data


def package(directory,expected,names=NAMES,uid=None):
    """Closed flat inventory and all seals before any import, retaining checked bytes."""
    raw=read(directory/'manifest.json',16384,uid)
    if sha(raw)!=expected:raise ValueError('Reviewed upgrade manifest changed')
    manifest=decode(raw)
    if (set(manifest)!={'version','files'} or type(manifest['version']) is not int or manifest['version']!=1
            or not isinstance(manifest['files'],dict) or set(manifest['files'])!=names):
        raise ValueError('Upgrade manifest closed inventory')
    observed=set()
    with os.scandir(directory) as entries:
        for entry in entries:
            if len(observed)>=len(names)+1 or entry.name in observed:raise ValueError('Upgrade inventory count')
            observed.add(entry.name)
    if observed!=names|{'manifest.json'}:raise ValueError('Unexpected upgrade files')
    files={}
    for name,digest in manifest['files'].items():
        if not isinstance(digest,str) or not re.fullmatch('[a-f0-9]{64}',digest):raise ValueError('Upgrade file digest')
        files[name]=read(directory/name,256*1024,uid)
        if sha(files[name])!=digest:raise ValueError('Upgrade package bytes changed: '+name)
    return raw,files


def snapshot(root,uid=0,byte_limit=8*1024**3):
    """Complete bounded regular-file audit, with clean read-cache eviction."""
    safe(root,uid,True);stack=[root];result={};total=0;count=0;deadline=time.monotonic()+300
    while stack:
        parent=stack.pop()
        with os.scandir(parent) as children:
            for entry in children:
                count+=1
                if count>20000 or time.monotonic()>deadline:raise ValueError('Upgrade audit bound')
                path=Path(entry.path);name=str(path.relative_to(root));info=entry.stat(follow_symlinks=False)
                if len(path.relative_to(root).parts)>16:raise ValueError('Upgrade audit depth')
                safe(path,uid,stat.S_ISDIR(info.st_mode))
                if stat.S_ISDIR(info.st_mode):stack.append(path);result[name]={'directory':True};continue
                total+=info.st_size
                if total>byte_limit:raise ValueError('Upgrade audit byte bound')
                digest=hashlib.sha256();offset=0;pending=0
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(fd,'rb') as stream:
                    remaining=info.st_size
                    while remaining:
                        if time.monotonic()>deadline:raise ValueError('Upgrade hashing deadline')
                        body=stream.read(min(1024**2,remaining))
                        if not body:raise ValueError('Upgrade audit truncated')
                        digest.update(body);remaining-=len(body);pending+=len(body)
                        if pending>=16*1024**2:
                            os.posix_fadvise(stream.fileno(),offset,pending,os.POSIX_FADV_DONTNEED);offset+=pending;pending=0
                    if stream.read(1):raise ValueError('Upgrade audit grew')
                    if pending:os.posix_fadvise(stream.fileno(),offset,pending,os.POSIX_FADV_DONTNEED)
                result[name]={'bytes':info.st_size,'sha256':digest.hexdigest(),'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid}
    return result


def sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def readable_release(path,uid):
    """Normalize only this attempt's owned release, including forward-retry staging."""
    safe(path,uid,True)
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        opened=os.fstat(fd);named=path.lstat()
        identity=lambda value:(value.st_dev,value.st_ino,value.st_uid,value.st_gid,stat.S_IFMT(value.st_mode))
        if identity(opened)!=identity(named) or opened.st_uid!=uid or opened.st_mode&0o022:
            raise ValueError('Owned release directory changed')
        os.fchmod(fd,0o755);os.fsync(fd)
        after=os.fstat(fd);named=path.lstat()
        if identity(after)!=identity(opened) or identity(named)!=identity(after) or stat.S_IMODE(named.st_mode)!=0o755:
            raise ValueError('Owned readable release directory changed')
    finally:os.close(fd)


def write(path,data,mode):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:
        os.fchmod(stream.fileno(),mode);stream.write(data);stream.flush();os.fsync(stream.fileno())


def atomic(path,data,uid=0):
    before=safe(path,uid)
    with tempfile.TemporaryDirectory(prefix='.upgrade-',dir=path.parent) as temporary:
        staged=Path(temporary)/'value';write(staged,data,stat.S_IMODE(before.st_mode))
        os.chown(staged,before.st_uid,before.st_gid);os.replace(staged,path)
    sync_dir(path.parent)


def wrappers(paths,version):
    return {paths.helper:('#!/bin/sh\n[ "$#" -eq 0 ] || exit 2\nexec /usr/bin/python3 -I '+str(version/'host.py')+'\n').encode(),
            paths.client:('#!/bin/sh\nexec /usr/bin/python3 -I '+str(version/'candidate.py')+' "$@"\n').encode()}


def command(args):
    result=subprocess.run(args,env=ENV,cwd='/',capture_output=True,text=True,timeout=240)
    if result.returncode or len(result.stdout.encode())>256*1024 or len(result.stderr.encode())>65536:
        raise ValueError('Upgrade probe failed: '+result.stderr[-1000:])
    return result.stdout


def controller_group(paths,identifier,query):
    """Hold the kernel directory through final unit queries; never prune empty debt."""
    if not re.fullmatch('[a-f0-9]{10}',identifier):raise ValueError('Controller run identity')
    name='eqemuvmb'+identifier+'ctl.slice';directory=paths.cgroups/name;unitfile=paths.units/name
    if unitfile.exists() or unitfile.is_symlink():raise ValueError('Controller slice file remains')
    before=query();slice_before=slice_properties(name)
    if not directory.exists() and not directory.is_symlink():
        after=query();slice_after=slice_properties(name)
        if (after!=before or slice_after!=slice_before or slice_before['ActiveState']!='inactive'
                or directory.exists() or directory.is_symlink() or unitfile.exists() or unitfile.is_symlink()):
            raise ValueError('Absent controller group changed')
        return {'slice':name,'state':'absent','slice_properties':slice_before}
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if info.st_uid!=paths.uid or info.st_mode&0o022:raise ValueError('Controller group ownership')
        def empty():
            values={}
            for filename in ('cgroup.events','cgroup.procs'):
                child=os.open(filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
                with os.fdopen(child,'rb') as stream:
                    facts=os.fstat(stream.fileno())
                    if not stat.S_ISREG(facts.st_mode) or facts.st_uid!=paths.uid or facts.st_size>65536:raise ValueError('Controller group file')
                    body=stream.read(65537)
                    if len(body)>65536:raise ValueError('Controller group read bound')
                    values[filename]=body.decode('ascii')
            events={}
            for line in values['cgroup.events'].splitlines():
                fields=line.split()
                if len(fields)!=2 or fields[0] in events:raise ValueError('Controller events shape')
                events[fields[0]]=fields[1]
            if events!={'populated':'0','frozen':'0'} or values['cgroup.procs'].strip():raise ValueError('Controller group populated/frozen')
            count=0
            with os.scandir(fd) as children:
                for child in children:
                    count+=1
                    if count>128 or child.is_symlink() or child.is_dir(follow_symlinks=False):raise ValueError('Controller descendants/unsafe inventory')
        empty();after=query();slice_after=slice_properties(name);named=directory.lstat()
        if (named.st_dev,named.st_ino,named.st_mode,named.st_uid,named.st_gid)!=(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid) or before!=after or slice_before!=slice_after:
            raise ValueError('Controller group identity changed')
        empty()
        if unitfile.exists() or unitfile.is_symlink():raise ValueError('Controller slice file appeared')
        return {'slice':name,'state':'empty','slice_properties':slice_before}
    finally:os.close(fd)


def live_runs(paths,version,ids):
    # Package bytes were sealed before this isolated interpreter imports host.
    # Check every explicitly pinned prior release's complete flat inventory too.
    code='import sys,json,hashlib,os,stat;from pathlib import Path;sys.dont_write_bytecode=True;sys.path.insert(0,'+repr(str(version))+');import host;host.S.verify_installation();results=[]\n'
    code+='def sealed_prior(directory,expected):\n raw=(directory/"manifest.json").read_bytes();assert len(raw)<=16384 and hashlib.sha256(raw).hexdigest()==expected;manifest=json.loads(raw);assert set(p.name for p in directory.iterdir())==set(manifest["files"])|{"manifest.json"}\n for name,digest in manifest["files"].items():\n  assert name.replace("_","").replace("-","").replace(".","").isalnum();path=directory/name;host.S.safe_path(path);assert path.stat().st_size<=262144 and hashlib.sha256(path.read_bytes()).hexdigest()==digest\n'
    code+='for identifier in '+repr(ids)+':\n root=host.BASE/"runs"/identifier;record=host.S.read_json(root/"owner.json")\n if record["version"]!=str(host.HERE):\n  pins=[digest for digest in host.PRIOR_MANIFESTS if record["version"]==str(host.LIB/digest[:16])];assert len(pins)==1;sealed_prior(Path(record["version"]),pins[0])\n result=host.report_record(root,record,identifier,persist=False) if record["version"]==str(host.HERE) else host.prior_report(root,record);assert result["terminal"] is True and result["cleanup_complete"] is True\n suite=host.suite_for(root,record);assert suite.quiescent(suite.properties(suite.UNIT));assert not host.S.read_json(suite.ROOT/"leases.json")["active"];results.append({"run_id":identifier,"unit":suite.UNIT})\n'
    code+='print(json.dumps(results))'
    return decode(command(['/usr/bin/python3','-I','-c',code]))


def unit_properties(name):
    result=command(['/usr/bin/systemctl','show',name,'-p','LoadState','-p','ActiveState','-p','SubState','-p','MainPID','-p','ControlPID'])
    values=dict(line.split('=',1) for line in result.splitlines())
    valid = ((values.get('LoadState')=='not-found' and values.get('ActiveState')=='inactive' and values.get('SubState')=='dead')
             or values.get('LoadState')=='loaded' and (values.get('ActiveState'),values.get('SubState')) in (('inactive','dead'),('failed','failed')))
    if not valid or values.get('MainPID')!='0' or values.get('ControlPID')!='0':raise ValueError('Upgrade service active/unknown')
    return values


def slice_properties(name):
    names=('LoadState','ActiveState','SubState','FragmentPath','DropInPaths','Transient')
    result=command(['/usr/bin/systemctl','show',name,*[item for key in names for item in ('-p',key)]])
    values=dict(line.split('=',1) for line in result.splitlines())
    if (set(values)!=set(names) or values['LoadState'] not in ('loaded','not-found')
            or (values['ActiveState'],values['SubState']) not in (('inactive','dead'),('active','active'))
            or values['LoadState']=='not-found' and values['ActiveState']!='inactive'
            or values['FragmentPath']!='' or values['DropInPaths']!='' or values['Transient']!='no'):
        raise ValueError('Controller slice state/definition uncertain')
    return values


def idle():
    result=command(['/usr/sbin/runuser','-u','bump','--','/usr/bin/env','XDG_RUNTIME_DIR=/run/user/1000',
        'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus','/usr/bin/systemctl','--user','list-units',
        '--type=service','--state=active,activating,deactivating','--no-pager','--no-legend','afk*'])
    if result.strip():raise ValueError('AFK services active')


def proof_gate(paths):
    report=read(paths.proof/'report.json',65536,paths.uid);cleanup=read(paths.proof/'cleanup.json',65536,paths.uid)
    if sha(report)!=PROOF_REPORT or sha(cleanup)!=PROOF_CLEANUP:raise ValueError('Qualified Rust proof changed')
    report=decode(report);cleanup=decode(cleanup)
    if report.get('uuid')!=PROOF_UUID or report.get('ok') is not True or report.get('workload_ok') is not True or cleanup.get('uuid')!=PROOF_UUID or cleanup.get('complete') is not True:
        raise ValueError('Qualified Rust proof incomplete')
    for path in (paths.proof.parent/'data',paths.units/'eqemuvmrust20261012b.slice',paths.cgroups/'eqemuvmrust20261012b.slice'):
        if path.exists() or path.is_symlink():raise ValueError('Proof resources remain')
    unit_properties('eqemu-vm-rust-proof-20261012b.service')
    if PROOF_UUID in command(['/usr/bin/virsh','-c','qemu:///system','list','--all','--uuid']).split():raise ValueError('Proof VM remains')


def health(version,expected):
    code='import sys,json;sys.dont_write_bytecode=True;sys.path.insert(0,'+repr(str(version))+');import host,candidate;host.S.verify_installation();print(json.dumps(candidate.installed_identity()))'
    if decode(command(['/usr/bin/python3','-I','-c',code]))!={'schema_version':1,'identity':'sha256:'+expected}:
        raise ValueError('New release health identity')


def user_identity(expected):
    result=command(['/usr/sbin/runuser','-u','bump','--','/usr/local/bin/eqemu-validate','--identity'])
    if decode(result)!={'schema_version':1,'identity':'sha256:'+expected}:raise ValueError('Normal user identity mismatch')


def run_ids(paths):
    root=paths.base/'runs';safe(root,paths.uid,True);ids=[]
    with os.scandir(root) as children:
        for child in children:
            if len(ids)>=8 or not re.fullmatch('[a-f0-9]{10}',child.name):raise ValueError('Retained run inventory bound')
            safe(Path(child.path),paths.uid,True);ids.append(child.name)
    return sorted(ids)


def preserved(paths,ids):
    result={'inputs':snapshot(paths.base/'inputs',paths.uid),
            'runs':{identifier:snapshot(paths.base/'runs'/identifier,paths.uid) for identifier in ids},
            'policy':sha(read(paths.policy,65536,paths.uid)),
            'afk':{str(path):sha(read(path,1024**2)) if path.exists() or path.is_symlink() else None for path in paths.afk}}
    uploads=paths.base/'uploads/1000'
    facts=uploads.lstat()
    if not stat.S_ISDIR(facts.st_mode) or facts.st_uid!=1000 or stat.S_IMODE(facts.st_mode)!=0o700 or any(uploads.iterdir()):raise ValueError('Submitter uploads outstanding/unsafe')
    return result


def installed_inputs(observed,declarations):
    if set(observed)!=set(declarations):raise ValueError('Installed media inventory changed')
    for name,wanted in declarations.items():
        if observed[name].get('bytes')!=wanted.get('bytes') or observed[name].get('sha256')!=wanted.get('sha256'):
            raise ValueError('Installed input bytes differ from sealed declaration')


def quiescent(paths,version,ids):
    idle();before=preserved(paths,ids);rows=live_runs(paths,version,ids)
    if [row.get('run_id') for row in rows]!=ids:raise ValueError('Live run inventory mismatch')
    groups=[controller_group(paths,row['run_id'],lambda row=row:unit_properties(row['unit'])) for row in rows]
    if before!=preserved(paths,ids) or run_ids(paths)!=ids:raise ValueError('Retained evidence changed during probes')
    return before,groups


def save_audit(path,value,uid):
    data=canonical(value)
    if len(data)>8*1024**2:raise ValueError('Upgrade audit too large')
    if path.exists():atomic(path,data,uid)
    else:write(path,data,0o600);sync_dir(path.parent)


def profile_change(files, oldfiles):
    """Allow only a frozen Rust declaration over the unchanged native profile."""
    raw=files['profile.json'];profile=decode(raw)
    if ACTIVATION_PROFILE_SHA256 is None:
        if raw!=oldfiles['profile.json']:
            raise ValueError('Upgrade must preserve the installed profile')
        return
    if sha(raw)!=ACTIVATION_PROFILE_SHA256:raise ValueError('Reviewed Rust activation profile changed')
    old=decode(oldfiles['profile.json'])
    if 'rust' in old or 'rust' in old.get('dependencies',{}):raise ValueError('Activation requires dormant old profile')
    declared=profile.pop('rust')
    if profile['dependencies'].pop('rust')!=declared['bundle']:raise ValueError('Rust bundle declaration mismatch')
    for name,blob in declared['source_blobs'].items():
        if profile['dependency_blobs'].get(name)!=blob:raise ValueError('Rust dependency declaration mismatch')
        if name not in old['dependency_blobs']:del profile['dependency_blobs'][name]
    if profile!=old:raise ValueError('Rust activation changed native profile')


def apply(declaration,paths=None,fault=lambda _:None):
    if (set(declaration)!={'version','old_manifest','new_manifest','proof_report','proof_uuid','package','mode'}
            or type(declaration['version']) is not int or declaration['version']!=1
            or declaration['mode'] not in ('check','apply')
            or not isinstance(declaration['new_manifest'],str) or not re.fullmatch('[a-f0-9]{64}',declaration['new_manifest'])
            or not Path(declaration['package']).is_absolute()):
        raise ValueError('Fixed upgrade declaration shape')
    paths=paths or Paths();newhash=declaration['new_manifest'];old=paths.lib/OLD[:16];new=paths.lib/newhash[:16]
    if declaration['old_manifest']!=OLD or declaration['proof_report']!=PROOF_REPORT or declaration['proof_uuid']!=PROOF_UUID:
        raise ValueError('Upgrade declaration pins')
    safe(paths.base,paths.uid,True);safe(paths.lib,paths.uid,True);safe(old,paths.uid,True)
    raw,files=package(Path(declaration['package']),newhash)
    _,oldfiles=package(old,OLD,OLD_NAMES,paths.uid)
    for name in ('host-inputs.json','client-config.json','actor.py','actor_runtime.py','debugger.py','debugger-gdb.py','runtime-fixture.json'):
        if files[name]!=oldfiles[name]:raise ValueError('Upgrade widened dormant/native input contract: '+name)
    profile_change(files,oldfiles)
    if read(paths.policy,65536,paths.uid)!=RULE:raise ValueError('Existing fixed helper policy changed')
    safe(paths.base/'request.lock',paths.uid)
    lock_fd=os.open(paths.base/'request.lock',os.O_RDWR|os.O_NOFOLLOW)
    with os.fdopen(lock_fd,'r+') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        proof_gate(paths);ids=run_ids(paths)
        current=decode(read(paths.state,65536,paths.uid))
        allowed=[{'enabled':flag,'version':str(version),'manifest_sha256':digest} for version,digest in ((old,OLD),(new,newhash)) for flag in (True,False)]
        if current not in allowed:raise ValueError('Upgrade installation selection unknown')
        auditroot=paths.base/('direct-upgrade-'+newhash[:16]);auditfile=auditroot/'audit.json';stage=paths.lib/('.direct-upgrade-'+newhash[:16])
        retry=auditroot.exists()
        if retry:
            safe(auditroot,paths.uid,True);audit=decode(read(auditfile,8*1024**2,paths.uid))
            if audit.get('old_manifest')!=OLD or audit.get('new_manifest')!=newhash:raise ValueError('Forward attempt ownership mismatch')
        else:
            if current!=allowed[0] or new.exists() or stage.exists():raise ValueError('Initial upgrade requires unchanged enabled old release')
            audit={'version':1,'old_manifest':OLD,'new_manifest':newhash,'phase':'prepared'}
        for path in (paths.client,paths.helper):
            if read(path,65536,paths.uid) not in (wrappers(paths,old)[path],wrappers(paths,new)[path]):raise ValueError('Upgrade wrapper changed')
        prior=old if current['version']==str(old) else new
        if prior==new:package(new,newhash,NAMES,paths.uid)
        preservation,groups=quiescent(paths,prior,ids)
        installed_inputs(preservation['inputs'],decode(oldfiles['host-inputs.json']))
        if retry and preservation!=audit['preserved']:raise ValueError('Forward retry evidence/input drift')
        if declaration.get('mode')=='check':return {'checked':True,'new_manifest':newhash,'runs':ids,'controller_groups':groups,'jobs_started':False}
        if not retry:
            audit.update(preserved=preservation,runs=ids,controller_groups=groups)
            if len(canonical(audit))>8*1024**2:raise ValueError('Upgrade audit too large')
            auditroot.mkdir(mode=0o700);save_audit(auditfile,audit,paths.uid)
        started=False
        try:
            atomic(paths.state,canonical({**current,'enabled':False}),paths.uid);started=True;fault('disabled')
            audit['phase']='disabled';save_audit(auditfile,audit,paths.uid)
            if not new.exists():
                if not stage.exists():stage.mkdir(mode=0o755)
                readable_release(stage,paths.uid)
                if not set(p.name for p in stage.iterdir())<=NAMES|{'manifest.json'}:raise ValueError('Foreign upgrade stage files')
                for name,data in {**files,'manifest.json':raw}.items():
                    path=stage/name
                    if path.exists():
                        actual=read(path,256*1024,paths.uid)
                        if not data.startswith(actual):raise ValueError('Owned partial stage changed')
                        if actual!=data:atomic(path,data,paths.uid)
                    else:write(path,data,0o644)
                    fault('stage-file')
                package(stage,newhash,NAMES,paths.uid);os.rename(stage,new);sync_dir(paths.lib)
            package(new,newhash,NAMES,paths.uid);readable_release(new,paths.uid);health(new,newhash)
            compatible,_=quiescent(paths,new,ids)
            if compatible!=preservation:raise ValueError('New reader preservation drift')
            fault('release')
            audit['phase']='release-verified';save_audit(auditfile,audit,paths.uid)
            atomic(paths.state,canonical({'enabled':False,'version':str(new),'manifest_sha256':newhash}),paths.uid)
            for path,data in wrappers(paths,new).items():atomic(path,data,paths.uid);fault(path.name)
            user_identity(newhash);fault('identity')
            after,_=quiescent(paths,new,ids)
            if after!=preservation:raise ValueError('Upgrade preservation drift')
            proof_gate(paths);package(new,newhash,NAMES,paths.uid)
            audit['phase']='commit-ready';save_audit(auditfile,audit,paths.uid);fault('commit-ready')
            atomic(paths.state,canonical({'enabled':True,'version':str(new),'manifest_sha256':newhash}),paths.uid)
            audit.update(phase='complete',error=None);save_audit(auditfile,audit,paths.uid)
            return {'upgraded':True,'new_manifest':newhash,'runs_preserved':ids,'controller_groups':groups,'jobs_started':False,'rollback':False}
        except BaseException as error:
            if started:
                selected=decode(read(paths.state,65536,paths.uid))
                atomic(paths.state,canonical({**selected,'enabled':False}),paths.uid)
            audit.update(phase='failed',error=str(error)[-2000:]);save_audit(auditfile,audit,paths.uid)
            raise


def main():
    if os.geteuid()!=0 or len(sys.argv)!=1 or DECLARATION is None:raise ValueError('Use the fixed reviewed root-side upgrade launcher')
    os.umask(0o077)
    print(json.dumps(apply(DECLARATION)))


if __name__=='__main__':
    try:main()
    except Exception as error:print(json.dumps({'upgraded':False,'error':str(error)[-2000:]}),file=sys.stderr);raise SystemExit(2)
