"""Prepare and review one finite installed-b999 integration overlay.

Preparation only copies source/data. Root operations require a separately copied,
externally hash-verified operator and explicit package hash, outside NoNewPrivs.
This module never launches a worker, guest, native executable, Cargo or database.
"""
import argparse
import contextlib
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

sys.dont_write_bytecode=True
CODE=Path('/srv/eqemu-validator-code')
DIRECTORIES=(CODE,CODE/'validation',CODE/'validation/worker')
LOCK=Path('/var/lib/eqemu-validator/worker.lock')
JOURNAL=Path('/etc/eqemu-validator/integration-publication.json')
BACKUP=CODE/'.central-cdau-integration-backup-v1'
OPERATOR=Path('/usr/local/libexec/eqemu-cdau-integration-operator.py')
BASELINE_SHA='b3ab5338bd088d179f3895bc14b5a3a14daea3e147d9e7fc944643527868ad25'
SELECTION='central-cdau-integration-v1'
CHANGED=('validation/worker/runtime.py','validation/worker/guest.py','validation/worker/build_guest.py',
         'validation/worker/normal_world.py','validation/worker/client.py','validation/actor_runtime.py')
ADDED=('validation/worker/actor_integration.py','validation/worker/integration_artifacts.py',
       'validation/worker/integration-v1.4.json','validation/actor-integration-fixture.json','integration-release.json')
ASSETS=CHANGED+ADDED
FRONTEND_FILES=('validation/worker/integration-v1.3.json', 'validation/worker/integration-v1.4.json', 'validation/worker/integration-v1.2.json', 'validation/worker/integration-v1.1.json', 'validation/worker/integration-v1.json', 'validation/worker/actor_integration.py', 'validation/worker/integration_artifacts.py', 'validation/actor-integration-fixture.json', 'validation/worker/sanitizers.py', 'validation/worker/profile_contract.py', 'validation/worker/profiling.py', 'validation/worker/profile_artifacts.py', 'validation/worker/profile_inputs.py', 'scripts/validate-worker-candidate', 'validation/worker/identity.py', 'validation/worker/prepare.py', 'validation/worker/client.py', 'validation/inputs.py', 'validation/profile.json', 'validation/runtime-fixture.json', 'validation/worker/normal_world.py', 'validation/worker/snapshot.py', 'validation/worker/runtime.py', 'validation/worker/guest.py', 'validation/worker/quick_guest.py', 'validation/worker/quick_snapshot.py', 'validation/worker/build_guest.py', 'validation/actor.py', 'validation/actor_runtime.py', 'validation/debugger.py', 'validation/rust.py', 'validation/worker/jobs.py', 'scripts/validation-job', 'scripts/t3-validation-notify')
LIMIT=8*1024**2


def canonical(value): return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
def sha(raw): return hashlib.sha256(raw).hexdigest()


def read(path,limit=LIMIT):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size>limit: raise ValueError('Invalid finite package asset')
        raw=stream.read(limit+1);after=os.fstat(stream.fileno())
        if len(raw)!=before.st_size or (before.st_ino,before.st_dev,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_ino,after.st_dev,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            raise ValueError('Package asset changed during read')
        return raw


class Host:
    def info(self,path): return Path(path).lstat()
    def lock_info(self,fd): return os.fstat(fd)
    def metadata(self,fd,uid,gid,mode): os.fchown(fd,uid,gid);os.fchmod(fd,mode)
    def socket_active(self):
        result=subprocess.run(['/usr/bin/systemctl','is-active','eqemu-validator.socket'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
        if (result.returncode,result.stdout) not in ((0,b'active\n'),(3,b'inactive\n')): raise ValueError('Unknown ordinary socket state')
        return result.returncode==0
    def socket(self,active):
        subprocess.run(['/usr/bin/systemctl','start' if active else 'stop','eqemu-validator.socket'],check=True,timeout=30,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if self.socket_active()!=active: raise ValueError('Ordinary socket transition unconfirmed')
    def quiescent(self):
        result=subprocess.run(['/usr/bin/systemctl','list-units','--type=service','--state=activating,active,deactivating',
            '--no-legend','--no-pager','eqemu-validator@*.service','eqemu-validator-asan-v*@*.service','eqemu-validator-profiling@*.service'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
        if result.returncode or result.stdout.strip(): raise ValueError('Worker service activity is not quiescent')
        for suffix in ('','-asan-v1','-asan-v2','-asan-v3','-profiling'):
            active=Path('/var/lib/eqemu-validator'+suffix)/'active.json'
            if active.exists() or active.is_symlink(): raise ValueError('Private worker active state requires disposition')
    def writers(self,identities):
        # Ownership protection does not revoke already-open writable descriptors.
        for directory in Path('/proc').glob('[0-9]*'):
            if directory.name==str(os.getpid()): continue
            try:
                for entry in (directory/'fd').iterdir():
                    try:
                        info=entry.stat()
                        if (info.st_dev,info.st_ino) not in identities: continue
                        fields=dict(line.split(':',1) for line in (directory/'fdinfo'/entry.name).read_text().splitlines() if ':' in line)
                        if int(fields['flags'].strip(),8)&os.O_ACCMODE: raise ValueError('Existing writable helper descriptor')
                    except (FileNotFoundError,ProcessLookupError): pass
            except (FileNotFoundError,ProcessLookupError): pass


def record(path,host=None):
    host=host or Host();path=Path(path);info=host.info(path)
    if stat.S_ISLNK(info.st_mode): raise ValueError('Unexpected publication symlink')
    result=dict(uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode),inode=info.st_ino,device=info.st_dev)
    if stat.S_ISREG(info.st_mode): result.update(bytes=info.st_size,sha256=sha(read(path)))
    elif not stat.S_ISDIR(info.st_mode): raise ValueError('Unexpected publication inode type')
    again=host.info(path)
    if (info.st_ino,info.st_dev)!=(again.st_ino,again.st_dev): raise ValueError('Publication path replaced')
    return result


def content_record(raw,uid=0,gid=0,mode=0o644):
    return dict(bytes=len(raw),sha256=sha(raw),uid=uid,gid=gid,mode=mode)


def matches(actual,expected): return all(actual.get(k)==v for k,v in expected.items())


def baseline_check(baseline,host):
    for group in ('files','directories','retained'):
        for name,expected in baseline[group].items():
            if record(name,host)!=expected: raise ValueError('Original installed baseline drift: '+name)


def patch_files(old,patch):
    """Apply only exact, zero-fuzz reviewed hunks to the six pinned source files."""
    lines=patch.decode().splitlines(True);index=0;result={}
    while index<len(lines):
        if not lines[index].startswith('--- a/'): raise ValueError('Invalid finite patch header')
        name=lines[index][6:].rstrip('\n');index+=1
        if name not in CHANGED or name in result or lines[index]!='+++ b/'+name+'\n': raise ValueError('Unknown finite patch target')
        index+=1;source=old[name].decode().splitlines(True);output=[];position=0
        while index<len(lines) and lines[index].startswith('@@ '):
            match=re.fullmatch(r'@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n',lines[index])
            if not match: raise ValueError('Invalid finite patch hunk')
            start=int(match[1])-1;old_count=int(match[2] or 1);new_count=int(match[4] or 1);index+=1
            if start<position: raise ValueError('Overlapping finite patch hunk')
            output.extend(source[position:start]);position=start;used=written=0
            while index<len(lines) and not lines[index].startswith(('@@ ','--- a/')):
                line=lines[index];index+=1
                if line[0] in ' -':
                    if position>=len(source) or source[position]!=line[1:]: raise ValueError('Installed bytes do not match patch')
                    position+=1;used+=1
                if line[0] in ' +': output.append(line[1:]);written+=1
                if line[0] not in ' +-': raise ValueError('Unknown finite patch operation')
            if used!=old_count or written!=new_count: raise ValueError('Finite patch count mismatch')
        output.extend(source[position:]);result[name]=''.join(output).encode()
    if set(result)!=set(CHANGED): raise ValueError('Incomplete finite overlay')
    return result


def prepare(source,output):
    source=Path(source);output=Path(output)
    status=subprocess.run(['/usr/bin/git','-C',str(source),'-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null','status','--porcelain','--untracked-files=all'],check=True,stdout=subprocess.PIPE).stdout
    if status: raise ValueError('Preparation requires a clean committed Stack checkout')
    commit=subprocess.run(['/usr/bin/git','-C',str(source),'rev-parse','HEAD'],check=True,stdout=subprocess.PIPE).stdout.decode().strip()
    if not re.fullmatch('[a-f0-9]{40}',commit): raise ValueError('Invalid Stack source pin')
    def source_bytes(name):
        result=subprocess.run(['/usr/bin/git','-C',str(source),'show',commit+':'+name],check=True,stdout=subprocess.PIPE).stdout
        if len(result)>LIMIT: raise ValueError('Source blob exceeds package budget')
        return result
    baseline_raw=source_bytes('validation/worker/integration-b999-baseline.json')
    if sha(baseline_raw)!=BASELINE_SHA: raise ValueError('Changed installed baseline contract')
    baseline=json.loads(baseline_raw);baseline_check(baseline,Host())
    old={name:read(CODE/name) for name in CHANGED}
    for name,raw in old.items():
        if not matches(content_record(raw),{k:baseline['files'][str(CODE/name)][k] for k in ('bytes','sha256')}): raise ValueError('Changed original helper during preparation')
    patch=source_bytes('validation/worker/integration-b999.patch')
    forward=patch_files(old,patch)
    for name in ADDED[:-1]: forward[name]=source_bytes(name)
    # Derive the complete narrow installed inventory without importing its code.
    sys.path.insert(0,str(source/'validation/worker'))
    from integration_artifacts import INSTALLED_FILES
    installed={}
    for name in INSTALLED_FILES:
        if name=='integration-release.json': continue
        if name in forward: installed[name]=content_record(forward[name])
        else:
            expected=baseline['files'][str(CODE/name)]
            installed[name]={k:expected[k] for k in ('bytes','sha256','uid','gid','mode')}
    release=dict(schema=1,selection=SELECTION,source_commit=commit,
                 base_runtime_sha256=baseline['files'][str(CODE/'validation/worker/runtime.py')]['sha256'],files=installed)
    forward['integration-release.json']=canonical(release)
    output.mkdir(mode=0o700)
    assets={}
    def copy(name,raw):
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with path.open('xb') as stream: stream.write(raw);stream.flush();os.fsync(stream.fileno())
        path.chmod(0o700 if name.startswith('frontend/scripts/') else 0o600);assets[name]=dict(bytes=len(raw),sha256=sha(raw))
    for name,raw in forward.items(): copy('forward/'+name,raw)
    for name,raw in old.items(): copy('rollback/'+name,raw)
    for name in FRONTEND_FILES:
        if 'frontend/'+name not in assets: copy('frontend/'+name,source_bytes(name))
    copy('frontend/stack-source.json',canonical(dict(source_commit=commit)))
    copy('baseline.json',baseline_raw);copy('installed.patch',patch);copy('operator.py',source_bytes('validation/worker/integration_release.py'))
    fixture=json.loads(source_bytes('validation/actor-integration-fixture.json'))
    runtime_fixture=json.loads(source_bytes('validation/runtime-fixture.json'))
    inputs=dict(native=dict(bytes=469000192,sha256='02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4'),
                runtime={k:runtime_fixture['iso'][k] for k in ('bytes','sha256')},
                rust=fixture['rust_input'],fixture=dict(fixture['fixture'],manifest_sha256=fixture['manifest_sha256']))
    manifest=dict(schema=1,selection=SELECTION,source_commit=commit,baseline_sha256=BASELINE_SHA,inputs=inputs,
                  assets=assets,installed={name:content_record(raw) for name,raw in forward.items()},
                  directories={str(path):dict(uid=0,gid=0,mode=0o755,inode=baseline['directories'][str(path)]['inode'],device=baseline['directories'][str(path)]['device']) for path in DIRECTORIES},
                  retained_mutable_exceptions=[name for name in baseline['files'] if name not in {str(CODE/n) for n in CHANGED}],
                  backup=str(BACKUP),journal=str(JOURNAL),shared_lock=str(LOCK))
    baseline_check(baseline,Host())
    raw=canonical(manifest);(output/'manifest.json').write_bytes(raw);(output/'manifest.json').chmod(0o600)
    return dict(package=str(output),manifest_sha256=sha(raw),operator_sha256=assets['operator.py']['sha256'],source_commit=commit,
                commands={operation:['/usr/bin/python3','-I',str(OPERATOR),'--package',str(output),'--sha256',sha(raw),operation] for operation in ('verify','apply','rollback')})


def package(path,digest):
    path=Path(path)
    if not re.fullmatch('[a-f0-9]{64}',digest): raise ValueError('Exact reviewed package SHA256 required')
    raw=read(path/'manifest.json')
    if sha(raw)!=digest: raise ValueError('Package hash differs from review')
    value=json.loads(raw)
    if (set(value)!={'schema','selection','source_commit','baseline_sha256','assets','installed','directories','retained_mutable_exceptions','backup','journal','shared_lock','inputs'}
            or value['schema']!=1 or value['selection']!=SELECTION or value['baseline_sha256']!=BASELINE_SHA
            or set(value['installed'])!=set(ASSETS) or set(value['directories'])!={str(p) for p in DIRECTORIES}
            or value['backup']!=str(BACKUP) or value['journal']!=str(JOURNAL) or value['shared_lock']!=str(LOCK)):
        raise ValueError('Unknown finite package shape')
    expected_assets={'forward/'+name for name in ASSETS}|{'rollback/'+name for name in CHANGED}|{'frontend/'+name for name in FRONTEND_FILES}|{'frontend/stack-source.json','baseline.json','installed.patch','operator.py'}
    if set(value['assets'])!=expected_assets: raise ValueError('Unknown or missing finite package asset')
    if not isinstance(value['source_commit'],str) or not re.fullmatch('[a-f0-9]{40}',value['source_commit']): raise ValueError('Invalid package source pin')
    frozen={}
    for name,expected in value['assets'].items():
        if not isinstance(name,str) or name.startswith('/') or '..' in name.split('/') or not name.startswith(('forward/','rollback/','frontend/','baseline.json','installed.patch','operator.py')): raise ValueError('Unknown package asset path')
        data=read(path/name)
        if expected!={'bytes':len(data),'sha256':sha(data)}: raise ValueError('Package asset identity mismatch')
        frozen[name]=data
        if sum(len(v) for v in frozen.values())>LIMIT: raise ValueError('Aggregate finite package budget')
    if sha(frozen['baseline.json'])!=BASELINE_SHA: raise ValueError('Changed baseline asset')
    for name,expected in value['installed'].items():
        if expected!=content_record(frozen['forward/'+name]): raise ValueError('Changed forward target metadata')
    if set(n[8:] for n in value['assets'] if n.startswith('forward/'))!=set(ASSETS) or set(n[9:] for n in value['assets'] if n.startswith('rollback/'))!=set(CHANGED): raise ValueError('Missing or extra publication asset')
    baseline=json.loads(frozen['baseline.json'])
    for name in CHANGED:
        old=baseline['files'][str(CODE/name)]
        if content_record(frozen['rollback/'+name],old['uid'],old['gid'],old['mode'])!={k:old[k] for k in ('bytes','sha256','uid','gid','mode')}: raise ValueError('Changed rollback target')
    for directory in DIRECTORIES:
        old=baseline['directories'][str(directory)]
        if value['directories'][str(directory)]!={k:dict(old,uid=0,gid=0,mode=0o755)[k] for k in ('uid','gid','mode','inode','device')}: raise ValueError('Changed directory metadata declaration')
    if value['retained_mutable_exceptions']!=[name for name in baseline['files'] if name not in {str(CODE/n) for n in CHANGED}]: raise ValueError('Changed mutable exception inventory')
    release=json.loads(frozen['forward/integration-release.json'])
    expected_files={}
    for absolute,old in baseline['files'].items():
        name=str(Path(absolute).relative_to(CODE))
        expected_files[name]=value['installed'][name] if name in CHANGED else {k:old[k] for k in ('bytes','sha256','uid','gid','mode')}
    for name in ADDED[:-1]: expected_files[name]=value['installed'][name]
    expected_release=dict(schema=1,selection=SELECTION,source_commit=value['source_commit'],base_runtime_sha256=baseline['files'][str(CODE/'validation/worker/runtime.py')]['sha256'],files=expected_files)
    if release!=expected_release or type(release['schema']) is not int: raise ValueError('Installed/frontend source identity mismatch')
    fixture=json.loads(frozen['forward/validation/actor-integration-fixture.json'])
    runtime_fixture=json.loads(frozen['frontend/validation/runtime-fixture.json'])
    expected_inputs=dict(native=dict(bytes=469000192,sha256='02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4'),runtime={k:runtime_fixture['iso'][k] for k in ('bytes','sha256')},rust=fixture['rust_input'],fixture=dict(fixture['fixture'],manifest_sha256=fixture['manifest_sha256']))
    if value['inputs']!=expected_inputs: raise ValueError('Selected package inputs differ')
    if json.loads(frozen['frontend/stack-source.json'])!={'source_commit':value['source_commit']}: raise ValueError('Frontend source receipt mismatch')
    if frozen['operator.py']!=read(Path(__file__)): raise ValueError('Installed operator differs from reviewed package')
    return value,baseline,frozen


@contextlib.contextmanager
def ordinary_lock(host):
    fd=os.open(LOCK,os.O_RDWR|os.O_NOFOLLOW)
    try:
        info=host.lock_info(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=995 or info.st_gid!=980 or stat.S_IMODE(info.st_mode)!=0o600:
            raise ValueError('Unexpected existing ordinary lock metadata')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        again=LOCK.lstat()
        if (info.st_dev,info.st_ino)!=(again.st_dev,again.st_ino): raise ValueError('Ordinary lock was replaced')
        host.quiescent()
        again=LOCK.lstat()
        if (info.st_dev,info.st_ino)!=(again.st_dev,again.st_ino): raise ValueError('Ordinary lock changed before publication')
        yield
        again=LOCK.lstat()
        if (info.st_dev,info.st_ino)!=(again.st_dev,again.st_ino): raise ValueError('Ordinary lock changed during publication')
    finally: os.close(fd)


def sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def journal(package_sha,host,*,create=False):
    if create:
        fd=os.open(JOURNAL,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            host.metadata(stream.fileno(),0,0,0o600)
            header=dict(schema=1,package_sha256=package_sha,prior_socket_active=host.socket_active())
            stream.write(canonical(header));stream.flush();os.fsync(stream.fileno())
        sync(JOURNAL.parent)
    info=host.info(JOURNAL)
    if info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o600 or not stat.S_ISREG(info.st_mode): raise ValueError('Publication journal is not protected')
    lines=read(JOURNAL,65536).splitlines(keepends=True)
    header=json.loads(lines[0])
    if set(header)!={'schema','package_sha256','prior_socket_active'} or header['schema']!=1 or header['package_sha256']!=package_sha or type(header['prior_socket_active']) is not bool: raise ValueError('Publication journal binding differs')
    events=[]
    for line in lines[1:]:
        if not line.endswith(b'\n'): raise ValueError('Partial publication journal requires external root disposition')
        event=json.loads(line)
        if set(event)!={'event','name','inode','device'} or event['event'] not in ('protected','published','applied','restored','removed','rolled-back'):
            raise ValueError('Unknown publication journal event')
        if event['name'] not in (*ASSETS,*map(str,DIRECTORIES),'all'): raise ValueError('Unknown journal target')
        if any(type(event[k]) is not int or event[k]<0 for k in ('inode','device')): raise ValueError('Unknown journal inode')
        events.append(event)
    return header,events


def append(event,name,info=None):
    value=dict(event=event,name=name,inode=info.st_ino if info else 0,device=info.st_dev if info else 0)
    fd=os.open(JOURNAL,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
    with os.fdopen(fd,'wb') as stream: stream.write(canonical(value));stream.flush();os.fsync(stream.fileno())


def current_kind(name,manifest,baseline,host,events):
    path=CODE/name
    if not path.exists() and not path.is_symlink(): return 'absent'
    actual=record(path,host)
    if matches(actual,manifest['installed'][name]):
        published=[e for e in events if e['event']=='published' and e['name']==name]
        if published and (actual['inode'],actual['device'])!=(published[-1]['inode'],published[-1]['device']): raise ValueError('Published helper inode drift')
        return 'new'
    if name in CHANGED:
        old=baseline['files'][str(path)]
        if actual==old: return 'old'
        # fchown and fchmod are separate syscalls in both protection and restore.
        # Only the exact old inode/content with their finite intermediate metadata qualifies.
        if actual in (dict(old,uid=0,gid=0,mode=old['mode']),
                      dict(old,uid=0,gid=0,mode=0o600),
                      dict(old,mode=0o600)): return 'protected'
    raise ValueError('Unknown bytes or metadata at finite publication target: '+name)


def verify_state(manifest,baseline,host,events,*,old_only=False,new_only=False,assets=None):
    for name,expected in baseline['retained'].items():
        if record(name,host)!=expected: raise ValueError('Retained selection drift: '+name)
    for name,expected in baseline['files'].items():
        if name not in {str(CODE/n) for n in CHANGED} and record(name,host)!=expected: raise ValueError('Mutable ordinary exception drift: '+name)
    for path in DIRECTORIES:
        before=baseline['directories'][str(path)];after=dict(before,uid=0,gid=0,mode=0o755)
        actual=record(path,host)
        if actual not in (before,after) or (old_only and actual!=before) or (new_only and actual!=after): raise ValueError('Directory identity/metadata drift')
    kinds={name:current_kind(name,manifest,baseline,host,events) for name in ASSETS}
    if old_only and any(kinds[n]!=('old' if n in CHANGED else 'absent') for n in ASSETS): raise ValueError('Original ordinary closure is not restored')
    if new_only and any(value!='new' for value in kinds.values()): raise ValueError('New installed closure is incomplete')
    # Known temporary prefixes are removable after an interrupted write. Unknown
    # bytes, types or ownership are never overwritten, even during rollback.
    temporary_paths={}
    for name in ASSETS:
        temporary=(CODE/name).with_name(Path(name).name+'.cdau-new')
        if temporary.exists() or temporary.is_symlink():
            actual=record(temporary,host)
            raw=read(temporary)
            if (assets is None or actual['uid']!=0 or actual['gid']!=0 or actual['mode'] not in (0o600,0o644)
                    or raw!=assets['forward/'+name][:len(raw)] or len(raw)>len(assets['forward/'+name])):
                raise ValueError('Unknown staged publication bytes')
            if old_only or new_only: raise ValueError('Staged publication is unfinished')
            temporary_paths[temporary]=name
    allowed_files={Path(name) for name in baseline['files']}|{CODE/name for name in ADDED}|set(temporary_paths)
    allowed_directories={CODE}
    for path in allowed_files:
        allowed_directories.update(parent for parent in path.parents if parent==CODE or CODE in parent.parents)
    if BACKUP.exists(): allowed_directories.add(BACKUP)
    for path in CODE.rglob('*'):
        if BACKUP in path.parents: continue
        info=host.info(path)
        if stat.S_ISDIR(info.st_mode):
            if path not in allowed_directories: raise ValueError('Unknown installed directory')
        elif path not in allowed_files: raise ValueError('Unknown installed asset')
    # Every backup is one of the original six inodes, never an arbitrary tree.
    if BACKUP.exists():
        allowed={Path(name) for name in CHANGED}
        allowed_dirs={parent for name in allowed for parent in name.parents}
        for path in BACKUP.rglob('*'):
            info=host.info(path)
            if stat.S_ISDIR(info.st_mode):
                if path.relative_to(BACKUP) not in allowed_dirs: raise ValueError('Unknown backup directory')
                if info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError('Unprotected rollback directory')
                continue
            relative=path.relative_to(BACKUP)
            if relative not in allowed: raise ValueError('Unknown rollback backup asset')
            expected=dict(baseline['files'][str(CODE/relative)],uid=0,gid=0,mode=0o600)
            if record(path,host)!=expected: raise ValueError('Rollback backup identity drift')
    for name in CHANGED:
        if kinds[name]=='new':
            expected=dict(baseline['files'][str(CODE/name)],uid=0,gid=0,mode=0o600)
            if not (BACKUP/name).exists() or record(BACKUP/name,host)!=expected: raise ValueError('Original rollback inode is unavailable')
    return kinds


def protect_directory(path,expected,host):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        before=record(path,host)
        if before not in (expected,dict(expected,uid=0,gid=0,mode=0o755)): raise ValueError('Directory changed before protection')
        actual=os.fstat(fd)
        if (actual.st_ino,actual.st_dev)!=(before['inode'],before['device']): raise ValueError('Directory descriptor mismatch')
        host.metadata(fd,0,0,0o755)
        if record(path,host)!=dict(expected,uid=0,gid=0,mode=0o755): raise ValueError('Directory protection failed')
        append('protected',str(path),host.info(path))
    finally: os.close(fd)


def protected_backup_parents(name,host):
    path=BACKUP/Path(name).parent
    for directory in [BACKUP,*[BACKUP/p for p in reversed(Path(name).parent.parents) if str(p)!='.'],path]:
        if not directory.exists(): directory.mkdir(mode=0o700)
        fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: host.metadata(fd,0,0,0o700)
        finally: os.close(fd)
        info=host.info(directory)
        if info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o700: raise ValueError('Rollback parent protection failed')


def apply(path,digest,host=None):
    host=host or Host();manifest,baseline,assets=package(path,digest)
    with ordinary_lock(host):
        if not JOURNAL.exists():
            verify_state(manifest,baseline,host,[],old_only=True,assets=assets)
            header,events=journal(digest,host,create=True)
        else:
            header,events=journal(digest,host)
        kinds=verify_state(manifest,baseline,host,events,assets=assets)
        if events and events[-1]['event']=='rolled-back': raise ValueError('Rolled-back package requires fresh reviewed preparation')
        host.socket(False);host.quiescent()
        for directory in DIRECTORIES: protect_directory(directory,baseline['directories'][str(directory)],host)
        # Protection precedes the second complete hash/inode/metadata inventory.
        _,events=journal(digest,host);kinds=verify_state(manifest,baseline,host,events,assets=assets)
        for name in ASSETS:
            if kinds[name]=='new':
                temporary=(CODE/name).with_name(Path(name).name+'.cdau-new')
                if temporary.exists(): temporary.unlink();sync(temporary.parent)
                continue
            target=CODE/name
            if name in CHANGED:
                expected=baseline['files'][str(target)]
                fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
                try:
                    if current_kind(name,manifest,baseline,host,events) not in ('old','protected'): raise ValueError('Target changed before protection')
                    opened=os.fstat(fd)
                    if (opened.st_ino,opened.st_dev)!=(expected['inode'],expected['device']): raise ValueError('Changed helper descriptor mismatch')
                    host.metadata(fd,0,0,0o600)
                    host.writers({(expected['device'],expected['inode'])})
                    if record(target,host)!=dict(expected,uid=0,gid=0,mode=0o600): raise ValueError('Changed helper drift after protection')
                    protected_backup_parents(name,host)
                    backup=BACKUP/name
                    if not backup.exists(): os.link(target,backup,follow_symlinks=False)
                    if record(backup,host)!=dict(expected,uid=0,gid=0,mode=0o600): raise ValueError('Original inode backup mismatch')
                    sync(backup.parent)
                finally: os.close(fd)
            elif target.exists() or target.is_symlink(): raise ValueError('New helper target appeared')
            temporary=target.with_name(target.name+'.cdau-new')
            if temporary.exists(): temporary.unlink();sync(temporary.parent)
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            try:
                with os.fdopen(fd,'wb') as stream:
                    host.metadata(stream.fileno(),0,0,0o644)
                    stream.write(assets['forward/'+name]);stream.flush();os.fsync(stream.fileno())
                if not matches(record(temporary,host),manifest['installed'][name]): raise ValueError('Staged helper identity mismatch')
                os.replace(temporary,target);sync(target.parent)
                append('published',name,host.info(target))
            finally:
                if temporary.exists(): temporary.unlink()
        _,events=journal(digest,host);verify_state(manifest,baseline,host,events,new_only=True,assets=assets)
        append('applied','all')
        if header['prior_socket_active']: host.socket(True)
    return dict(state='applied',source_commit=manifest['source_commit'],new_files=len(ASSETS),vm_started=False)


def rollback(path,digest,host=None):
    host=host or Host();manifest,baseline,assets=package(path,digest)
    with ordinary_lock(host):
        header,events=journal(digest,host)
        kinds=verify_state(manifest,baseline,host,events,assets=assets)
        host.socket(False);host.quiescent()
        # Validate ALL targets first, then protect the same three parents before mutation.
        for directory in DIRECTORIES: protect_directory(directory,baseline['directories'][str(directory)],host)
        # Directory protection prevents replacement, but old UID1000 file ownership
        # still permits writes. Freeze those exact inodes before the second inventory.
        for name in CHANGED:
            if current_kind(name,manifest,baseline,host,events) in ('old','protected'):
                target=CODE/name;expected=baseline['files'][str(target)]
                fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
                try:
                    opened=os.fstat(fd)
                    if (opened.st_ino,opened.st_dev)!=(expected['inode'],expected['device']): raise ValueError('Rollback helper descriptor mismatch')
                    host.metadata(fd,0,0,0o600)
                    host.writers({(expected['device'],expected['inode'])})
                    if record(target,host)!=dict(expected,uid=0,gid=0,mode=0o600): raise ValueError('Rollback helper drift after protection')
                finally: os.close(fd)
        _,events=journal(digest,host)
        kinds=verify_state(manifest,baseline,host,events,assets=assets)
        for name in ASSETS:
            temporary=(CODE/name).with_name(Path(name).name+'.cdau-new')
            if temporary.exists(): temporary.unlink();sync(temporary.parent)
        for name in reversed(ASSETS):
            target=CODE/name;kind=kinds[name]
            if name in ADDED:
                if kind=='new': target.unlink();sync(target.parent);append('removed',name)
                elif kind!='absent': raise ValueError('Unknown additive rollback asset')
            else:
                expected=baseline['files'][str(target)];backup=BACKUP/name
                if kind=='new':
                    if not backup.exists(): raise ValueError('Original inode is unavailable for rollback')
                    os.replace(backup,target);sync(target.parent)
                elif backup.exists(): backup.unlink();sync(backup.parent)
                fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
                try: host.metadata(fd,expected['uid'],expected['gid'],expected['mode'])
                finally: os.close(fd)
                if record(target,host)!=expected: raise ValueError('Original helper inode/bytes/metadata not restored')
                append('restored',name,host.info(target))
        # Files and retained closures must match before directory permissions reopen.
        for name,expected in {**baseline['files'],**baseline['retained']}.items():
            if record(name,host)!=expected: raise ValueError('Original closure verification failed')
        for directory in reversed(DIRECTORIES):
            expected=baseline['directories'][str(directory)]
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try: host.metadata(fd,expected['uid'],expected['gid'],expected['mode'])
            finally: os.close(fd)
        _,events=journal(digest,host);verify_state(manifest,baseline,host,events,old_only=True,assets=assets)
        append('rolled-back','all')
        if header['prior_socket_active']: host.socket(True)
    return dict(state='rolled-back',vm_started=False)


def verify(path,digest,host=None):
    host=host or Host();manifest,baseline,assets=package(path,digest)
    with ordinary_lock(host):
        events=journal(digest,host)[1] if JOURNAL.exists() else []
        if events and events[-1]['event']=='applied': verify_state(manifest,baseline,host,events,new_only=True,assets=assets);state='new'
        else: verify_state(manifest,baseline,host,events,old_only=True,assets=assets);state='original'
    return dict(state=state,source_commit=manifest['source_commit'],vm_started=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--package',type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('operation',choices=('prepare','verify','apply','rollback'))
    args=parser.parse_args()
    try:
        if args.operation=='prepare':
            if args.output is None or args.package or args.sha256: raise ValueError('Preparation needs one fresh private output')
            value=prepare(Path(__file__).resolve().parents[2],args.output)
        else:
            if args.output or args.package is None or args.sha256 is None: raise ValueError('Exact finite package and SHA256 required')
            if os.geteuid()!=0 or Path(__file__).resolve()!=OPERATOR: raise ValueError('Use separately installed and externally verified root operator')
            for parent in (*reversed(OPERATOR.parents),OPERATOR):
                info=parent.lstat()
                if info.st_uid!=0 or info.st_mode&0o022 or stat.S_ISLNK(info.st_mode): raise ValueError('Operator path is not root protected')
            if 'NoNewPrivs:\t0' not in Path('/proc/self/status').read_text(): raise ValueError('Real external root outside NoNewPrivs required')
            value={'verify':verify,'apply':apply,'rollback':rollback}[args.operation](args.package,args.sha256)
        print(json.dumps(value,sort_keys=True));return 0
    except Exception as error:
        print(json.dumps(dict(error=str(error),executed=False,admitted=False)),file=sys.stderr);return 2


if __name__=='__main__': raise SystemExit(main())
