"""One-off 02fee atomic retirement PREPARATION; never invoked by a worker.

Original files remain uncertain, incomplete and unacknowledged. Receipt files are
siblings of the unchanged original tree. No deletion or copy fallback exists.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import types

STATE = Path('/var/lib/eqemu-validator')
ARCHIVE = Path('/var/lib/eqemu-validator-transfer-archive-02fee-v1')
SLOT = 'last-integration'
RETIRED = 'original-461d7aad57cb41e8ade9e7e1afcc1ab3'
DATA_SHA = '0e0e71d7b21d5133f29eaccd52e599190fb889d631a540378bb1a49528fe196d'
V6_SHA = '4fe1738ea201bd1b898b426ec4be480f11155a8153fb5407a22aed30673bd8fc'
FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOATIME


def sha(raw): return hashlib.sha256(raw).hexdigest()


def canonical(value): return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


def read(path,limit=1048576):
    fd=os.open(path,FLAGS)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size>limit: raise ValueError('file')
        raw=os.pread(fd,limit+1,0)
        if len(raw)!=before.st_size or before!=os.fstat(fd): raise ValueError('changed')
        return raw
    finally: os.close(fd)


def metadata(info):
    return dict(device=info.st_dev,inode=info.st_ino,uid=info.st_uid,gid=info.st_gid,
                mode=stat.S_IMODE(info.st_mode),bytes=info.st_size)


def protected(info):
    return stat.S_ISDIR(info.st_mode) and info.st_uid==info.st_gid==0 and not info.st_mode&0o022


@contextlib.contextmanager
def directory(path,private=False):
    """Hold every ancestor; refuse symlinks and parent replacement."""
    fds=[];links=[]
    try:
        fd=os.open('/',FLAGS|os.O_DIRECTORY);fds.append(fd)
        if not protected(os.fstat(fd)): raise ValueError('parent')
        for i,name in enumerate(path.parts[1:]):
            parent=fd;fd=os.open(name,FLAGS|os.O_DIRECTORY,dir_fd=parent);fds.append(fd)
            info=os.fstat(fd)
            if private and i==len(path.parts)-2:
                if (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(995,980,0o700): raise ValueError('state')
            elif not protected(info): raise ValueError('parent')
            links.append((parent,name,fd,metadata(info)))
        def check():
            for parent,name,held,expected in links:
                actual=metadata(os.fstat(held));named=metadata(os.stat(name,dir_fd=parent,follow_symlinks=False))
                for k in ('device','inode','uid','gid','mode'):
                    if actual[k]!=expected[k] or named[k]!=expected[k]: raise ValueError('parent-changed')
        yield fd,check
        check()
    finally:
        for fd in reversed(fds): os.close(fd)


def rename(source_fd,source,destination_fd,destination):
    """Linux RENAME_NOREPLACE only; no overwrite and no cross-device fallback."""
    libc=ctypes.CDLL(None,use_errno=True)
    fn=libc.renameat2
    fn.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    fn.restype=ctypes.c_int
    if fn(source_fd,os.fsencode(source),destination_fd,os.fsencode(destination),1):
        code=ctypes.get_errno();raise OSError(code,errno.errorcode.get(code,'rename'))
    os.fsync(source_fd);os.fsync(destination_fd)


def tree(parent,name,expected):
    """Return exact inode/content records without changing original metadata."""
    fd=os.open(name,FLAGS|os.O_DIRECTORY,dir_fd=parent)
    try:
        before=metadata(os.fstat(fd))
        if before!=expected['directory']: raise ValueError('directory-identity')
        with os.scandir(fd) as entries:
            names=set()
            for entry in entries:
                if entry.name not in expected['files'] or entry.name in names: raise ValueError('members')
                names.add(entry.name)
        if names!=set(expected['files']): raise ValueError('members')
        for leaf,want in expected['files'].items():
            child=os.open(leaf,FLAGS,dir_fd=fd)
            try:
                info=os.fstat(child)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>4096: raise ValueError('file')
                raw=os.pread(child,4097,0)
                if dict(metadata(info),sha256=sha(raw))!=want: raise ValueError('file-identity')
                if info!=os.fstat(child) or info!=os.stat(leaf,dir_fd=fd,follow_symlinks=False): raise ValueError('file-changed')
            finally: os.close(child)
        if before!=metadata(os.fstat(fd)) or before!=metadata(os.stat(name,dir_fd=parent,follow_symlinks=False)): raise ValueError('tree-changed')
        return expected
    finally: os.close(fd)


def absent(fd,name):
    try: os.stat(name,dir_fd=fd,follow_symlinks=False)
    except FileNotFoundError: return True
    return False


def event(fd,name,value):
    child=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
    try:
        os.fchown(child,0,0);os.fchmod(child,0o600)
        raw=canonical(value)
        with os.fdopen(child,'wb',closefd=False) as stream: stream.write(raw);stream.flush();os.fsync(child)
    finally: os.close(child)
    os.fsync(fd)


def load_event(fd,name):
    child=os.open(name,FLAGS,dir_fd=fd)
    try:
        info=os.fstat(child)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(0,0,0o600) or info.st_size>4096: raise ValueError('receipt')
        raw=os.pread(child,4097,0);value=json.loads(raw)
        if raw!=canonical(value) or info!=os.fstat(child) or info!=os.stat(name,dir_fd=fd,follow_symlinks=False): raise ValueError('receipt-changed')
        return value
    finally: os.close(child)


def inspect(state,archive,expected):
    at_source=not absent(state,SLOT);at_archive=archive is not None and not absent(archive,RETIRED)
    if at_source and at_archive: raise ValueError('new-slot-or-duplicate')
    if not at_source and not at_archive: raise ValueError('missing-original')
    tree(state if at_source else archive,SLOT if at_source else RETIRED,expected)
    return 'original' if at_source else 'retired'


def transaction(op,host,expected):
    """host.guard holds the ordinary lock and verifies installed/publication history.

    Exceptions after socket stop deliberately leave it stopped. A protected intent
    records the previous socket state before retirement; no recovery is automatic.
    """
    with host.guard(), directory(STATE,private=True) as (state,check_state):
        with contextlib.ExitStack() as stack:
            archive=None;check_archive=lambda:None
            if ARCHIVE.exists() or ARCHIVE.is_symlink():
                archive,check_archive=stack.enter_context(directory(ARCHIVE))
                if stat.S_IMODE(os.fstat(archive).st_mode)!=0o700: raise ValueError('archive-mode')
                names=set(os.listdir(archive))
                if not names<=set((RETIRED,'intent.json','retired.json','rollback.json')) or 'intent.json' not in names: raise ValueError('archive-members')
                intent=load_event(archive,'intent.json')
                if set(intent)!={'schema','run','original','prior_socket_active','history'} or intent['schema']!=1 or intent['run']!=RETIRED or intent['original']!=expected or type(intent['prior_socket_active']) is not bool or intent['history']!=host.history: raise ValueError('intent-binding')
                for name in ('retired.json','rollback.json'):
                    if name in names and load_event(archive,name)!={'schema':1,'run':RETIRED,'state':'retired' if name=='retired.json' else 'original','uncertain':True,'ack':False}: raise ValueError('receipt-binding')
            else: intent=None
            current=inspect(state,archive,expected)
            host.verify();check_state();check_archive()
            if op=='verify':
                if intent is not None:
                    required='retired.json' if current=='retired' else 'rollback.json'
                    if absent(archive,required) or (current=='retired' and not absent(archive,'rollback.json')):
                        raise ValueError('interrupted-disposition')
                return dict(state=current,vm_started=False,uncertain=True,ack=False)
            if op=='apply' and intent is not None: raise ValueError('used-transaction')
            if op=='rollback' and (intent is None or current!='retired' or not absent(archive,'rollback.json')): raise ValueError('rollback-state')
            host.socket(False);host.verify();check_state();check_archive()
            host.writers({(expected['directory']['device'],expected['directory']['inode']),*((v['device'],v['inode']) for v in expected['files'].values())})
            if op=='apply':
                # Parent is outside worker-writable ancestry and held across creation.
                with directory(ARCHIVE.parent) as (parent,check_parent):
                    if os.fstat(parent).st_dev!=os.fstat(state).st_dev: raise ValueError('filesystem')
                    os.mkdir(ARCHIVE.name,0o700,dir_fd=parent);os.fsync(parent)
                    archive,check_archive=stack.enter_context(directory(ARCHIVE))
                    if os.fstat(archive).st_dev!=expected['directory']['device']: raise ValueError('filesystem')
                    intent=dict(schema=1,run=RETIRED,original=expected,prior_socket_active=host.prior_socket,history=host.history)
                    event(archive,'intent.json',intent);check_parent()
            host.verify();check_state();check_archive()
            if inspect(state,archive,expected)!=current: raise ValueError('state-changed')
            if op=='apply': rename(state,SLOT,archive,RETIRED)
            else: rename(archive,RETIRED,state,SLOT)
            tree(archive if op=='apply' else state,RETIRED if op=='apply' else SLOT,expected)
            if not absent(state if op=='apply' else archive,SLOT if op=='apply' else RETIRED): raise ValueError('namespace')
            host.verify();check_state();check_archive()
            event(archive,'retired.json' if op=='apply' else 'rollback.json',dict(schema=1,run=RETIRED,state='retired' if op=='apply' else 'original',uncertain=True,ack=False))
            if intent['prior_socket_active']: host.socket(True)
            return dict(state='retired' if op=='apply' else 'original',vm_started=False,uncertain=True,ack=False)


class Host:
    def __init__(self,package):
        self.package=Path(package)
        def module(name,path,want):
            # Execute only the exact frozen bytes just verified in memory. Package
            # paths are user-owned and must never be imported after a hash check.
            raw=read(path)
            if sha(raw)!=want: raise ValueError('helper-hash')
            value=types.ModuleType(name);value.__file__=str(path)
            exec(compile(raw,str(path),'exec'),value.__dict__)
            return value
        self.release=module('finite_v6',self.package/'v6/operator.py',
                            '9e7b899fdd3ec11ba20626e68bae0c15f8775c01b16e1f93454772fa0813f296')
        self.audit=module('finite_audit',self.package/'audit.py',
                          '5979299ebd41706e6e7f5affc33c7eabc30dfe0931c363c10aa788b159f68ba6')
        raw=read(self.package/'binding.json')
        if sha(raw)!=DATA_SHA: raise ValueError('binding')
        self.data=json.loads(raw)
        self.ops=self.release.Host();self.history=None

    @contextlib.contextmanager
    def guard(self):
        self.audit.Host().root();self.ops.quiescent()
        with directory(STATE,private=True) as (state,check):
            lock=os.open('worker.lock',FLAGS,dir_fd=state)
            try:
                info=os.fstat(lock)
                if not stat.S_ISREG(info.st_mode) or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(995,980,0o600): raise ValueError('lock')
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.prior_socket=self.ops.socket_active()
                with self.release.DerivedHistory(self.ops) as self.private:
                    expected=self.data['reported_private']['v6']['derived_private_observations']
                    if self.private.observations!=expected: raise ValueError('v5-identity')
                    self.manifest,self.baseline,self.assets=self.release.package(self.package/'v6',V6_SHA)
                    journal=self.release.JOURNAL
                    self.journal_fd=os.open(journal,FLAGS)
                    self.journal_info=os.fstat(self.journal_fd)
                    self.journal_raw=os.pread(self.journal_fd,65537,0)
                    if self.journal_info.st_size>65536 or not stat.S_ISREG(self.journal_info.st_mode): raise ValueError('journal')
                    self.history=dict(v6_journal=dict(metadata(self.journal_info),sha256=sha(self.journal_raw)),v5=expected)
                    try:
                        self.verify();yield
                        self.verify();check()
                        if info!=os.fstat(lock) or info!=os.stat('worker.lock',dir_fd=state,follow_symlinks=False): raise ValueError('lock-changed')
                    finally: os.close(self.journal_fd)
            finally: os.close(lock)

    def verify(self):
        self.ops.quiescent();self.private.check()
        for path,expected in self.data['public']['records'].items():
            if self.release.record(path,self.ops)!=expected: raise ValueError('installed-drift')
        fd=self.journal_fd;info=self.journal_info
        if info!=os.fstat(fd) or info!=self.release.JOURNAL.lstat() or os.pread(fd,65537,0)!=self.journal_raw: raise ValueError('journal-changed')
        _,events=self.release.journal(V6_SHA,self.ops,history=self.private)
        if not events or events[-1]['event']!='applied': raise ValueError('v6-not-applied')
        self.release.verify_state(self.manifest,self.baseline,self.ops,events,new_only=True,assets=self.assets,history=self.private)

    def socket(self,value): self.ops.socket(value)
    def writers(self,identities): self.ops.writers(identities)


def validate_package(path,digest):
    path=Path(path);raw=read(path/'manifest.json',65536)
    if sha(raw)!=digest: raise ValueError('package-hash')
    manifest=json.loads(raw)
    if set(manifest)!={'schema','assets'} or manifest['schema']!=1: raise ValueError('manifest')
    for name,expected in manifest['assets'].items():
        if name.startswith('/') or '..' in name.split('/'): raise ValueError('asset')
        data=read(path/name)
        if expected!=dict(bytes=len(data),sha256=sha(data)): raise ValueError('asset-hash')
    expected={'operator.py','binding.json','audit.py','v6/manifest.json'}
    v6=json.loads(read(path/'v6/manifest.json',65536))
    expected.update('v6/'+name for name in v6['assets'])
    if set(manifest['assets'])!=expected: raise ValueError('asset-inventory')
    seen=set();count=0
    for parent,dirs,files in os.walk(path,followlinks=False):
        count+=len(dirs)+len(files)
        if count>256: raise ValueError('members')
        for name in dirs+files:
            f=Path(parent)/name
            if f.is_symlink(): raise ValueError('symlink')
        seen.update(str((Path(parent)/name).relative_to(path)) for name in files)
    if seen!=expected|{'manifest.json'}: raise ValueError('unknown-members')
    if sha(read(path/'binding.json'))!=DATA_SHA: raise ValueError('binding')
    if sha(read(path/'v6/manifest.json'))!=V6_SHA: raise ValueError('v6')
    if sha(read(path/'audit.py'))!='5979299ebd41706e6e7f5affc33c7eabc30dfe0931c363c10aa788b159f68ba6': raise ValueError('audit')
    if sha(read(path/'v6/operator.py'))!='9e7b899fdd3ec11ba20626e68bae0c15f8775c01b16e1f93454772fa0813f296': raise ValueError('v6-operator')
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',required=True);parser.add_argument('--sha256',required=True)
    parser.add_argument('operation',choices=['verify','apply','rollback']);args=parser.parse_args()
    try:
        validate_package(args.package,args.sha256)
        host=Host(args.package);result=transaction(args.operation,host,host.data['reported_private']['audit']['records'])
        print(json.dumps(result,separators=(',',':')),flush=True);return 0
    except Exception:
        print('{"error":"02fee-retirement-refused","exit_code":2,"vm_started":false}',flush=True);return 2


if __name__=='__main__': raise SystemExit(main())
