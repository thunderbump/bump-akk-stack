"""Finite root READ-ONLY audit of the original 02fee retained transfer, never recovery."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

STATE = Path('/var/lib/eqemu-validator')
WORKER_UID, WORKER_GID = 995, 980
RUN = '461d7aad57cb41e8ade9e7e1afcc1ab3'
CANDIDATE = 'e35d4513c44e5eacac796a36fd68cd30acb7706a'
FIXTURE = 'cf71b70acf549328552b3c203d2760571cb40b4d816f8aaf0ee447629039c48c'
NAME = 'central-cdau-integration-v1.json'
LIMITS = {NAME: 851968, 'pending.json': 1024, 'receipt.json': 4096}
BINDING = dict(version=1, name=NAME, candidate=CANDIDATE, run_id=RUN, fixture_sha256=FIXTURE)
RECEIPT = dict(BINDING, bytes=0, sha256=hashlib.sha256(b'').hexdigest(), terminal=True,
               complete=False, client_durable=False, original_transfer='uncertain',
               error='integration-incomplete', execution=dict(workload_exit_code=2, validator_exit_code=2,
               native_cleanup='not-run', database_cleanup=True, vm_cleanup=True))
EXTERNAL = dict(observation_sha256='07e1226c4dbe8e923f97037216abf806284ff078f35bbfe4ad23f014dcb472ea',
                server_tree='f288d612781a4ceb9d8595f4d36d797c863080b1',
                payload_sha256='46465bd9d7a68517e7571d40be3ab9118ed8e58198308a93bdfdf5fcec6be4ba',
                provenance='compiled-reviewed-trusted-worker-observation', observed_in_protected_files=False)


class Refused(Exception):
    """Only fixed reason vocabulary may leave this privileged helper."""
    def __init__(self, reason):
        if reason not in ('arguments','root','quiescence','parent','state','lock','members','file','changed','binding','size','io'):
            reason='io'
        self.reason=reason


def fingerprint(info):
    return tuple(getattr(info, name) for name in ('st_dev','st_ino','st_uid','st_gid','st_mode','st_size',
                                                'st_nlink','st_atime_ns','st_mtime_ns','st_ctime_ns'))


def metadata(info):
    return dict(device=info.st_dev,inode=info.st_ino,uid=info.st_uid,gid=info.st_gid,
                mode=stat.S_IMODE(info.st_mode),bytes=info.st_size)


def same(actual, expected):
    if type(actual) is not type(expected): return False
    if isinstance(expected,dict):
        return set(actual)==set(expected) and all(same(actual[k],v) for k,v in expected.items())
    return actual==expected


def decode(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value: raise Refused('binding')
            value[key]=item
        return value
    try: return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(Refused('binding')))
    except (ValueError,UnicodeError): raise Refused('binding') from None


class Host:
    def root(self):
        if os.geteuid()!=0 or os.getegid()!=0: raise Refused('root')
        with Path('/proc/self/status').open() as stream: raw=stream.read(16385)
        if len(raw)>16384: raise Refused('root')
        status=dict(line.split(':',1) for line in raw.splitlines() if ':' in line)
        if status.get('NoNewPrivs','').strip()!='0': raise Refused('root')

    def parent(self, info):
        return stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_gid==0 and not info.st_mode&0o022

    def quiescent(self):
        args=['/usr/bin/systemctl','list-units','--type=service','--state=active,activating,deactivating',
              '--no-legend','--no-pager','eqemu-validator@*.service','eqemu-validator-asan-v*@*.service',
              'eqemu-validator-profiling@*.service']
        result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10,
                              env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
        if result.returncode or result.stdout: raise Refused('quiescence')
        # Existing guards inspect marker existence only, never another private JSON record.
        for suffix in ('','-asan-v1','-asan-v2','-asan-v3','-profiling'):
            marker=Path('/var/lib/eqemu-validator'+suffix)/'active.json'
            try: marker.lstat()
            except FileNotFoundError: continue
            raise Refused('quiescence')


def audit(host=None):
    host=host or Host();host.root();host.quiescent()
    if not hasattr(os,'O_NOATIME'): raise Refused('io')
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_NOATIME
    descriptors=[];chain=[];opened=[]
    def directory(name,parent=None):
        fd=os.open(name,flags|os.O_DIRECTORY,**({} if parent is None else {'dir_fd':parent}))
        descriptors.append(fd)
        return fd
    def state_metadata(info):
        return stat.S_ISDIR(info.st_mode) and (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))==(WORKER_UID,WORKER_GID,0o700)
    def check_chain():
        for parent,name,fd,before,private in chain:
            named=os.stat(name,dir_fd=parent,follow_symlinks=False)
            current=os.fstat(fd)
            if fingerprint(named)!=before or fingerprint(current)!=before: raise Refused('changed')
            if not (state_metadata(current) if private else host.parent(current)): raise Refused('state' if private else 'parent')
    def read_file(parent,name,limit):
        fd=os.open(name,flags,dir_fd=parent);descriptors.append(fd);info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1
                or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(WORKER_UID,WORKER_GID,0o600)):
            raise Refused('file')
        if not 0<=info.st_size<=limit: raise Refused('size')
        before=fingerprint(info);raw=os.pread(fd,limit+1,0)
        if len(raw)!=info.st_size or fingerprint(os.fstat(fd))!=before: raise Refused('changed')
        if fingerprint(os.stat(name,dir_fd=parent,follow_symlinks=False))!=before: raise Refused('changed')
        opened.append((parent,name,fd,before,raw,limit))
        return raw,dict(metadata(info),sha256=hashlib.sha256(raw).hexdigest())
    try:
        root=directory('/');parent=root
        if not host.parent(os.fstat(root)): raise Refused('parent')
        for index,name in enumerate(STATE.parts[1:]):
            fd=directory(name,parent);info=os.fstat(fd);private=index==len(STATE.parts)-2
            if not (state_metadata(info) if private else host.parent(info)): raise Refused('state' if private else 'parent')
            chain.append((parent,name,fd,fingerprint(info),private));parent=fd
        state=parent
        lock=os.open('worker.lock',flags,dir_fd=state);descriptors.append(lock);lock_info=os.fstat(lock)
        if (not stat.S_ISREG(lock_info.st_mode)
                or (lock_info.st_uid,lock_info.st_gid,stat.S_IMODE(lock_info.st_mode))!=(WORKER_UID,WORKER_GID,0o600)):
            raise Refused('lock')
        lock_before=fingerprint(lock_info)
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise Refused('lock') from None
        host.quiescent()
        target=directory('last-integration',state);target_info=os.fstat(target)
        if not state_metadata(target_info): raise Refused('state')
        chain.append((state,'last-integration',target,fingerprint(target_info),True))
        if set(os.listdir(target))!=set(LIMITS): raise Refused('members')
        raw={};records={}
        for name,limit in LIMITS.items():raw[name],records[name]=read_file(target,name,limit)
        if not same(decode(raw['pending.json']),BINDING) or not same(decode(raw['receipt.json']),RECEIPT) or raw[NAME]!=b'':
            raise Refused('binding')
        host.quiescent()
        # All three held descriptors and names are re-read after the complete observation.
        for parent,name,fd,before,data,limit in opened:
            if (fingerprint(os.stat(name,dir_fd=parent,follow_symlinks=False))!=before
                    or fingerprint(os.fstat(fd))!=before or os.pread(fd,limit+1,0)!=data
                    or fingerprint(os.fstat(fd))!=before): raise Refused('changed')
        if set(os.listdir(target))!=set(LIMITS): raise Refused('members')
        if (fingerprint(os.fstat(lock))!=lock_before
                or fingerprint(os.stat('worker.lock',dir_fd=state,follow_symlinks=False))!=lock_before): raise Refused('changed')
        check_chain()
        return dict(version=1,scope='central-cdau-transfer-audit-02fee-v1',exit_code=0,audit_complete=True,
                    readonly=True,qualification=False,vm_started=False,records=dict(directory=metadata(target_info),files=records),
                    protected_binding=BINDING,receipt_outcome={k:RECEIPT[k] for k in ('complete','client_durable','original_transfer','error','execution')},
                    external_trusted_receipt_binding=EXTERNAL,external_link='exact-run-candidate-fixture-match',
                    guards=dict(root=True,quiescent=True,ordinary_lock=True,stable_identity_bytes_metadata=True),
                    state_mutated=False,ack_sent=False,journal_written=False,archive_created=False)
    finally:
        for fd in reversed(descriptors):os.close(fd)


def main():
    try:
        if len(sys.argv)!=1: raise Refused('arguments')
        value=audit()
        if len(json.dumps(value,separators=(',',':')).encode())>4096: raise Refused('size')
    except Refused as error:
        value=dict(version=1,scope='central-cdau-transfer-audit-02fee-v1',exit_code=2,audit_complete=False,
                   readonly=True,state_mutated=False,error='audit-refused',reason=error.reason)
    except Exception:
        value=dict(version=1,scope='central-cdau-transfer-audit-02fee-v1',exit_code=2,audit_complete=False,
                   readonly=True,state_mutated=False,error='audit-refused',reason='io')
    print(json.dumps(value,separators=(',',':')),flush=True)
    return value['exit_code']


if __name__=='__main__':raise SystemExit(main())
