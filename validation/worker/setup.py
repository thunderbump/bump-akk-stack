"""Finite Ubuntu worker setup. Never imports or runs the worker as root."""
import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import tempfile

import staging

CONFIG = '/etc/eqemu-validator/config.json'
SOCKET = '/run/eqemu-validator.sock'
TEMPLATES = Path(__file__).with_name('templates')
TOOLS = ('/usr/sbin/useradd', '/usr/bin/systemctl', '/usr/bin/systemd-analyze', '/usr/sbin/apparmor_parser',
         '/usr/bin/python3', '/usr/bin/qemu-system-x86_64', '/usr/bin/qemu-img',
         '/usr/bin/genisoimage')


class Host:
    """System calls kept at one seam so setup can be tested without host changes."""
    def __init__(self, root=Path('/')):
        self.root = Path(root)
        self.admin_uid = 0

    def path(self, name):return self.root/str(name).lstrip('/')
    def info(self, path):return path.lstat()
    def user(self, name):
        try:return pwd.getpwnam(name)
        except KeyError:return None
    def group(self, name):
        try:return grp.getgrgid(name) if isinstance(name,int) else grp.getgrnam(name)
        except KeyError:return None
    def groups(self, name, gid):return os.getgrouplist(name,gid)
    def chown(self, path, uid, gid):os.chown(path, uid, gid, follow_symlinks=False)
    def run(self, args):
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
            text=True, timeout=30, env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
        if result.returncode:
            raise ValueError('Setup command failed: '+args[0]+': '+result.stderr[-2048:])
        return result.stdout


def checked_path(value):
    # These paths also enter systemd/AppArmor syntax. Refuse metacharacters.
    if not re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', value):
        raise ValueError('Use an absolute path without whitespace or policy metacharacters')
    path = Path(value)
    if any(part in ('.','..') for part in value.split('/')):
        raise ValueError('Dot path components are unsupported')
    return path


def safe(host, path, *, uid=None, directory=False):
    info = host.info(path)
    kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not kind or (uid is not None and info.st_uid != uid) or info.st_mode & 0o022:
        raise ValueError('Unexpected type, ownership or writable permissions: '+str(path))
    return info


def present(path):return path.exists() or path.is_symlink()


def ancestors(host, path):
    parents=[]
    for parent in path.parents:
        parents.append(parent)
        if parent==host.root:break
    for parent in reversed(parents):
        safe(host, parent, uid=host.admin_uid, directory=True)


def public_path(host, name, *, uid, directory=False):
    path = host.path(name)
    ancestors(host, path)
    info = safe(host, path, uid=uid, directory=directory)
    required = 0o005 if directory else 0o004
    if info.st_mode & required != required:
        raise ValueError('Worker needs public read/traverse permission: '+str(path))
    return path


def optional_public_path(host, name, *, uid, directory=False):
    """Account-only may defer missing inputs, but cannot pin unsafe existing paths."""
    path=host.path(name)
    for parent in path.parents:
        if present(parent):safe(host,parent,uid=host.admin_uid,directory=True)
        if parent==host.root:break
    if present(path):safe(host,path,uid=uid,directory=directory)


def load_config(host):
    path = host.path(CONFIG)
    ancestors(host, path.parent)
    if present(path.parent):
        info=safe(host,path.parent,uid=host.admin_uid,directory=True)
        if stat.S_IMODE(info.st_mode)!=0o755:raise ValueError('Worker configuration directory must be mode 0755')
    if not present(path):return None
    info=safe(host, path, uid=host.admin_uid)
    if stat.S_IMODE(info.st_mode)!=0o644:raise ValueError('Worker configuration must be mode 0644')
    if path.stat().st_size > 8192:raise ValueError('Oversized worker configuration')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:raise ValueError('Duplicate worker configuration field')
            value[key] = item
        return value
    return json.loads(path.read_text(), object_pairs_hook=unique)


def configuration(args, worker):
    return dict(version=1, user=args.user, worker_uid=worker.pw_uid,
                worker_gid=worker.pw_gid, state_dir=args.state_dir,
                code_dir=args.code_dir, submitter=args.submitter,
                socket=SOCKET, base_image=args.base_image)


def assets(args, submitter_group):
    values = {'USER':args.user,'STATE':args.state_dir,'CODE':args.code_dir,
              'BASE':args.base_image,'SOCKET':SOCKET,'SUBMITTER_GROUP':submitter_group}
    result = {}
    for template, target in (
        ('eqemu-validator.socket','/etc/systemd/system/eqemu-validator.socket'),
        ('eqemu-validator@.service','/etc/systemd/system/eqemu-validator@.service'),
        ('apparmor','/etc/apparmor.d/eqemu-validator')):
        text = (TEMPLATES/template).read_text()
        for name,value in values.items():text = text.replace('@'+name+'@',value)
        if re.search(r'@[A-Z_]+@',text):raise ValueError('Unresolved setup template')
        result[target] = text.encode()
    return result


def verify_policy(host, files):
    """Parse exactly the rendered policy without loading it or changing host units."""
    with tempfile.TemporaryDirectory(prefix='eqemu-worker-policy-') as temporary:
        paths = {}
        for target, data in files.items():
            path = Path(temporary)/Path(target).name
            path.write_bytes(data)
            paths[target] = str(path)
        host.run(['/usr/sbin/apparmor_parser','--skip-kernel-load','--skip-cache',
                  paths['/etc/apparmor.d/eqemu-validator']])
        host.run(['/usr/bin/systemd-analyze','verify','--generators=no','--man=no',
                  paths['/etc/systemd/system/eqemu-validator.socket'],
                  paths['/etc/systemd/system/eqemu-validator@.service']])


def inspect(host, args):
    """Finish all refusal checks before account, file or service mutation."""
    for name in (args.user,args.submitter):
        if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',name):raise ValueError('Unsupported account name')
    if args.user == args.submitter:raise ValueError('Worker and submitter must be separate accounts')
    for name in (args.state_dir,args.code_dir,args.base_image):checked_path(name)
    state,code,base = map(Path,(args.state_dir,args.code_dir,args.base_image))
    forbidden = ('/home','/root','/etc','/usr','/proc','/sys','/dev','/run','/tmp')
    for name in (state,code,base):
        if any(name == Path(prefix) or name.is_relative_to(prefix) for prefix in forbidden):
            raise ValueError('Use dedicated paths outside homes and system/runtime directories')
    if any(a == b or a.is_relative_to(b) or b.is_relative_to(a)
           for a,b in ((state,code),(state,base),(code,base))):
        raise ValueError('State, code and public image paths must be separate')
    release = host.path('/etc/os-release').read_text()
    facts = dict(line.split('=',1) for line in release.splitlines() if '=' in line)
    if facts.get('ID','').strip('"') != 'ubuntu' or facts.get('VERSION_ID','').strip('"') != '26.04':
        raise ValueError('Initial worker setup supports Ubuntu 26.04 only')
    submitter = host.user(args.submitter)
    if not submitter or submitter.pw_uid == 0:raise ValueError('Submitter must be an existing ordinary account')
    submitter_group = host.group(submitter.pw_gid)
    if submitter_group is None:raise ValueError('Submitter primary group is missing')
    if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',submitter_group.gr_name):
        raise ValueError('Unsupported submitter primary group name')
    if args.account_only:
        optional_public_path(host,args.code_dir,uid=submitter.pw_uid,directory=True)
        optional_public_path(host,args.base_image,uid=host.admin_uid)
    worker = host.user(args.user)
    prior = load_config(host)
    if worker:
        if worker.pw_uid == 0 or worker.pw_uid == submitter.pw_uid:
            raise ValueError('Worker identity is not dedicated')
        group = host.group(args.user)
        if (not group or group.gr_gid != worker.pw_gid or group.gr_mem not in ([],[args.user])
                or set(host.groups(args.user,worker.pw_gid))!={worker.pw_gid}
                or worker.pw_dir != args.state_dir
                or worker.pw_shell != '/usr/sbin/nologin' or prior != configuration(args,worker)):
            raise ValueError('Existing worker requires its exact owned setup marker and identity')
    elif prior is not None or host.group(args.user):
        raise ValueError('Conflicting worker configuration or private group')
    state_path = host.path(state)
    ancestors(host,state_path)
    if present(state_path):
        if not worker:raise ValueError('Refusing pre-existing unowned worker state')
        info = safe(host,state_path,uid=worker.pw_uid,directory=True)
        if stat.S_IMODE(info.st_mode) != 0o700 or info.st_gid != worker.pw_gid:
            raise ValueError('Worker state must remain private and owned')
    elif worker:
        raise ValueError('Owned worker state is missing; inspect it before recovery')
    config_dir = host.path('/etc/eqemu-validator')
    if present(config_dir):
        safe(host,config_dir,uid=host.admin_uid,directory=True)
        if prior is None:raise ValueError('Refusing pre-existing unowned worker configuration directory')
    parent = host.path('/usr/sbin/useradd')
    if not worker and (not parent.is_file() or not os.access(parent,os.X_OK)):
        raise ValueError('Missing account setup dependency: useradd')
    if not os.access(host.path('/usr/sbin/nologin'),os.X_OK):raise ValueError('Missing non-login shell: nologin')
    stage = staging.prepare(host,args,submitter)
    files = {} if args.account_only else assets(args,submitter_group.gr_name)
    dependencies = []
    if not args.account_only:
        for tool in TOOLS:
            target=host.path(tool)
            if not target.is_file() or not os.access(target,os.X_OK):dependencies.append(tool)
        if dependencies:raise ValueError('Missing worker packages/tools: '+', '.join(dependencies))
        if stage is None or stage['code_exists']:
            ancestors(host,host.path(code))
        for suffix in (() if stage is not None and not stage['code_exists'] else ('','validation','validation/worker','scripts')):
            info=safe(host,host.path(code/suffix),uid=submitter.pw_uid,directory=True)
            if info.st_mode & 0o005 != 0o005:raise ValueError('Code directories must be worker-readable/traversable')
        for suffix in (() if stage is not None and not stage['code_exists'] else staging.FILES):
            runtime=host.path(code/suffix)
            info=safe(host,runtime,uid=submitter.pw_uid)
            if not info.st_mode & 0o004 or not info.st_size:
                raise ValueError('Required worker asset must be readable and nonempty: '+suffix)
            if suffix.startswith('scripts/') and not info.st_mode & 0o001:
                raise ValueError('Ordinary check command must be executable')
        if stage is None or stage['base_exists']:
            image = public_path(host,args.base_image,uid=host.admin_uid)
            if not 0 < image.stat().st_size <= 2*1024**3:raise ValueError('Public base image must be 1 byte to 2 GiB')
        kvm = host.info(host.path('/dev/kvm'));group=host.group('kvm')
        if not stat.S_ISCHR(kvm.st_mode) or not group or kvm.st_gid != group.gr_gid or kvm.st_mode & 0o060 != 0o060:
            raise ValueError('KVM requires the existing kvm device group with read/write access')
        if host.path('/sys/module/apparmor/parameters/enabled').read_text().strip() != 'Y':
            raise ValueError('AppArmor must be enabled')
        controllers=host.path('/sys/fs/cgroup/cgroup.controllers').read_text().split()
        if not {'memory','pids','cpu'} <= set(controllers):raise ValueError('Required cgroup v2 controllers unavailable')
        version=host.run(['/usr/bin/systemctl','--version']).splitlines()[0]
        match=re.match(r'systemd ([0-9]+)\b',version)
        if not match or int(match[1])<259:raise ValueError('Worker policy requires systemd 259 or newer')
        verify_policy(host,files)
        for target,data in files.items():
            path=host.path(target);ancestors(host,path)
            if present(path):
                safe(host,path,uid=host.admin_uid)
                if prior is None or path.read_bytes()!=data:
                    raise ValueError('Conflicting existing worker policy: '+target)
        if not args.check:
            units=host.run(['/usr/bin/systemctl','list-units','--all','--no-legend','--plain','eqemu-validator@*.service'])
            if units.strip():raise ValueError('Worker connections must be absent before initial policy installation')
            if (any(not present(host.path(target)) for target in files) and present(host.path(SOCKET))):
                raise ValueError('Refusing an existing submission socket before policy installation')
            profiles=host.path('/sys/kernel/security/apparmor/profiles').read_text().splitlines()
            if (any(line.startswith('eqemu-validator (') for line in profiles)
                    and not present(host.path('/etc/apparmor.d/eqemu-validator'))):
                raise ValueError('Refusing to replace an unknown loaded AppArmor profile')
    return worker,submitter,files,stage


def write(host, path, data, mode=0o644):
    """Create only a missing owned file; never replace user data or policy."""
    if present(path):
        if path.read_bytes()!=data:raise ValueError('Setup file changed during apply: '+str(path))
        return
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    host.chown(path,host.admin_uid,0)
    path.chmod(mode)


def setup(host, args):
    worker,submitter,files,stage=inspect(host,args)
    configured = worker is not None and present(host.path(CONFIG))
    if args.check:
        if not configured:raise ValueError('Worker account has not been set up')
        if not args.account_only:
            if any(not present(host.path(target)) for target in files):raise ValueError('Worker service policy is not installed')
            profiles=host.path('/sys/kernel/security/apparmor/profiles').read_text()
            if 'eqemu-validator (enforce)' not in profiles.splitlines():raise ValueError('Worker AppArmor profile is not enforcing')
            if host.run(['/usr/bin/systemctl','is-active','eqemu-validator.socket']).strip()!='active':
                raise ValueError('Worker socket is inactive')
    if args.apply:
        if os.geteuid()!=0 and host.root==Path('/'):raise ValueError('--apply requires root')
        if stage is not None:staging.publish(host,args,submitter,stage)
        if not worker:
            host.run(['/usr/sbin/useradd','--system','--user-group','--no-create-home',
                      '--home-dir',args.state_dir,'--shell','/usr/sbin/nologin',
                      '--comment','EQEmu validation worker',args.user])
            worker=host.user(args.user)
            if not worker:raise ValueError('Created worker identity was not found')
        state=host.path(args.state_dir)
        if not present(state):
            state.mkdir(mode=0o700);host.chown(state,worker.pw_uid,worker.pw_gid)
        config_dir=host.path('/etc/eqemu-validator')
        if not present(config_dir):config_dir.mkdir(mode=0o755);host.chown(config_dir,host.admin_uid,0)
        if not present(host.path(CONFIG)):config_dir.chmod(0o755)
        data=(json.dumps(configuration(args,worker),sort_keys=True,indent=2)+'\n').encode()
        write(host,host.path(CONFIG),data)
        for target,data in files.items():write(host,host.path(target),data)
        if files:
            host.run(['/usr/sbin/apparmor_parser','--replace','/etc/apparmor.d/eqemu-validator'])
            host.run(['/usr/bin/systemctl','daemon-reload'])
            host.run(['/usr/bin/systemctl','enable','--now','eqemu-validator.socket'])
        configured=True
    return dict(version=1,mode='apply' if args.apply else 'check' if args.check else 'dry-run',
                user=args.user,state_dir=args.state_dir,account_configured=configured,
                account_only=args.account_only,runtime_ready=False,
                next_step='Full setup, read-only worker check and explicit smoke remain pending' if args.account_only
                          else 'Ordinary worker check and explicit smoke remain pending; no VM was started',
                dependency_scope='account-only' if args.account_only else 'full-worker',
                staged_inputs=stage is not None,
                public_base_sha256=stage['image_sha256'] if stage else None,
                owned_policy_files=sorted(files),socket=SOCKET)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--user',default='eqemu-validator')
    parser.add_argument('--state-dir',default='/var/lib/eqemu-validator')
    parser.add_argument('--submitter',required=True,help='Existing local account allowed to submit')
    parser.add_argument('--code-dir',default='/srv/eqemu-validator-code',help='Reviewed submitter-owned checkout outside home directories')
    parser.add_argument('--base-image',default='/var/lib/eqemu-validator-inputs/base.qcow2',help='Root-staged public image outside worker state')
    parser.add_argument('--stage',action='store_true',help='Stage this checkout’s finite runtime and the explicitly hashed public image before full setup')
    parser.add_argument('--base-source',help='Existing ordinary public cloud image to copy as data; no download')
    parser.add_argument('--base-sha256',help='Required SHA256 of --base-source when staging')
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--apply',action='store_true',help='Create the account and install policy; requires root')
    mode.add_argument('--check',action='store_true',help='Read-only verification of installed setup')
    mode.add_argument('--dry-run',action='store_true',help='Read-only prerequisite and collision inspection, the default')
    parser.add_argument('--account-only',action='store_true',help='Prepare only the account, private state and ownership marker; runtime remains unavailable')
    args=parser.parse_args(argv)
    try:
        print(json.dumps(setup(Host(),args),sort_keys=True));return 0
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        print(json.dumps(dict(version=1,error=str(error)[-4096:],runtime_ready=False)),file=sys.stderr);return 2


if __name__=='__main__':raise SystemExit(main())
