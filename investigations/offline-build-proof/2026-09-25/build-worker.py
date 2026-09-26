#!/usr/bin/python3
"""Operator-owned offline EQEmu build trial. Fixed source inputs; no production data.

--check performs static policy/XML/input checks without root or VM creation.
No arguments stages the fixed inputs and starts a bounded systemd controller.
Internal modes run only from the root-owned copied script under systemd.
"""
import argparse, ctypes, ctypes.util, hashlib, json, os, pathlib, pwd
import re, shutil, signal, socket, stat, subprocess, sys, time, uuid
import xml.etree.ElementTree as ET
P=pathlib.Path
BASE=P('/var/lib/eqemu-vm-proof')
ROOT=BASE/'build-proof-01'/'build'
DATA=ROOT/'data'
EVIDENCE=ROOT/'evidence'
STATE=ROOT/'state.json'
SCRIPT=ROOT/'controller.py'
UNIT='eqemu-vm-build-01-worker.service'
SLICE='eqemuvmbuild01worker.slice'
SLICEFILE=P('/run/systemd/system')/SLICE
NAME='eqemu-build-01'
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}
INPUTS=P('/home/bump/.local/state/eqemu-vm-proof')
CASE='build'
GIB=1024**3
FILES={
 'base.qcow2':('inputs/ubuntu-noble-20260911/ubuntu-24.04-server-cloudimg-amd64.img',625256960,'612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354'),
 'seed.iso':('build-proof-inputs/seed.iso',387072,'087f7ab01061d65f4bc50f8ca03d3b31f70c56b0e05699462026438d3903009d'),
 'fixture.iso':('build-inputs-20260925/build-inputs.iso',467603456,'8c296a41d6a23d33985a4d820cab1727738155d1d2ad10e2583775597455cb9b'),
}


def run(args, timeout=30, check=True, data=None):
    result=subprocess.run(args,input=data,text=True,capture_output=True,timeout=timeout,env=ENV,cwd='/')
    if check and result.returncode:
        raise RuntimeError(str(args[:3])+': '+str(result.returncode)+' '+result.stderr[-6000:]+result.stdout[-2000:])
    return result


def virsh(*args, **kw):return run(['/usr/bin/virsh','-c','qemu:///system',*args],**kw)
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()


def write_json(path,obj):
    temp=path.with_suffix('.new');temp.write_text(json.dumps(obj,indent=2)+'\n');temp.chmod(0o644)
    os.replace(temp,path)


def safe_dir(path):
    s=path.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('Unsafe directory '+str(path))


def state():
    safe_dir(BASE);safe_dir(ROOT)
    s=json.loads(STATE.read_text())
    if str(uuid.UUID(s['uuid']))!=s['uuid'] or s['name']!=NAME or s['profile']!='libvirt-'+s['uuid']:
        raise RuntimeError('Invalid ownership state')
    return s


def policy(s):
    return f'''#include <tunables/global>
profile {s['profile']} flags=(attach_disconnected) {{
  #include <abstractions/libvirt-qemu>
  {DATA}/root.raw rwk,
  {DATA}/seed.iso rk,
  {DATA}/fixture.iso rk,
  {DATA}/serial.sock rw,
  /var/lib/libvirt/qemu/domain-[0-9]*-{NAME}/** rwk,
  /{{var/,}}run/libvirt/qemu/domain-[0-9]*-{NAME}/** rwk,
  unix (create, bind, listen, accept, send, receive, connect) type=stream,
  signal (receive) peer=unconfined,
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
  audit deny {ROOT}/controller.py rwkl,
  audit deny {ROOT}/state.json rwkl,
  audit deny {ROOT}/evidence/** rwkl,
  audit deny /dev/net/tun rw,
  audit deny /dev/vhost-* rw,
  audit deny /dev/vfio/** rw,
  audit deny /dev/snd/** rw,
  audit deny /var/lib/libvirt/qemu/nvram/** rwkl,
}}
'''


def domain(s):
    return f'''<domain type="kvm">
  <name>{NAME}</name><uuid>{s['uuid']}</uuid>
  <memory unit="MiB">4096</memory><currentMemory unit="MiB">4096</currentMemory>
  <vcpu placement="static">2</vcpu>
  <resource><partition>/eqemuvmbuild01worker</partition></resource>
  <cputune><global_period>100000</global_period><global_quota>200000</global_quota></cputune>
  <memtune><hard_limit unit="MiB">6144</hard_limit><swap_hard_limit unit="MiB">6144</swap_hard_limit></memtune>
  <os><type arch="x86_64" machine="pc-q35-8.2">hvm</type><boot dev="hd"/></os>
  <features><acpi/><apic/></features>
  <cpu mode="host-passthrough" check="none"><feature policy="disable" name="svm"/><feature policy="disable" name="vmx"/></cpu>
  <on_poweroff>destroy</on_poweroff><on_reboot>destroy</on_reboot><on_crash>destroy</on_crash>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <disk type="file" device="disk"><driver name="qemu" type="raw" cache="none"/><source file="{DATA}/root.raw"/><target dev="vda" bus="virtio"/></disk>
    <disk type="file" device="cdrom"><driver name="qemu" type="raw"/><source file="{DATA}/seed.iso"/><target dev="sda" bus="sata"/><readonly/></disk>
    <disk type="file" device="cdrom"><driver name="qemu" type="raw"/><source file="{DATA}/fixture.iso"/><target dev="sdb" bus="sata"/><readonly/></disk>
    <serial type="unix"><source mode="bind" path="{DATA}/serial.sock"/><target type="isa-serial" port="0"><model name="isa-serial"/></target></serial>
    <controller type="usb" model="none"/><video><model type="none"/></video><memballoon model="none"/>
  </devices>
  <seclabel type="static" model="apparmor" relabel="no"><label>{s['profile']}</label></seclabel>
</domain>'''


def schema_check(xml):
    # Use the installed XML library; no extra host package or external entity fetch.
    lib=ctypes.CDLL(ctypes.util.find_library('xml2'))
    signatures={
      'xmlRelaxNGNewParserCtxt':([ctypes.c_char_p],ctypes.c_void_p),
      'xmlRelaxNGParse':([ctypes.c_void_p],ctypes.c_void_p),
      'xmlRelaxNGNewValidCtxt':([ctypes.c_void_p],ctypes.c_void_p),
      'xmlReadMemory':([ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_int],ctypes.c_void_p),
      'xmlRelaxNGValidateDoc':([ctypes.c_void_p,ctypes.c_void_p],ctypes.c_int),
      'xmlFreeDoc':([ctypes.c_void_p],None),'xmlRelaxNGFreeValidCtxt':([ctypes.c_void_p],None),
      'xmlRelaxNGFree':([ctypes.c_void_p],None),'xmlRelaxNGFreeParserCtxt':([ctypes.c_void_p],None),
    }
    for name,(args,result) in signatures.items():getattr(lib,name).argtypes=args;getattr(lib,name).restype=result
    parser=lib.xmlRelaxNGNewParserCtxt(b'/usr/share/libvirt/schemas/domain.rng');schema=lib.xmlRelaxNGParse(parser)
    ctx=lib.xmlRelaxNGNewValidCtxt(schema);data=xml.encode();doc=lib.xmlReadMemory(data,len(data),b'trial.xml',None,2048)
    if not all([parser,schema,ctx,doc]):raise RuntimeError('Could not initialize schema validation')
    result=lib.xmlRelaxNGValidateDoc(ctx,doc)
    lib.xmlFreeDoc(doc);lib.xmlRelaxNGFreeValidCtxt(ctx);lib.xmlRelaxNGFree(schema);lib.xmlRelaxNGFreeParserCtxt(parser)
    if result:raise RuntimeError('Domain schema rejected XML')


def admission():
    fs=os.statvfs('/var/lib');free=fs.f_bavail*fs.f_frsize
    memory={k:int(v.split()[0])*1024 for k,v in (line.split(':',1) for line in P('/proc/meminfo').read_text().splitlines())}
    if free<180*GIB or fs.f_favail<1000000 or memory['MemAvailable']<15*GIB:raise RuntimeError('Admission requires 180 GiB disk, 1M inodes, 15 GiB available RAM')
    return {'free_bytes':free,'free_inodes':fs.f_favail,'mem_available':memory['MemAvailable']}


def setup():
    if not re.fullmatch(r'[a-z0-9-]{1,20}',NAME):raise RuntimeError('Domain name must use at most 20 ASCII lowercase letters, digits or hyphens')
    if os.geteuid()!=0:raise RuntimeError('Run with sudo, or use --check for static validation')
    if ROOT.exists() or ROOT.is_symlink():raise RuntimeError('Previous trial state exists; inspect/reconcile before rerun')
    if SLICEFILE.exists() or SLICEFILE.is_symlink():raise RuntimeError('Trial slice file already exists')
    if run(['/usr/bin/systemctl','show',UNIT,'-p','LoadState','--value'],check=False).stdout.strip()!='not-found':
        raise RuntimeError('Controller unit already exists')
    # systemd synthesizes inactive slices even without a file. Refuse actual usage/configuration.
    observed=run(['/usr/bin/systemctl','show',SLICE,'-p','ActiveState','-p','FragmentPath','-p','DropInPaths','-p','Transient']).stdout
    properties=dict(line.split('=',1) for line in observed.splitlines() if '=' in line)
    if properties.get('ActiveState')!='inactive' or properties.get('FragmentPath') or properties.get('DropInPaths') or properties.get('Transient')!='no':
        raise RuntimeError('Worker slice already configured or in use')
    if any(P('/var/log/libvirt/qemu').glob(NAME+'.log*')):
        raise RuntimeError('Pre-existing log with trial name; preserve and investigate')
    admission_result=admission()
    if virsh('domuuid',NAME,check=False).returncode==0:raise RuntimeError('Domain name already exists')
    if not BASE.exists():BASE.mkdir(mode=0o755);BASE.chmod(0o755)
    safe_dir(BASE)
    # Atomic singleton ownership. Refuse retained state instead of guessing it disposable.
    ROOT.mkdir(mode=0o755);ROOT.chmod(0o755)
    DATA.mkdir(mode=0o755);DATA.chmod(0o755);EVIDENCE.mkdir(mode=0o755);EVIDENCE.chmod(0o755)
    ident=str(uuid.uuid4());s={'uuid':ident,'name':NAME,'profile':'libvirt-'+ident,'admission':admission_result,'created_at':time.time()}
    write_json(STATE,s)
    SCRIPT.write_bytes(P(__file__).read_bytes());SCRIPT.chmod(0o600)
    s['controller_sha256']=digest(SCRIPT);write_json(STATE,s)
    # Copies and all expensive preparation run inside the bounded controller.
    args=['/usr/bin/systemd-run','--quiet','--unit='+UNIT,'--service-type=exec',
          '-p','RuntimeMaxSec=17400','-p','TimeoutStopSec=120','-p','KillMode=control-group',
          '-p','Slice=eqemuvmbuild01ctl.slice','-p','MemoryMax=960M','-p','MemorySwapMax=0','-p','TasksMax=64',
          '-p','StandardOutput=null','-p','StandardError=journal','-p','LogRateLimitIntervalSec=30s','-p','LogRateLimitBurst=20',
          '-p','ExecStopPost=/usr/bin/python3 -I '+str(SCRIPT)+' --cleanup',
          '/usr/bin/python3','-I',str(SCRIPT),'--worker']
    try:run(args)
    except Exception:
        cleanup();raise
    print(json.dumps({'started':True,'unit':UNIT,'state':str(STATE),'report':str(EVIDENCE/'report.json'),'status_command':'sudo systemctl status '+UNIT,'cancel_command':'sudo systemctl stop '+UNIT}))


def prepare_disk(base, raw):
    # Reserve extents without dirtying 32 GiB of page cache inside a 1 GiB cgroup.
    run(['/usr/bin/qemu-img','convert','-f','qcow2','-O','raw','-t','none',
         '-o','preallocation=falloc',str(base),str(raw)],timeout=240)
    run(['/usr/bin/qemu-img','resize','-f','raw','--preallocation=falloc',str(raw),'32G'],timeout=240)
    if raw.stat().st_size!=32*GIB or raw.stat().st_blocks*512<32*GIB:
        raise RuntimeError('Raw disk is not fully allocated')


def io_device_number(device, sys_root=P('/sys/dev/block')):
    # io.max uses the whole-disk identity for a filesystem on a partition.
    number=f'{os.major(device)}:{os.minor(device)}'
    node=(sys_root/number).resolve(strict=True)
    if (node/'dev').read_text().strip()!=number:raise RuntimeError('Backing device identity mismatch')
    if (node/'partition').exists():node=node.parent
    canonical=(node/'dev').read_text().strip()
    if not re.fullmatch(r'[0-9]+:[0-9]+',canonical):raise RuntimeError('Invalid I/O device identity')
    if (node/'slaves').exists() and any((node/'slaves').iterdir()):
        raise RuntimeError('Layered block devices need a separate I/O policy investigation')
    return canonical


def verify_io_limits(text, device):
    matches=[]
    for line in text.splitlines():
        fields=line.split()
        if not fields or fields[0]!=device:continue
        values={}
        for token in fields[1:]:
            key,separator,value=token.partition('=')
            if not separator or key in values:raise RuntimeError('Malformed or duplicate I/O limit field')
            values[key]=value
        matches.append(values)
    if len(matches)!=1 or matches[0].get('rbps')!='104857600' or matches[0].get('wbps')!='52428800':
        raise RuntimeError('I/O limits not applied to the backing disk')


def inspect_limits(cgroup):
    return {key:(cgroup/key).read_text().strip() for key in ['memory.max','memory.swap.max','pids.max','cpu.max','io.max']}


def owned_pids(s):
    found=[]
    for p in P('/proc').iterdir():
        if not p.name.isdigit():continue
        try:
            args=(p/'cmdline').read_bytes().split(b'\0')
            if b'-uuid' in args and args[args.index(b'-uuid')+1].decode()==s['uuid']:
                if 'qemu-system-' not in os.readlink(p/'exe'):raise RuntimeError('Unexpected executable with owned UUID')
                found.append(int(p.name))
        except (FileNotFoundError,ProcessLookupError,PermissionError):continue
    return found


def worker():
    s=state();report={'schema':1,'ok':False,'workload_ok':False,'scope':'offline EQEmu build experiment; guest evidence remains untrusted','uuid':s['uuid'],'checks':{},'inputs':{},'started_at':time.time()}
    write_json(EVIDENCE/'report.json',report)
    def interrupted(*_):raise RuntimeError('Controller interrupted')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    try:
        # Do not let global logging defaults silently produce an unbounded QEMU log.
        qconf=P('/etc/libvirt/qemu.conf').read_text();lconf=P('/etc/libvirt/virtlogd.conf').read_text()
        def setting(text,key,default):
            m=re.search(r'^\s*'+key+r'\s*=\s*([^#\n]+)',text,re.M);return m.group(1).strip().strip('"') if m else default
        if setting(qconf,'stdio_handler','logd')!='logd':raise RuntimeError('QEMU must use bounded virtlogd logging')
        size=int(setting(lconf,'max_size','2097152'));backups=int(setting(lconf,'max_backups','3'))
        if not 0<size<=8*1024**2 or not 0<=backups<=4:raise RuntimeError('virtlogd rotation outside trial budget')
        report['virtlogd']={'max_size':size,'max_backups':backups}
        account=pwd.getpwnam('libvirt-qemu')
        if account.pw_uid==0:raise RuntimeError('QEMU UID must be non-root')
        for target,(rel,length,sha) in FILES.items():
            source=INPUTS/rel;dest=DATA/target
            if source.is_symlink() or not source.is_file() or source.stat().st_size!=length:raise RuntimeError('Invalid fixed input '+target)
            # Fixed size loop also prevents an expanding source from filling storage.
            with source.open('rb') as src,dest.open('xb') as dst:
                remain=length
                while remain:
                    chunk=src.read(min(remain,1024**2))
                    if not chunk:raise RuntimeError('Short input')
                    dst.write(chunk);remain-=len(chunk)
                if src.read(1):raise RuntimeError('Input grew')
            if digest(dest)!=sha:raise RuntimeError('Input digest mismatch '+target)
            report['inputs'][target]=sha;dest.chmod(0o444)
        raw=DATA/'root.raw'
        report['inputs_verified_at']=time.time();write_json(EVIDENCE/'report.json',report)
        prepare_disk(DATA/'base.qcow2',raw)
        raw.chmod(0o600);os.chown(raw,account.pw_uid,account.pw_gid);(DATA/'base.qcow2').unlink()
        report['allocated_disk_bytes']=raw.stat().st_blocks*512
        device=os.stat(DATA).st_dev;dev=io_device_number(device)
        report['io_device']={'filesystem':f'{os.major(device)}:{os.minor(device)}','backing_disk':dev}
        if not P('/dev/block',dev).exists():raise RuntimeError('No block device for I/O policy')
        content=f'[Unit]\nDescription=Owned first EQEmu synthetic VM trial\n[Slice]\nMemoryMax=6G\nMemorySwapMax=0\nCPUQuota=200%\nTasksMax=256\nIOReadBandwidthMax=/dev/block/{dev} 104857600\nIOWriteBandwidthMax=/dev/block/{dev} 52428800\n'
        with SLICEFILE.open('x') as f:f.write(content)
        SLICEFILE.chmod(0o644);s['slice_file_sha256']=digest(SLICEFILE);write_json(STATE,s)
        run(['/usr/bin/systemctl','daemon-reload']);run(['/usr/bin/systemctl','start',SLICE])
        group=run(['/usr/bin/systemctl','show',SLICE,'-p','ControlGroup','--value']).stdout.strip()
        if group!='/eqemuvmbuild01worker.slice':raise RuntimeError('Unexpected worker cgroup')
        cg=P('/sys/fs/cgroup')/group.lstrip('/');limits=inspect_limits(cg);report['limits']=limits
        quota,period=limits['cpu.max'].split()
        if limits['memory.max']!=str(6*GIB) or limits['memory.swap.max']!='0' or limits['pids.max']!='256' or quota=='max' or int(quota)>2*int(period):raise RuntimeError('Effective limits differ from requested policy')
        verify_io_limits(limits['io.max'],dev)
        p=policy(s);(EVIDENCE/'apparmor.txt').write_text(p);(EVIDENCE/'domain.xml').write_text(domain(s))
        schema_check(domain(s));run(['/usr/sbin/apparmor_parser','-a','-K','-j','1'],data=p)
        if s['profile']+' (enforce)' not in P('/sys/kernel/security/apparmor/profiles').read_text():raise RuntimeError('Profile not enforcing')
        virsh('create',str(EVIDENCE/'domain.xml'),'--paused','--validate',timeout=60)
        xml=virsh('dumpxml',s['uuid']).stdout;(EVIDENCE/'effective-domain.xml').write_text(xml);tree=ET.fromstring(xml)
        if tree.attrib.get('type')!='kvm' or tree.findall('./devices/interface') or any(tree.findall('./devices/'+tag) for tag in ['filesystem','hostdev','graphics','channel','redirdev','vsock']):raise RuntimeError('Unexpected guest device')
        if virsh('domstate',s['uuid']).stdout.strip()!='paused':raise RuntimeError('Guest was not paused')
        pids=owned_pids(s)
        if len(pids)!=1:raise RuntimeError('Expected exactly one owned QEMU process')
        pid=pids[0];proc=P('/proc')/str(pid);status=(proc/'status').read_text()
        facts={k:v.strip() for k,v in (line.split(':',1) for line in status.splitlines() if ':' in line)}
        label=(proc/'attr/current').read_text().strip();cgroup=(proc/'cgroup').read_text().strip();cmd=(proc/'cmdline').read_bytes().split(b'\0')
        report['qemu']={'pid':pid,'uid':facts['Uid'],'gid':facts['Gid'],'groups':facts['Groups'],'cap_eff':facts['CapEff'],'seccomp':facts['Seccomp'],'apparmor':label,'cgroup':cgroup,'cmdline':[x.decode() for x in cmd if x]}
        if any(int(x)!=account.pw_uid for x in facts['Uid'].split()) or int(facts['CapEff'],16)!=0 or facts['Seccomp']!='2':raise RuntimeError('QEMU process identity/capability/seccomp mismatch')
        if label!=s['profile']+' (enforce)' or '/eqemuvmbuild01worker.slice/' not in cgroup:raise RuntimeError('QEMU not in its profile and resource slice')
        if os.readlink(proc/'ns/mnt')==os.readlink('/proc/self/ns/mnt'):raise RuntimeError('QEMU has no private mount namespace')
        fds=[]
        for fd in (proc/'fd').iterdir():
            try:target=os.readlink(fd)
            except FileNotFoundError:continue
            fds.append(target)
            if target.startswith(('/home/','/root/','/mnt/','/media/','/var/lib/docker/')):raise RuntimeError('Protected descriptor attached')
        report['qemu']['fds']=fds;report['checks']['host_pre_resume']=True
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);sock.settimeout(1);sock.connect(str(DATA/'serial.sock'))
        write_json(EVIDENCE/'report.json',report)
        virsh('resume',s['uuid']);report['resumed_at']=time.time();write_json(EVIDENCE/'report.json',report)
        collect_build(sock,s,report,cg)
    except Exception as exc:report['error']=str(exc)
    finally:
        report['finished_at']=time.time()
        cg=P('/sys/fs/cgroup/eqemuvmbuild01worker.slice')
        if cg.exists():
            report['resource_observations']={name:(cg/name).read_text().strip() for name in ['memory.peak','memory.events','cpu.stat','pids.events'] if (cg/name).exists()}
        write_json(EVIDENCE/'report.json',report)
    return 0 if report['workload_ok'] else 1


def wait_domain_absent(ident, seconds=20):
    # QEMU exit and removal of its transient libvirt object are asynchronous.
    deadline=time.monotonic()+seconds
    while True:
        domains=virsh('list','--all','--uuid',timeout=5).stdout.split()
        if ident not in domains:return
        if time.monotonic()>=deadline:raise RuntimeError('Owned domain remains registered after bounded wait')
        time.sleep(0.25)


def cleanup(preserve_failed_outcome=False):
    s=state();receipt={'complete':False,'uuid':s['uuid'],'started_at':time.time()}
    try:
        try:found=virsh('domname',s['uuid'],check=False)
        except Exception as exc:
            receipt['domain_lookup_error']=str(exc);found=None
        if found is not None and found.returncode==0:
            if found.stdout.strip()!=s['name']:raise RuntimeError('Domain ownership mismatch')
            try:
                stopped=virsh('destroy',s['uuid'],check=False,timeout=30)
                receipt['virsh_destroy_exit']=stopped.returncode
            except Exception as exc:receipt['virsh_destroy_error']=str(exc)
        # Libvirt failure must not leave the owned process outside the deadline.
        # pidfds prevent PID reuse from turning this into a signal to another process.
        for pid in owned_pids(s):
            fd=os.pidfd_open(pid)
            try:
                if pid not in owned_pids(s):continue
                signal.pidfd_send_signal(fd,signal.SIGKILL)
            except ProcessLookupError:pass
            finally:os.close(fd)
        for _ in range(15):
            if not owned_pids(s):break
            time.sleep(1)
        if owned_pids(s):raise RuntimeError('Owned QEMU still alive; retain inputs and profile')
        # A management error must not be interpreted as an absent domain.
        wait_domain_absent(s['uuid'])
        receipt['domain_absent']=True
        profiles=P('/sys/kernel/security/apparmor/profiles')
        if s['profile'] in profiles.read_text():run(['/usr/sbin/apparmor_parser','-R','-K','-j','1'],data=policy(s))
        if s['profile'] in profiles.read_text():raise RuntimeError('Profile remains loaded')
        receipt['profile_absent']=True
        if SLICEFILE.exists():
            if not s.get('slice_file_sha256') or digest(SLICEFILE)!=s['slice_file_sha256']:raise RuntimeError('Slice ownership mismatch')
            run(['/usr/bin/systemctl','stop',SLICE]);SLICEFILE.unlink();run(['/usr/bin/systemctl','daemon-reload'])
        receipt['slice_file_absent']=not SLICEFILE.exists()
        if P('/sys/fs/cgroup',SLICE).exists():raise RuntimeError('Worker cgroup remains')
        receipt['cgroup_absent']=True
        receipt['readonly_inputs_unchanged']=all((DATA/name).is_file() and digest(DATA/name)==FILES[name][2] for name in ['seed.iso','fixture.iso'])
        # Save only capped logs with exact run name; do not mount guest disks.
        logroot=P('/var/log/libvirt/qemu')
        for suffix in ['', '.0','.1','.2','.3','.4']:
            p=logroot/(NAME+'.log'+suffix)
            if p.exists():
                if p.is_symlink() or not p.is_file() or p.stat().st_size>8*1024**2:raise RuntimeError('Unexpected QEMU log size/type')
                dest=EVIDENCE/('qemu.log'+suffix);shutil.copyfile(p,dest);dest.chmod(0o644);p.unlink()
        for parent in [P('/var/lib/libvirt/qemu'),P('/run/libvirt/qemu')]:
            if any(parent.glob('domain-[0-9]*-'+NAME)):
                raise RuntimeError('Libvirt runtime directory remains; retain for reconciliation')
        if (EVIDENCE/'serial.log').exists():(EVIDENCE/'serial.log').chmod(0o644)
        if DATA.exists():safe_dir(DATA);shutil.rmtree(DATA)
        receipt['data_absent']=not DATA.exists();receipt['complete']=True
    except Exception as exc:receipt['error']=str(exc)
    receipt['finished_at']=time.time()
    write_json(EVIDENCE/'cleanup.json',receipt)
    reportfile=EVIDENCE/'report.json'
    if reportfile.exists():
        report=json.loads(reportfile.read_text());report['cleanup']=receipt
        if preserve_failed_outcome:
            report['reconciled']=receipt['complete'];report['ok']=False
        else:
            report['service_result']=os.environ.get('SERVICE_RESULT','unknown')
            report['ok']=report.get('workload_ok',False) and receipt['complete'] and report['service_result']=='success'
        write_json(reportfile,report)
    return 0 if receipt['complete'] else 1


class EvidenceError(RuntimeError):pass

def strict_json(data):
    # Bound nesting before invoking the JSON decoder, including on builds with a larger recursion limit.
    depth=0;quoted=False;escaped=False
    for byte in data:
        if quoted:
            if escaped:escaped=False
            elif byte==92:escaped=True
            elif byte==34:quoted=False
        elif byte==34:quoted=True
        elif byte in [91,123]:
            depth+=1
            if depth>32:raise EvidenceError('JSON nesting limit exceeded')
        elif byte in [93,125]:depth-=1
    def pairs(items):
        obj={}
        for key,value in items:
            if key in obj:raise EvidenceError('Duplicate JSON key')
            obj[key]=value
        return obj
    def constant(_):raise EvidenceError('Non-finite JSON number')
    try:return json.loads(data,object_pairs_hook=pairs,parse_constant=constant)
    except EvidenceError:raise
    except (ValueError,UnicodeError,RecursionError):raise EvidenceError('Malformed result JSON')


# Host accepts only bounded protocol data; guest reports cannot select host paths/actions.
MANIFEST_SHA='d1ea62a29af65f1e412377a5319086f65e590f03f83d3cdedf90e44f86a760d5'
class BuildSerial:
    def __init__(self):self.tail=b'';self.total=0
    def feed(self,data):
        if self.total+len(data)>1024**2:raise RuntimeError('Serial output limit exceeded')
        self.total+=len(data);self.tail+=data;values=[]
        while b'\n' in self.tail:
            line,self.tail=self.tail.split(b'\n',1);line=line.rstrip(b'\r')
            if len(line)>65536:raise RuntimeError('Oversized serial line')
            if line.startswith(b'EQEMU_BUILD '):
                raw=line[len(b'EQEMU_BUILD '):]
                if len(raw)>16384:raise RuntimeError('Oversized result frame')
                obj=strict_json(raw)
                if not isinstance(obj,dict):raise RuntimeError('Invalid protocol object')
                values.append(obj)
        if len(self.tail)>65536:raise RuntimeError('Oversized serial line')
        return values

class BuildProtocol:
    def __init__(self,nonce):self.nonce=nonce;self.ready=False;self.preflight=False;self.result=None;self.frames=0
    def accept(self,v):
        self.frames+=1
        if self.frames>1500:raise RuntimeError('Frame count limit')
        if self.result is not None:raise RuntimeError('Frame after final result')
        kind=v.get('kind')
        if kind=='ready':
            if self.ready or set(v)!={'kind','nonce','manifest_sha256'} or v['nonce'] is not None or v['manifest_sha256']!=MANIFEST_SHA:raise RuntimeError('Invalid/duplicate ready')
            self.ready=True;return kind
        if not self.ready or v.get('nonce')!=self.nonce:raise RuntimeError('Wrong run identity or frame ordering')
        if kind=='stage':
            if set(v)!={'kind','nonce','name','state'} or not isinstance(v['name'],str) or not re.fullmatch('[a-z0-9-]{1,80}',v['name']) or v['state'] not in ['started','running','passed']:raise RuntimeError('Invalid stage')
        elif kind=='preflight':
            if self.preflight or set(v)!={'kind','nonce','before_status','after_status','solver_sha256','ports','negative_control','tools'} or v['negative_control'] is not True or type(v['ports']) is not int or v['ports']!=51:raise RuntimeError('Invalid preflight')
            if any(not isinstance(v[k],str) or not re.fullmatch('[a-f0-9]{64}',v[k]) for k in ['before_status','after_status','solver_sha256']):raise RuntimeError('Invalid preflight hash')
            if not isinstance(v['tools'],dict) or len(v['tools'])>10 or any(not isinstance(x,str) or len(x)>600 for x in v['tools'].values()):raise RuntimeError('Invalid tool facts')
            self.preflight=True
        elif kind=='result':
            if v.get('ok') is not True:
                if set(v)!={'kind','nonce','ok','error'} or v['ok'] is not False or not isinstance(v['error'],str) or len(v['error'])>4500:raise RuntimeError('Invalid failure result')
            else:
                keys={'kind','nonce','ok','checks','binaries','cache_sha256','guest_disk_used_bytes','effective_cmake'}
                checks={'inputs','packages','solver','negative_control','perl','build','tests'}
                if not self.preflight or set(v)!=keys or not isinstance(v['checks'],dict) or set(v['checks'])!=checks or any(x is not True for x in v['checks'].values()):raise RuntimeError('Invalid success result')
                if not isinstance(v['binaries'],dict) or set(v['binaries'])!={'world','zone','shared_memory','loginserver','ucs','queryserv','eqlaunch','tests'}:raise RuntimeError('Missing binary identity')
                if any(not isinstance(x,str) or not re.fullmatch('[a-f0-9]{64}',x) for x in [v['cache_sha256'],*v['binaries'].values()]):raise RuntimeError('Invalid binary hash')
                if type(v['guest_disk_used_bytes']) is not int or not 0<v['guest_disk_used_bytes']<=32*GIB:raise RuntimeError('Invalid disk observation')
                if not isinstance(v['effective_cmake'],dict) or len(v['effective_cmake'])>20 or any(not isinstance(x,str) or len(x)>500 for x in v['effective_cmake'].values()):raise RuntimeError('Invalid effective configuration')
            self.result=v
        else:raise RuntimeError('Unknown frame kind')
        return kind

def collect_build(sock,s,report,cg):
    start=time.monotonic();deadline=start+600;nonce=uuid.uuid4().hex
    parser=BuildSerial();protocol=BuildProtocol(nonce);report['stages']={}
    with sock,(EVIDENCE/'serial.log').open('xb') as log:
        while time.monotonic()<deadline:
            if shutil.disk_usage('/var/lib').free<100*GIB:raise RuntimeError('Disk reserve threatened')
            available=int(next(x.split()[1] for x in P('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))*1024
            if available<8*GIB:raise RuntimeError('Host memory reserve threatened')
            try:data=sock.recv(4096)
            except socket.timeout:continue
            if not data:break
            if parser.total+len(data)>1024**2:raise RuntimeError('Serial output limit exceeded')
            log.write(data);log.flush()
            for v in parser.feed(data):
                kind=protocol.accept(v)
                if kind=='ready':
                    report['ready_at']=time.time();deadline=time.monotonic()+1800
                    sock.sendall((json.dumps({'op':'build','nonce':nonce})+'\n').encode())
                elif kind=='stage':
                    if v['name'] not in report['stages'] and len(report['stages'])>=50:raise RuntimeError('Too many stages')
                    report['stages'][v['name']]={'state':v['state'],'at':time.time()}
                elif kind=='preflight':report['preflight_untrusted']=v;deadline=time.monotonic()+14400
                elif kind=='result':report['guest_report_untrusted']=v;deadline=min(deadline,time.monotonic()+60)
                report['serial_bytes']=parser.total;write_json(EVIDENCE/'report.json',report)
        else:raise RuntimeError('Guest execution deadline reached')
    if protocol.result is None:raise RuntimeError('Missing guest result')
    end=time.monotonic()+30
    while owned_pids(s) and time.monotonic()<end:time.sleep(.25)
    if owned_pids(s):raise RuntimeError('Guest did not shut down')
    wait_domain_absent(s['uuid'])
    if protocol.result['ok'] is not True:raise RuntimeError('Guest build failed: '+protocol.result['error'])
    report['workload_ok']=True

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');parser.add_argument('--worker',action='store_true');parser.add_argument('--cleanup',action='store_true');args=parser.parse_args()
    if sum([args.check,args.worker,args.cleanup])>1:parser.error('Choose only one mode')
    if args.check:
        s={'uuid':'00000000-0000-4000-8000-000000000031','profile':'libvirt-00000000-0000-4000-8000-000000000031'}
        schema_check(domain(s));run(['/usr/sbin/apparmor_parser','-Q','-K','-j','1'],data=policy(s))
        for _,(rel,length,sha) in FILES.items():
            p=INPUTS/rel
            if p.stat().st_size!=length or digest(p)!=sha:raise RuntimeError('Input identity mismatch '+rel)
        print(json.dumps({'schema':True,'policy_syntax':True,'input_hashes':True,'vm_started':False}));return 0
    if os.geteuid()!=0:raise RuntimeError('sudo required for trial execution')
    os.umask(0o077)
    if args.worker or args.cleanup:
        if P(__file__).resolve()!=SCRIPT:raise RuntimeError('Internal modes require the root-owned copied controller')
        if args.worker:return worker()
        return cleanup()
    setup()
    return 0

if __name__=='__main__':
    try:sys.exit(main())
    except Exception as exc:print(json.dumps({'error':str(exc)}),file=sys.stderr);sys.exit(1)
