#!/usr/bin/python3
"""Synthetic guest-only offline test. Reports are untrusted host input."""
import hashlib, io, json, os, pathlib, socket, subprocess, tarfile, time
P = pathlib.Path
report = {'schema': 1, 'kind': 'offline-container-trial', 'ok': False, 'checks': {}}

def run(args, timeout=120, check=True):
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                       env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','DEBIAN_FRONTEND':'noninteractive'})
    if check and r.returncode:
        raise RuntimeError(str(args[:3])+': '+str(r.returncode)+' '+r.stderr[-2000:]+r.stdout[-2000:])
    return r

try:
    report['checks']['guest_root'] = os.getuid() == 0
    report['interfaces_before_docker'] = sorted(p.name for p in P('/sys/class/net').iterdir())
    report['checks']['no_virtual_nic'] = report['interfaces_before_docker'] == ['lo']
    flags = P('/proc/cpuinfo').read_text().split()
    report['checks']['no_nested_virtualization'] = 'svm' not in flags and 'vmx' not in flags
    report['checks']['approved_input'] = P('/opt/eqemu-proof/input.txt').read_text() == 'eqemu-synthetic-input-v1\n'
    report['checks']['no_host_mounts'] = not any(x in P('/proc/mounts').read_text() for x in [' virtiofs ', ' 9p ', ' nfs ', ' nfs4 '])
    report['checks']['no_host_control_socket'] = not P('/run/libvirt/libvirt-sock').exists()
    # TEST-NET destination: with no NIC, require no route before any container starts.
    route = run(['ip','route','get','192.0.2.1'], check=False)
    report['checks']['no_external_route'] = route.returncode != 0
    if not all(report['checks'].values()): raise RuntimeError('Guest boundary preflight failed')
    P('/opt/fixture').mkdir(exist_ok=True)
    run(['mount','-o','ro,nosuid,nodev,noexec','/dev/disk/by-label/EQFIXTURE','/opt/fixture'])
    manifest = json.loads(P('/opt/fixture/package-proof.json').read_text())
    packages=[]
    for item in manifest['packages']:
        p=P('/opt/fixture')/item['file']
        if p.stat().st_size!=item['bytes'] or hashlib.sha256(p.read_bytes()).hexdigest()!=item['sha256']:
            raise RuntimeError('Package identity mismatch')
        packages.append(str(p))
    # Restrict package service starts until daemon configuration is installed.
    P('/usr/sbin/policy-rc.d').write_text('#!/bin/sh\nexit 101\n');P('/usr/sbin/policy-rc.d').chmod(0o755)
    run(['dpkg','--force-confdef','--force-confold','-i',*packages],timeout=300)
    P('/etc/docker').mkdir(exist_ok=True)
    P('/etc/docker/daemon.json').write_text(json.dumps({'log-driver':'local','log-opts':{'max-size':'1m','max-file':'2'}}))
    P('/usr/sbin/policy-rc.d').unlink()
    run(['systemctl','start','containerd','docker'],timeout=120)
    info=json.loads(run(['docker','info','--format','{{json .}}']).stdout)
    report['docker']={k:info.get(k) for k in ['ID','ServerVersion','DockerRootDir','Driver']}
    # busybox-static is already in the signed base. No registry pull or build.
    with tarfile.open('/opt/eqemu-proof/tiny.tar','w') as t:
        t.add('/bin/busybox',arcname='bin/busybox',recursive=False)
        link=tarfile.TarInfo('bin/sh');link.type=tarfile.SYMTYPE;link.linkname='busybox';t.addfile(link)
        payload=b'eqemu-offline-ok\n';entry=tarfile.TarInfo('www/index.html');entry.size=len(payload);entry.mode=0o444;t.addfile(entry,io.BytesIO(payload))
    run(['docker','import','/opt/eqemu-proof/tiny.tar','eqemu-synthetic:v1'])
    run(['docker','network','create','--internal','--subnet','172.29.31.0/24','eqemu-proof'])
    run(['docker','run','-d','--pull=never','--name','fixture-server','--network','eqemu-proof','--ip','172.29.31.2','--read-only','--cap-drop=ALL','eqemu-synthetic:v1','/bin/busybox','httpd','-f','-p','8080','-h','/www'])
    for _ in range(10):
        result=run(['docker','run','--rm','--pull=never','--network','eqemu-proof','eqemu-synthetic:v1','/bin/busybox','wget','-T','3','-qO-','http://172.29.31.2:8080/'],timeout=20,check=False)
        if result.returncode==0:break
        time.sleep(1)
    report['checks']['container_exchange'] = result.returncode==0 and result.stdout=='eqemu-offline-ok\n'
    result=run(['docker','run','--rm','--pull=never','--network','none','eqemu-synthetic:v1','/bin/sh','-c','exit 7'],check=False)
    report['checks']['intentional_failure_distinct'] = result.returncode==7
    run(['docker','rm','-f','fixture-server']);run(['docker','network','rm','eqemu-proof'])
    report['checks']['containers_removed'] = run(['docker','ps','-aq']).stdout.strip()==''
    report['ok']=all(report['checks'].values())
except Exception as e:
    report['error']=str(e)[:4000]
finally:
    line='EQEMU_TRIAL_RESULT '+json.dumps(report,separators=(',',':'))+'\n'
    with open('/dev/ttyS0','w') as out:out.write(line);out.flush()
    subprocess.run(['systemctl','poweroff'],timeout=15,check=False)
