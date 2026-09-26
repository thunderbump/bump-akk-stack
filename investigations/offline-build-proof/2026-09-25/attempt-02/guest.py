#!/usr/bin/python3
"""Fixed offline guest build experiment. Never execute this workload on the host."""
import hashlib,json,os,pathlib,re,select,selectors,shutil,signal,subprocess,tarfile,time,tty
P=pathlib.Path
MEDIA=P('/opt/build-inputs');WORK=P('/opt/eqemu-build');LOGS=WORK/'logs'
MANIFEST_SHA='9875b7669ff9c55b1374d3b5bf38246daba616df6f1364240e11757ed1078988'
FD=None;NONCE=None;DEADLINE=0;EMIT=lambda value:None
ENV={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','DEBIAN_FRONTEND':'noninteractive','HOME':'/root','VCPKG_DISABLE_METRICS':'1','VCPKG_MAX_CONCURRENCY':'1','VCPKG_BINARY_SOURCES':'clear','X_VCPKG_ASSET_SOURCES':'clear;x-block-origin','CCACHE_DISABLE':'1'}

def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def emit(value):
 data=('\nEQEMU_BUILD '+json.dumps(dict(value,nonce=NONCE),separators=(',',':'))+'\n').encode()
 if len(data)>16384:raise RuntimeError('Outgoing frame overflow')
 while data:data=data[os.write(FD,data):]
def kill_group(p):
 try:os.killpg(p.pid,signal.SIGKILL)
 except ProcessLookupError:pass
 p.wait(timeout=10)

def command(name,args,timeout=300,cwd=None,cap=64*1024**2):
 """Drain bounded output; timeout/nonzero/overflow always fail and kill the process group."""
 path=LOGS/(name+'.log');end=min(DEADLINE,time.monotonic()+timeout);total=0;start=time.monotonic();last=0
 EMIT({'kind':'stage','name':name,'state':'started'})
 proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,env=ENV,cwd=cwd,start_new_session=True)
 try:
  os.set_blocking(proc.stdout.fileno(),False)
  with selectors.DefaultSelector() as sel,path.open('xb') as log:
   sel.register(proc.stdout,selectors.EVENT_READ);eof=False
   while not eof or proc.poll() is None:
    if time.monotonic()>end:raise RuntimeError(name+': deadline exceeded')
    if time.monotonic()-last>30:EMIT({'kind':'stage','name':name,'state':'running'});last=time.monotonic()
    for key,_ in sel.select(.2):
     block=os.read(key.fd,65536)
     if not block:eof=True;sel.unregister(key.fileobj);continue
     if total+len(block)>cap:raise RuntimeError(name+': log limit exceeded')
     total+=len(block);log.write(block)
   rc=proc.wait(timeout=5)
  if rc!=0:raise RuntimeError(name+': exit '+str(rc))
  EMIT({'kind':'stage','name':name,'state':'passed'})
  return path
 except Exception as e:
  kill_group(proc)
  tail=''
  if path.exists():
   with path.open('rb') as f:f.seek(max(0,path.stat().st_size-3500));tail=f.read(3500).decode(errors='replace')
  raise RuntimeError(str(e)+'\n'+tail) from e
 finally:proc.stdout.close()

def verify_inputs():
 m=MEDIA/'bundle-manifest.json'
 if sha(m)!=MANIFEST_SHA:raise RuntimeError('Manifest identity mismatch')
 manifest=json.loads(m.read_text());seen=set()
 for f in manifest['files']:
  rel=P(f['path'])
  if rel.is_absolute() or '..' in rel.parts or f['path'] in seen:raise RuntimeError('Unsafe manifest path')
  seen.add(f['path']);p=MEDIA/rel
  if p.is_symlink() or not p.is_file() or p.stat().st_size!=f['bytes'] or sha(p)!=f['sha256']:raise RuntimeError('Missing or changed input: '+f['path'])
 return manifest

def apt_preflight():
 a=WORK/'apt'
 for d in ['lists/partial','archives/partial','parts','sources','preferences.d','auth.conf.d','trusted.gpg.d','log']:(a/d).mkdir(parents=True,exist_ok=True)
 for f in (MEDIA/'apt-lists').iterdir():shutil.copyfile(f,a/'lists'/f.name)
 for f in (MEDIA/'debs').iterdir():shutil.copyfile(f,a/'archives'/f.name)
 (a/'empty.conf').touch()
 (a/'sources.list').write_text('\n'.join(f'deb [arch=amd64 signed-by={MEDIA}/ubuntu-archive-keyring.gpg] https://archive.ubuntu.com/ubuntu {s} main universe' for s in ['noble','noble-updates','noble-security'])+'\n')
 (a/'apt.conf').write_text(f'''Dir::Etc "{a}";
Dir::Etc::main "{a}/empty.conf";
Dir::Etc::parts "{a}/parts";
Dir::Etc::sourcelist "{a}/sources.list";
Dir::Etc::sourceparts "{a}/sources";
Dir::State "{a}";
Dir::State::lists "{a}/lists";
Dir::State::status "/var/lib/dpkg/status";
Dir::Cache "{a}";
Dir::Cache::archives "{a}/archives";
Dir::Log "{a}/log";
APT::Architecture "amd64";
APT::Architectures {{ "amd64"; }};
APT::Install-Recommends "false";
APT::Get::allow-Downgrades "false";
''')
 ENV['APT_CONFIG']=str(a/'apt.conf')
 for i,f in enumerate(sorted((MEDIA/'apt-lists').glob('*InRelease'))):command('signature-'+str(i),['gpgv','--keyring',str(MEDIA/'ubuntu-archive-keyring.gpg'),str(f)])
 proof=json.loads((MEDIA/'provenance/ubuntu-package-proof.json').read_text())
 pins=[p['package']+'='+p['version'] for p in proof['packages']];allowed={(p['package'],p['version']) for p in proof['packages']}
 args=['apt-get','--no-download','--no-remove','-y','-o','Dpkg::Options::=--force-confdef','-o','Dpkg::Options::=--force-confold','install',*pins]
 plan=command('apt-plan',['apt-get','-s',*args[1:]],cap=2*1024**2).read_text()
 for l in plan.splitlines():
  if l.startswith('Remv '):raise RuntimeError('Guest solver wants removals')
  if l.startswith('Inst '):
   match=re.match(r'Inst (\S+)(?: \[[^]]+\])? \((\S+)',l)
   if not match or (match[1].split(':')[0],match[2]) not in allowed:raise RuntimeError('Guest selected an unbundled package '+l)
 policy=P('/usr/sbin/policy-rc.d')
 if policy.exists():raise RuntimeError('Unexpected existing service-start policy')
 policy.write_text('#!/bin/sh\nexit 101\n');policy.chmod(0o755)
 try:command('apt-install',args,timeout=900)
 finally:policy.unlink()
 command('dpkg-audit',['dpkg','--audit'])
 if (LOGS/'dpkg-audit.log').stat().st_size:raise RuntimeError('Incomplete dpkg state')
 installed=command('package-identities',['dpkg-query','-W','-f=${Package}\t${Version}\n',*[p['package'] for p in proof['packages']]],cap=2*1024**2).read_text()
 if set(tuple(l.split('\t')) for l in installed.splitlines())!=allowed:raise RuntimeError('Installed version mismatch')
 return sha(P('/var/lib/dpkg/status'))

def build():
 global DEADLINE
 before=sha(P('/var/lib/dpkg/status'));after=apt_preflight()
 src=WORK/'eqemu';src.mkdir()
 for name,dest in [('eqemu',src),('websocketpp',src/'submodules/websocketpp')]:
  dest.mkdir(parents=True,exist_ok=True)
  with tarfile.open(MEDIA/'sources'/f'{name}.tar.gz') as t:t.extractall(dest,filter='data')
 vp=src/'submodules/vcpkg'
 if vp.exists():vp.rmdir() # git archive creates an empty gitlink directory.
 command('registry-clone',['git','clone',str(MEDIA/'sources/vcpkg.bundle'),str(vp)])
 command('registry-checkout',['git','-C',str(vp),'checkout','--detach','d1ff36c6520ee43f1a656c03cd6425c2974a449e'])
 command('registry-integrity',['git','-C',str(vp),'fsck','--full','--strict'],timeout=300)
 shutil.copyfile(MEDIA/'tools/vcpkg',vp/'vcpkg');(vp/'vcpkg').chmod(0o755)
 downloads=WORK/'downloads';shutil.copytree(MEDIA/'downloads',downloads)
 ENV.update(VCPKG_ROOT=str(vp),VCPKG_DOWNLOADS=str(downloads))
 tools={}
 for name,args in [('compiler',['g++','--version']),('cmake',['cmake','--version']),('ninja',['ninja','--version']),('perl',['perl','-MIPC::Cmd','-MExtUtils::Embed','-e','print "$^V\\n"']),('make',['make','--version']),('autoreconf',['autoreconf','--version']),('pkgconfig',['pkg-config','--version']),('vcpkg',[str(vp/'vcpkg'),'version'])]:
  tools[name]=command('tool-'+name,args).read_text()[:600]
 solver=command('vcpkg-plan',[str(vp/'vcpkg'),'install','--dry-run','--triplet=x64-linux','--host-triplet=x64-linux','--binarysource=clear','--no-downloads'],cwd=src,timeout=300,cap=2*1024**2)
 plan=json.loads((MEDIA/'provenance/static-input-plan.json').read_text());expected={p['port']:p for p in plan['ports']}
 actual={}
 for l in solver.read_text().splitlines():
  m=re.match(r'^\s*(?:\*\s*)?([a-z0-9-]+)(?:\[([^]]+)\])?:x64-linux@([^\s]+)',l)
  if m:actual[m[1]]={'version':m[3],'features':sorted(set((m[2] or '').split(','))-{'','core'})}
 for n,p in expected.items():
  v=p['version']+('#'+str(p['port_version']) if p['port_version'] else '')
  if n not in actual or actual[n]['version']!=v or actual[n]['features']!=p['features']:raise RuntimeError('Solver differs from inventory: '+n+' '+str(actual.get(n)))
 if set(actual)!=set(expected):raise RuntimeError('Unexpected solver port set')
 # Make failure propagation observable before spending time compiling.
 try:command('intentional-exit-seven',['/bin/sh','-c','exit 7'],timeout=10)
 except RuntimeError as e:
  if 'exit 7' not in str(e):raise
 else:raise RuntimeError('Nonzero command was accepted')
 emit({'kind':'preflight','before_status':before,'after_status':after,'solver_sha256':sha(solver),'ports':len(actual),'negative_control':True,'tools':tools})
 DEADLINE=time.monotonic()+14400
 config=['cmake','-S',str(src),'-B',str(WORK/'build'),'-G','Ninja','-DCMAKE_BUILD_TYPE=RelWithDebInfo','-DCMAKE_C_COMPILER=/usr/bin/gcc','-DCMAKE_CXX_COMPILER=/usr/bin/g++','-DCMAKE_TOOLCHAIN_FILE='+str(vp/'scripts/buildsystems/vcpkg.cmake'),'-DVCPKG_TARGET_TRIPLET=x64-linux','-DVCPKG_HOST_TRIPLET=x64-linux','-DVCPKG_INSTALL_OPTIONS=--no-downloads;--binarysource=clear']
 config+=['-DEQEMU_BUILD_'+n+'=ON' for n in ['SERVER','TESTS','LOGIN','LUA','PERL','CLIENT_FILES']]
 command('configure',config,timeout=14400)
 cache=(WORK/'build/CMakeCache.txt').read_text()
 for key in ['PERL_INCLUDE_PATH','PERL_LIBRARY']:
  m=re.search('^'+key+r':\w+=(.+)$',cache,re.M)
  if not m or 'NOTFOUND' in m[1] or not P(m[1]).exists():raise RuntimeError('Perl detection missing '+key)
 command('server-build',['cmake','--build',str(WORK/'build'),'--parallel','1'],timeout=14400)
 command('upstream-tests',[str(WORK/'build/bin/tests')],timeout=600,cwd=WORK/'build')
 binaries={}
 for n in ['world','zone','shared_memory','loginserver','ucs','queryserv','eqlaunch','tests']:
  p=WORK/'build/bin'/n
  if not p.is_file():raise RuntimeError('Expected binary absent: '+n)
  binaries[n]=sha(p)
 effective={l.split('=',1)[0]:l.split('=',1)[1] for l in cache.splitlines() if re.match(r'^(EQEMU_BUILD_|PERL_(INCLUDE_PATH|LIBRARY):|CMAKE_(BUILD_TYPE|C_COMPILER:|CXX_COMPILER:))',l) and '=' in l}
 return {'effective_cmake':effective,'checks':{'inputs':True,'packages':True,'solver':True,'negative_control':True,'perl':True,'build':True,'tests':True},'binaries':binaries,'cache_sha256':sha(WORK/'build/CMakeCache.txt'),'guest_disk_used_bytes':shutil.disk_usage(WORK).used}

def main():
 global FD,NONCE,DEADLINE,EMIT
 if os.geteuid()!=0 or not P('/opt/eqemu-proof/BUILD_GUEST_ONLY').exists():raise RuntimeError('Guest-only workload guard')
 WORK.mkdir();LOGS.mkdir()
 subprocess.run(['systemctl','stop','serial-getty@ttyS0.service'],check=True,timeout=30)
 FD=os.open('/dev/ttyS0',os.O_RDWR|os.O_NOCTTY);tty.setraw(FD);EMIT=emit
 try:
  if sorted(p.name for p in P('/sys/class/net').iterdir())!=['lo']:raise RuntimeError('Unexpected guest NIC')
  if any(x in P('/proc/mounts').read_text() for x in [' virtiofs ',' 9p ',' nfs ',' nfs4 ']):raise RuntimeError('Unexpected host mount')
  emit({'kind':'ready','manifest_sha256':MANIFEST_SHA})
  end=time.monotonic()+60;pending=b''
  while b'\n' not in pending and time.monotonic()<end:
   if select.select([FD],[],[],1)[0]:pending+=os.read(FD,1024)
   if len(pending)>2048:raise RuntimeError('Oversized command')
  c=json.loads(pending)
  if set(c)!={'op','nonce'} or c['op']!='build' or not re.fullmatch('[0-9a-f]{32}',c['nonce']):raise RuntimeError('Bad command')
  NONCE=c['nonce'];DEADLINE=time.monotonic()+1800
  MEDIA.mkdir();command('mount-input',['mount','-o','ro,nosuid,nodev,noexec','/dev/disk/by-label/EQEMUBUILD',str(MEDIA)])
  verify_inputs();result=build();emit(dict(result,kind='result',ok=True))
 except Exception as e:emit({'kind':'result','ok':False,'error':str(e)[-4500:]})
 finally:subprocess.run(['systemctl','poweroff'],timeout=15,check=False)

if __name__=='__main__':main()
