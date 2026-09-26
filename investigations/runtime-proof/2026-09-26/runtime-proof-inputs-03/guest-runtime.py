#!/usr/bin/python3
"""Fixed guest-only runtime experiment. Importing this module executes no workload."""
import hashlib,importlib.util,json,os,pathlib,pwd,re,resource,secrets,select,shutil,signal,subprocess,tarfile,threading,time,tty,zipfile
P=pathlib.Path
spec=importlib.util.spec_from_file_location('build',P(__file__).with_name('guest-build.py'));B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
RM=P('/opt/runtime-inputs');ROOT=P('/opt/eqemu-runtime');GIB=1024**3
LOG_CAP=64*1024**2
RUNTIME_SHA='b51d4751fe2a31689dd906b392da1e24d9510e26418067b09788f43b78403b28'
BUILD_USED=0;LAST_CHECK=0;SERVICES=[];SECRET_VALUES=[]
READINESS={'world','zone','instance','base_map','water_map','nav_map','quests','perl_plugins','world_time'}
# These tables have source-backed startup/timer writes. Player/login data is never exempt.
MUTABLE={'rule_values','logsys_categories','player_event_log_settings','eqtime','spawn_condition_values','respawn_times'}
ANSI=re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')
BAD=re.compile(r"\[ERROR\]|\[FATAL\]|\|\s*(?:Error|MySQL\s*Err|MySQL Erro|MySQL Error|QuestError|Quest Error|Crash|Fatal)\s*\||\b(?:Segmentation fault|Aborted|terminate called|ERROR [0-9]{3,5}|Perl Error|Lua Error|Lua Exception|syntax error|Compilation failed|BEGIN failed|Can't locate|World server connection lost|Zone->Init failed)\b",re.I)

def scrub(s):
 for secret in SECRET_VALUES:s=s.replace(secret,'[guest-local secret]')
 return s

def check_guest():
 if os.geteuid()!=0 or not P('/opt/eqemu-proof/RUNTIME_GUEST_ONLY').is_file():raise RuntimeError('Guest-only guard')
 if sorted(p.name for p in P('/sys/class/net').iterdir())!=['lo']:raise RuntimeError('Unexpected guest NIC')
 if any(x in P('/proc/mounts').read_text() for x in [' virtiofs ',' 9p ',' nfs ',' nfs4 ']):raise RuntimeError('Unexpected host mount')

def verify_runtime():
 p=RM/'runtime-bundle-manifest.json'
 if B.sha(p)!=RUNTIME_SHA:raise RuntimeError('Runtime manifest identity mismatch')
 m=json.loads(p.read_text());seen=set()
 for f in m['files']:
  path=P(f['path'])
  if path.is_absolute() or '..' in path.parts or f['path'] in seen:raise RuntimeError('Unsafe runtime path')
  seen.add(f['path']);p=RM/path
  if p.is_symlink() or not p.is_file() or p.stat().st_size!=f['bytes'] or B.sha(p)!=f['sha256']:raise RuntimeError('Runtime payload mismatch '+f['path'])
 return m

def allocated(path):return sum(p.stat().st_blocks*512 for p in path.rglob('*') if p.is_file() and not p.is_symlink()) if path.exists() else 0

def guard():
 global LAST_CHECK
 if time.monotonic()>B.DEADLINE:raise RuntimeError('Shared workload/runtime deadline')
 for s in SERVICES:
  if s.error:raise RuntimeError(s.error)
 if time.monotonic()-LAST_CHECK<2:return
 LAST_CHECK=time.monotonic()
 if BUILD_USED and shutil.disk_usage(ROOT).used-BUILD_USED>8*GIB:raise RuntimeError('Runtime disk growth cap')
 if shutil.disk_usage(ROOT).free<8*GIB:raise RuntimeError('Guest free disk floor')
 for p in ROOT.glob('*/database'):
  if allocated(p)>6*GIB:raise RuntimeError('Database allocation cap')
 for p in ROOT.glob('*/server'):
  if allocated(p/'logs')>256*1024**2 or allocated(p/'shared')>768*1024**2:raise RuntimeError('Runtime logs/shared-memory cap')

def event(case,state,**kw):B.emit(dict(kind='runtime',case=case,state=state,**kw))

class Service:
 """Own a process group and continuously drain capped output; never inherit guest secrets in arguments."""
 def __init__(self,name,args,cwd,log):
  self.name=name;self.path=log;self.error=None;self.tail='';self.pending='';self.flags=set();self.pid=None;self.stop_expected=False
  self.proc=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,cwd=cwd,env=B.ENV,start_new_session=True)
  self.pid=self.proc.pid;self.start_ticks=P(f'/proc/{self.pid}/stat').read_text().rsplit(')',1)[1].split()[19]
  self.thread=threading.Thread(target=self.drain,daemon=True);self.thread.start();SERVICES.append(self)
 def drain(self):
  total=0
  try:
   with self.path.open('xb') as f:
    while chunk:=self.proc.stdout.read1(65536):
     total+=len(chunk)
     if total>LOG_CAP:raise RuntimeError(self.name+': log cap')
     f.write(chunk);f.flush();text=chunk.decode(errors='replace');self.tail=(self.tail+text)[-3500:];self.pending+=text
     if len(self.pending)>65536 and '\n' not in self.pending:raise RuntimeError(self.name+': line cap')
     while '\n' in self.pending:
      line,self.pending=self.pending.split('\n',1);self.scan(line)
    if self.pending:self.scan(self.pending)
  except Exception as e:
   self.error=scrub(str(e))
   try:os.killpg(self.pid,signal.SIGKILL)
   except ProcessLookupError:pass
  finally:self.proc.stdout.close()
 def scan(self,line):
  if len(line)>65536:raise RuntimeError(self.name+': line cap')
  line=ANSI.sub('',line)
  if 'Unable to read perl file' in line and not line.endswith("Unable to read perl file 'plugin.pl'"):raise RuntimeError(self.name+': '+line[-1200:])
  if BAD.search(line):raise RuntimeError(self.name+': '+line[-1200:])
  if 'Setting zone process to Zone [The Plane of Knowledge] [poknowledge] zone_id [202]' in line and '(Static)' in line and 'Instance ID' not in line:self.flags.add('world')
  if 'Zone booted successfully zone_id [202]' in line:self.flags.add('zone')
  if 'Booting [poknowledge] ([202]:[0])' in line:self.flags.add('instance')
  if re.search(r'Loaded (?:V[12]|\.MMF) Map File.*poknowledge\.map',line):self.flags.add('base_map')
  if re.search(r'Loaded Water Map V\[\d+\].*poknowledge\.wtr',line):self.flags.add('water_map')
  if re.search(r'Loaded Navmesh V\[\d+\].*poknowledge\.nav',line):self.flags.add('nav_map')
  if 'Loading quests' in line:self.flags.add('quests')
  if 'Loading perlemb plugins' in line:self.flags.add('perl_plugins')
  if 'Received Message SyncWorldTime' in line:self.flags.add('world_time')
 def live(self):
  if self.error:raise RuntimeError(self.error)
  if self.proc.poll() is not None:raise RuntimeError(self.name+': early exit '+str(self.proc.returncode)+' '+scrub(self.tail))
  if P(f'/proc/{self.pid}/stat').read_text().rsplit(')',1)[1].split()[19]!=self.start_ticks:raise RuntimeError('Process identity changed')
 def stop(self):
  self.stop_expected=True
  if self.proc.poll() is not None:raise RuntimeError(self.name+': exited before requested shutdown')
  os.killpg(self.pid,signal.SIGTERM)
  try:rc=self.proc.wait(timeout=30)
  except subprocess.TimeoutExpired:B.kill_group(self.proc);raise RuntimeError(self.name+': graceful stop deadline')
  self.thread.join(5)
  if self.thread.is_alive() or self.error or rc!=0:raise RuntimeError(self.name+': shutdown '+str(rc)+' '+str(self.error))
  SERVICES.remove(self)
  return rc

def connection(zone_pid):
 inodes=set()
 for p in P(f'/proc/{zone_pid}/fd').iterdir():
  try:target=os.readlink(p)
  except FileNotFoundError:continue
  if target.startswith('socket:['):inodes.add(target[8:-1])
 for line in P('/proc/net/tcp').read_text().splitlines()[1:]:
  x=line.split()
  if x[3]=='01' and x[2]=='0100007F:2328' and x[9] in inodes:return True
 return False

def stage_runtime_packages(packages,source,cache):
 # Ubuntu pool names omit epochs. APT's cache uses full versions with escaped colons.
 for package in packages:
  src=source/P(package['Filename']).name
  name=package['Package']+'_'+package['Version'].replace(':','%3a')+'_'+package['Architecture']+'.deb'
  if P(name).name!=name or src.is_symlink() or not src.is_file():raise RuntimeError('Invalid runtime archive path')
  if src.stat().st_size!=int(package['Size']) or B.sha(src)!=package['SHA256']:raise RuntimeError('Runtime archive identity mismatch')
  with src.open('rb') as source_file,(cache/name).open('xb') as target:shutil.copyfileobj(source_file,target)
  if B.sha(cache/name)!=package['SHA256']:raise RuntimeError('Runtime cache copy mismatch')

def install_runtime():
 # The proven build package setup has already configured this isolated guest APT directory.
 proof=json.loads((RM/'provenance/runtime-package-proof.json').read_text())
 stage_runtime_packages(proof['packages'],RM/'debs',B.WORK/'apt/archives')
 allowed={(p['Package'],p['Version']) for p in proof['packages']}
 pins=[p+'='+v for p,v in sorted(allowed)]
 args=['apt-get','--no-download','--no-remove','-y','-o','Dpkg::Options::=--force-confdef','-o','Dpkg::Options::=--force-confold','install',*pins]
 plan=B.command('runtime-package-plan',['apt-get','-s',*args[1:]],cap=2*1024**2).read_text();selected=set()
 for line in plan.splitlines():
  if line.startswith('Remv '):raise RuntimeError('Runtime solver removal')
  if line.startswith('Inst '):
   m=re.match(r'Inst (\S+) \((\S+)',line)
   if not m:raise RuntimeError('Runtime solver upgrade or invalid line')
   selected.add((m[1].split(':')[0],m[2]))
 if selected!=allowed:raise RuntimeError('Runtime solver differs from sealed closure')
 policy=P('/usr/sbin/policy-rc.d')
 if policy.exists():raise RuntimeError('Unexpected service-start policy')
 B.command('runtime-service-mask',['systemctl','mask','mariadb.service','mysql.service'])
 policy.write_text('#!/bin/sh\nexit 101\n');policy.chmod(0o755)
 try:B.command('runtime-package-install',args,timeout=600)
 finally:policy.unlink()
 audit=B.command('runtime-package-audit',['dpkg','--audit']).read_text()
 if audit.strip():raise RuntimeError('Runtime dpkg audit')
 identities=B.command('runtime-package-identities',['dpkg-query','-W','-f=${Package}\t${Version}\n',*[p for p,_ in sorted(allowed)]]).read_text()
 if set(tuple(line.split('\t')) for line in identities.splitlines())!=allowed:raise RuntimeError('Installed runtime identities differ')
 B.command('runtime-perl-modules',['perl','-MDBI','-MDBD::mysql','-MJSON','-MScalar::Util','-e','print "$DBI::VERSION $DBD::mysql::VERSION $JSON::VERSION\\n"'])
 if subprocess.run(['pgrep','-x','mariadbd'],stdout=subprocess.DEVNULL).returncode!=1:raise RuntimeError('Unexpected database daemon')
 return B.sha(B.LOGS/'runtime-package-plan.log')

class Database:
 def __init__(self,case,root):self.case=case;self.root=root;self.sock=root/'mysql.sock';self.n=0
 def query(self,label,sql,db=True,timeout=60):
  self.n+=1;path=self.root/'query.sql';path.write_text(sql+'\n');path.chmod(0o600)
  try:
   with path.open('rb') as f:
    out=B.command(self.case+'-'+label,self.args(db),stdin=f,timeout=timeout,cap=8*1024**2)
   return out.read_text()
  finally:path.unlink()
 def args(self,db=True):return ['/usr/bin/mariadb','--no-defaults','--protocol=socket','--socket='+str(self.sock),'--user=root','--batch','--skip-column-names',*(['eqemu_proof'] if db else [])]
 def initialize(self):
  data=self.root/'database';data.mkdir();u=pwd.getpwnam('mysql');os.chown(data,u.pw_uid,u.pw_gid);os.chmod(self.root,0o755)
  # Socket/pid directory must be writable by mysql without granting access to server credentials.
  run=self.root/'run';run.mkdir();os.chown(run,u.pw_uid,u.pw_gid);self.sock=run/'mysql.sock'
  B.command(self.case+'-db-init',['mariadb-install-db','--no-defaults','--user=mysql','--datadir='+str(data),'--auth-root-authentication-method=socket','--skip-test-db'],timeout=120)
  self.service=Service('database',['/usr/sbin/mariadbd','--no-defaults','--user=mysql','--datadir='+str(data),'--socket='+str(self.sock),'--pid-file='+str(run/'mysql.pid'),'--bind-address=127.0.0.1','--port=3306','--skip-name-resolve','--skip-log-bin','--innodb-buffer-pool-size=256M','--innodb-log-file-size=64M','--max-allowed-packet=64M','--max-connections=30','--tmpdir='+str(run)],self.root,self.root/'database-console.log')
  end=time.monotonic()+60
  while time.monotonic()<end:
   guard();self.service.live()
   if self.sock.exists():break
   time.sleep(.25)
  else:raise RuntimeError('DB socket absent')
  self.query('db-create','CREATE DATABASE eqemu_proof CHARACTER SET latin1;',db=False)
 def import_fixture(self):
  inventory=json.loads((RM/'provenance/database-inspection.json').read_text());expected={m['path']:m for m in inventory['members']}
  with zipfile.ZipFile(RM/'database/peq-1787356814.zip') as z:
   for group in inventory['import_order']:
    name='peq-dump/create_tables_'+group+'.sql';meta=expected[name];target=self.root/'import.sql'
    h=hashlib.sha256();count=0
    with z.open(name) as src,target.open('xb') as dest:
     while block:=src.read(1024**2):count+=len(block);h.update(block);dest.write(block);guard()
    if count!=meta['bytes'] or h.hexdigest()!=meta['sha256']:raise RuntimeError('SQL member mismatch')
    try:
     with target.open('rb') as f:B.command(self.case+'-import-'+group,self.args(),stdin=f,timeout=300,cap=2*1024**2)
    finally:target.unlink()
  return inventory
 def snapshot(self,label,inventory):
  tables=sorted({t for g in inventory['groups'].values() for t in g['tables']})
  actual=self.query(label+'-tables','SHOW TABLES;').splitlines()
  if set(actual)!=set(tables):raise RuntimeError('Unexpected table set: '+str(set(actual)^set(tables)))
  version=self.query(label+'-version','SELECT version,bots_version,custom_version FROM db_version;').strip()
  if version!='9328\t0\t0':raise RuntimeError('Unexpected database version')
  policy=self.query(label+'-policy',"SELECT rule_value FROM rule_values WHERE ruleset_id=1 AND rule_name='Bots:Enabled';").strip()
  if policy!='false':raise RuntimeError('Bots rule changed')
  empty=sorted(set(inventory['groups']['player']['tables']+inventory['groups']['login']['tables']))
  sql=' UNION ALL '.join("SELECT '"+t+"',COUNT(*) FROM `"+t+'`' for t in empty)+';'
  counts=self.query(label+'-empty',sql)
  if any(line.split('\t')[1]!='0' for line in counts.splitlines()):raise RuntimeError('Nonempty player/login table')
  schema=self.query(label+'-schema',"SELECT TABLE_NAME,COLUMN_NAME,ORDINAL_POSITION,COLUMN_TYPE,IS_NULLABLE,IFNULL(COLUMN_DEFAULT,'<NULL>'),EXTRA,IFNULL(CHARACTER_SET_NAME,''),IFNULL(COLLATION_NAME,'') FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='eqemu_proof' ORDER BY TABLE_NAME,ORDINAL_POSITION; SELECT TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX,COLUMN_NAME,NON_UNIQUE,IFNULL(SUB_PART,0) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA='eqemu_proof' ORDER BY TABLE_NAME,INDEX_NAME,SEQ_IN_INDEX; SELECT TABLE_NAME,ENGINE,TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA='eqemu_proof' ORDER BY TABLE_NAME;")
  data=self.query(label+'-checksums','CHECKSUM TABLE '+','.join('`'+t+'`' for t in tables)+';',timeout=180)
  checks={line.split('\t')[0].split('.')[-1]:line.split('\t')[1] for line in data.splitlines()}
  if set(checks)!=set(tables) or any(v=='NULL' for v in checks.values()):raise RuntimeError('Incomplete table checksum evidence')
  return {'schema_sha256':hashlib.sha256(schema.encode()).hexdigest(),'checksums':checks,'empty_sha256':hashlib.sha256(counts.encode()).hexdigest(),'version':version}

def configure(case,root,db):
 server=root/'server';server.mkdir()
 with tarfile.open(RM/'quests/quests-b3e34b8.tar.gz') as t:t.extractall(server,filter='data')
 (server/'projecteqquests-b3e34b84457d570401ea954ddd66de19179d0e41').rename(server/'quests')
 shutil.copytree(RM/'maps',server/'maps');shutil.copytree(RM/'opcodes',server/'opcodes')
 for name in ['shared','logs']:(server/name).mkdir()
 if case=='negative':(server/'maps/water/poknowledge.wtr').unlink()
 password=secrets.token_hex(24);key=secrets.token_hex(24);SECRET_VALUES.extend([password,key])
 db.query('app-account',"CREATE USER 'eqemu'@'127.0.0.1' IDENTIFIED BY '"+password+"'; GRANT ALL ON eqemu_proof.* TO 'eqemu'@'127.0.0.1';",db=False)
 config={'server':{'auto_database_updates':'false','world':{'shortname':'offlineproof','longname':'Offline runtime proof','address':'127.0.0.1','localaddress':'127.0.0.1','key':key,'tcp':{'ip':'127.0.0.1','port':'9000'},'telnet':{'enabled':'false'},'http':{'enabled':'false'}},'database':{'host':'127.0.0.1','port':'3306','username':'eqemu','password':password,'db':'eqemu_proof'},'ucs':{'host':'127.0.0.1','port':'7778'},'queryserver':{'host':'127.0.0.1'},'directories':{'quests':'quests','plugins':'quests/plugins','lua_modules':'quests/lua_modules','maps':'maps','patches':'opcodes/','opcodes':'opcodes/','shared_memory':'shared/','logs':'logs/'}}}
 p=server/'eqemu_config.json';p.write_text(json.dumps(config));p.chmod(0o600)
 # Explicit derived fixture setup before baseline; sealed SQL is unchanged.
 db.query('fixture-settings',"UPDATE rule_values SET rule_value='false' WHERE rule_name IN ('Bots:Enabled','Analytics:CrashReporting','Zone:StateSavingOnShutdown'); UPDATE variables SET value='default' WHERE varname='RuleSet'; UPDATE logsys_categories SET log_to_file=0,log_to_gmsay=0,log_to_discord=0,discord_webhook_id=0; UPDATE logsys_categories SET log_to_console=1 WHERE log_category_description IN ('Info','Error','MySQL Error','QuestErrors','Quests','Crash'); UPDATE logsys_categories SET log_to_console=0 WHERE log_category_description='MySQL Query';")
 if db.query('fixture-policy',"SELECT COUNT(*) FROM discord_webhooks WHERE COALESCE(webhook_url,'')<>''; SELECT COUNT(*) FROM rule_values WHERE ruleset_id=1 AND rule_name='Bots:Enabled' AND rule_value='false';").strip()!='0\n1':raise RuntimeError('Fixture policy mismatch')
 return server

def check_state(before,after):
 if before['schema_sha256']!=after['schema_sha256'] or before['empty_sha256']!=after['empty_sha256'] or before['version']!=after['version']:raise RuntimeError('Schema/version/player state changed')
 changed={t for t in before['checksums'] if before['checksums'][t]!=after['checksums'][t]}
 if changed-MUTABLE:raise RuntimeError('Unexpected database writes '+str(sorted(changed-MUTABLE)))
 return sorted(changed)

def shared_evidence(directory):
 # Linux IPC mutexes leave empty .lock files beside the nonempty data segments.
 required={'items','spells'};allowed=required|{'items.lock','spells.lock'}
 entries=[p for _,p in zip(range(5),directory.iterdir())]
 sizes={p.name[:80]:('symlink' if p.is_symlink() else p.stat().st_size if p.is_file() else 'not-regular') for p in entries}
 invalid=len(entries)>4 or set(sizes)-allowed or not required<=set(sizes)
 invalid=invalid or any(type(n) is not int for n in sizes.values())
 invalid=invalid or any(type(sizes.get(name)) is not int or not 0<sizes[name]<=768*1024**2 for name in required)
 if invalid:raise RuntimeError('Shared memory output invalid: '+json.dumps(sizes,sort_keys=True))
 return {name:{'bytes':sizes[name],'sha256':B.sha(directory/name)} for name in sorted(required)}

def scenario(case):
 event(case,'started');root=ROOT/case;root.mkdir();db=Database(case,root);world=zone=None
 try:
  db.initialize();inventory=db.import_fixture();server=configure(case,root,db);config_sha=B.sha(server/'eqemu_config.json')
  expected_zone=db.query('zone-content',"SELECT zoneidnumber,version,short_name FROM zone WHERE zoneidnumber=202 AND version=0; SELECT COUNT(*)>0 FROM items; SELECT COUNT(*)>0 FROM spells_new;").strip()
  if expected_zone!='202\t0\tpoknowledge\n1\n1':raise RuntimeError('Required public content missing')
  shared_log=B.command(case+'-shared-memory',[str(B.WORK/'build/bin/shared_memory')],cwd=server,timeout=180)
  scan=Service.__new__(Service);scan.name='shared_memory';scan.flags=set()
  with shared_log.open() as f:
   for line in f:scan.scan(line.rstrip('\n'))
  shared=shared_evidence(server/'shared')
  before=db.snapshot('before',inventory)
  world=Service('world',[str(B.WORK/'build/bin/world')],server,root/'world-console.log')
  # Start zone after the world listener is present; readiness still requires authenticated zone registration.
  end=time.monotonic()+120
  while time.monotonic()<end:
   guard();world.live();db.service.live()
   if any(x.split()[1].endswith(':2328') and x.split()[3]=='0A' for x in P('/proc/net/tcp').read_text().splitlines()[1:]):break
   time.sleep(.25)
  else:raise RuntimeError('World listener absent')
  zone=Service('zone',[str(B.WORK/'build/bin/zone'),'poknowledge:7000'],server,root/'zone-console.log')
  needed=READINESS-({'water_map'} if case=='negative' else set());end=time.monotonic()+120
  while time.monotonic()<end:
   guard();world.live();zone.live();db.service.live();flags=world.flags|zone.flags
   if needed<=flags and connection(zone.pid):break
   time.sleep(.25)
  else:raise RuntimeError('Readiness missing '+str(sorted(needed-(world.flags|zone.flags)))+' '+scrub(world.tail+' '+zone.tail)[-3500:])
  if case=='negative' and 'water_map' in flags:raise RuntimeError('Withheld water map unexpectedly ready')
  event(case,'ready',flags=sorted(flags),zone_id=202,instance_id=0)
  start=time.monotonic();samples=0;duration=15 if case=='negative' else 60
  while True:
   guard();world.live();zone.live();db.service.live()
   if not connection(zone.pid):raise RuntimeError('Lost world connection')
   if case=='negative' and 'water_map' in world.flags|zone.flags:raise RuntimeError('Negative control became ready')
   elapsed=time.monotonic()-start;samples+=1
   event(case,'sample',sample=samples,elapsed=round(elapsed,3))
   if elapsed>=duration:break
   time.sleep(10 if case=='positive' else 5)
  exits={'zone':zone.stop(),'world':world.stop()};zone=world=None
  after=db.snapshot('after',inventory);changed=check_state(before,after)
  if B.sha(server/'eqemu_config.json')!=config_sha:raise RuntimeError('Runtime configuration changed')
  exits['database']=db.service.stop()
  result={'accepted':case=='positive','missing_readiness':['water_map'] if case=='negative' else [],'flags':sorted(flags),'samples':samples,'duration':round(elapsed,3),'exits':exits,'config_sha256':config_sha,'schema_sha256':before['schema_sha256'],'state_before_sha256':hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest(),'state_after_sha256':hashlib.sha256(json.dumps(after,sort_keys=True).encode()).hexdigest(),'changed_tables':changed,'shared':shared,'logs':{p.name:{'bytes':p.stat().st_size,'sha256':B.sha(p)} for p in root.glob('*-console.log')}}
  event(case,'completed',accepted=result['accepted'],missing_readiness=result['missing_readiness'])
  return result
 finally:
  for service in list(reversed(SERVICES)):
   try:B.kill_group(service.proc)
   except Exception:pass
   service.thread.join(5);SERVICES.remove(service)
  if case=='negative' and (root/'database').exists():shutil.rmtree(root/'database')

def oom_kills():
 values=dict(line.split() for line in P('/proc/vmstat').read_text().splitlines())
 return int(values['oom_kill'])

def verify_binaries(binaries):
 for name,expected in binaries.items():
  if B.sha(B.WORK/'build/bin'/name)!=expected:raise RuntimeError('Built binary changed '+name)

def runtime(binaries):
 global BUILD_USED
 BUILD_USED=shutil.disk_usage(ROOT).used;B.DEADLINE=min(B.DEADLINE,time.monotonic()+1800);B.GUARD=guard
 package_plan=install_runtime();verify_binaries(binaries);negative=scenario('negative');verify_binaries(binaries);positive=scenario('positive');verify_binaries(binaries);verify_runtime()
 return {'input_manifest_sha256':RUNTIME_SHA,'package_plan_sha256':package_plan,'negative':negative,'positive':positive,'disk_growth_bytes':max(0,shutil.disk_usage(ROOT).used-BUILD_USED)}

def main():
 check_guest();resource.setrlimit(resource.RLIMIT_CORE,(0,0));B.WORK.mkdir();B.LOGS.mkdir();ROOT.mkdir();os.chmod(ROOT,0o755)
 subprocess.run(['systemctl','stop','serial-getty@ttyS0.service'],check=True,timeout=30)
 B.FD=os.open('/dev/ttyS0',os.O_RDWR|os.O_NOCTTY);tty.setraw(B.FD);B.EMIT=B.emit
 try:
  B.emit({'kind':'ready','manifest_sha256':B.MANIFEST_SHA,'runtime_manifest_sha256':RUNTIME_SHA});end=time.monotonic()+60;pending=b''
  while b'\n' not in pending and time.monotonic()<end:
   if select.select([B.FD],[],[],1)[0]:pending+=os.read(B.FD,1024)
   if len(pending)>2048:raise RuntimeError('Oversized command')
  c=json.loads(pending)
  if set(c)!={'op','nonce'} or c['op']!='build' or not re.fullmatch('[0-9a-f]{32}',c['nonce']):raise RuntimeError('Bad command')
  B.NONCE=c['nonce'];B.DEADLINE=time.monotonic()+1800;oom_before=oom_kills()
  B.MEDIA.mkdir();RM.mkdir()
  B.command('mount-input',['mount','-o','ro,nosuid,nodev,noexec','/dev/disk/by-label/EQEMUBUILD',str(B.MEDIA)])
  B.command('mount-runtime',['mount','-o','ro,nosuid,nodev,noexec','/dev/disk/by-label/EQEMURUNTIME',str(RM)])
  B.verify_inputs();verify_runtime();result=B.build();result['runtime']=runtime(result['binaries'])
  if oom_kills()!=oom_before:raise RuntimeError('Guest OOM observed')
  result['checks']['runtime']=True
  B.emit(dict(result,kind='result',ok=True))
 except Exception as e:B.emit({'kind':'result','ok':False,'error':scrub(str(e))[-4500:]})
 finally:
  for s in list(SERVICES):
   try:B.kill_group(s.proc)
   except Exception:pass
  subprocess.run(['systemctl','poweroff'],timeout=15,check=False)
if __name__=='__main__':main()
