"""Inventory SQL and verify public source archives as data; do not import or execute."""
import hashlib,json,re,stat,tarfile,zipfile,subprocess
from pathlib import Path,PurePosixPath
R=Path(__file__).resolve().parent
S=Path('/home/bump/Projects/bump-eqemu/bump-EQEmu');COMMIT='4aceae18b94ffaafc08e2b17bc41cd72c77f795d'
def sha(b):return hashlib.sha256(b).hexdigest()
def safe(name):
 p=PurePosixPath(name)
 assert not p.is_absolute() and '..' not in p.parts and '\\' not in name and '\x00' not in name
 return p
members=[];groups={};alltables={};duplicates=[]
with zipfile.ZipFile(R/'downloads/peq-1787356814.zip') as z:
 assert len(z.infolist())==12 and len({m.filename for m in z.infolist()})==12
 assert sum(m.file_size for m in z.infolist())<1024**3
 for m in z.infolist():
  p=safe(m.filename);assert len(p.parts)==2 and p.parts[0]=='peq-dump'
  assert not stat.S_ISLNK(m.external_attr>>16) and not m.flag_bits&1
  raw=z.read(m);assert len(raw)==m.file_size
  members.append({'path':m.filename,'bytes':len(raw),'sha256':sha(raw)})
  if not re.fullmatch('create_tables_(content|login|player|state|system).sql',p.name):continue
  s=raw.decode('utf-8');group=p.stem.removeprefix('create_tables_')
  tables=re.findall(r'^CREATE TABLE `([^`]+)` \(.*?^\).*?;',s,re.M|re.S)
  ddl={match[1]:sha(match[0].encode()) for match in re.finditer(r'^CREATE TABLE `([^`]+)` \(.*?^\).*?;',s,re.M|re.S)}
  assert len(tables)==len(ddl)
  for table in set(tables)&set(alltables):
   assert ddl[table]==alltables[table],table
   duplicates.append({'table':table,'later_group':group,'identical_ddl':True})
  inserts=re.findall(r'^INSERT INTO `([^`]+)` VALUES\s*\n',s,re.M)
  assert set(inserts)<=set(tables)
  forbidden=re.findall(r'^\s*(?:CREATE (?:DATABASE|USER|TRIGGER|PROCEDURE|FUNCTION|EVENT)|GRANT|USE |SOURCE |\\!|SYSTEM |INSTALL |LOAD DATA|SELECT .* INTO (?:OUTFILE|DUMPFILE)).*',s,re.M|re.I)
  assert not forbidden,forbidden[:3]
  if group in ['login','player']:assert not inserts
  if group=='state':assert set(inserts)=={'instance_list'}
  groups[group]={'member':m.filename,'tables':tables,'table_count':len(tables),'insert_tables':sorted(set(inserts)),'schema_sha256':ddl,'header':s.splitlines()[:7]}
  alltables.update(ddl)
  if group=='system':
   version=re.findall(r'INSERT INTO `db_version` VALUES\s*\n\((\d+),(\d+),(\d+)\);',s)
   assert version==[('9328','0','0')]
   assert "(1,'Bots:Enabled','false'," in s
   groups[group]['db_version']=[9328,0,0];groups[group]['bots_disabled_ruleset']=1
   i=s.index('INSERT INTO `rule_sets`') if 'INSERT INTO `rule_sets`' in s else -1
   groups[group]['rulesets_sql']=s[i:s.index(';',i)+1] if i>=0 else None
  if group=='content':
   zone_sql=re.search(r"^INSERT INTO `zone` VALUES\s*\n(.*?)^UNLOCK TABLES;",s,re.M|re.S)[1]
   zrow=re.search(r"^.*'poknowledge'.*$",zone_sql,re.M)
   assert zrow;groups[group]['poknowledge_row']=zrow[0]
 assert not any(t.startswith('bot_') for t in alltables)
(R/'evidence/database-inspection.json').write_text(json.dumps({'archive':'peq-1787356814.zip','origin_authentication':'HTTPS official PEQ portal; no publisher signature or independent published checksum found','members':members,'expanded_bytes':sum(m['bytes'] for m in members),'import_order':['content','login','player','state','system'],'groups':groups,'duplicate_tables':duplicates,'total_tables':len(alltables),'bot_tables':[],'scope':'static statement/table inventory, not SQL execution or full semantic validation; verify schema/content/empty-state after guest import'},indent=2)+'\n')
expected={x['path']:x for x in json.loads((R/'evidence/quest-tree.json').read_text())['tree'] if x['type']=='blob'}
files=[];requires={};checks={}
with tarfile.open(R/'downloads/quests-b3e34b8.tar.gz') as t:
 assert sum(m.size for m in t.getmembers())<32*1024**2
 seen=set()
 for m in t.getmembers():
  safe(m.name);assert m.isdir() or m.isfile()
  if m.isdir():continue
  p=m.name.split('/',1)[1];assert p not in seen;seen.add(p)
  data=t.extractfile(m).read();assert len(data)==expected[p]['size']
  assert hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==expected[p]['sha']
  files.append({'path':p,'bytes':len(data),'sha256':sha(data),'git_blob':expected[p]['sha']})
  if p.split('/')[0] in ['poknowledge','global','plugins','lua_modules']:
   s=data.decode('latin-1')  # Preserve legacy quest bytes; ASCII module-token scan only.
   modules=re.findall(r'^\s*use\s+([\w:]+)',s,re.M)
   if modules:requires[p]=modules
   if p in ['plugins/check_handin.pl','lua_modules/items.lua']:checks[p]='CheckHandin' in s
 assert seen==set(expected) and all(checks.values()) and len(checks)==2
(R/'evidence/quest-inspection.json').write_text(json.dumps({'commit':'b3e34b84457d570401ea954ddd66de19179d0e41','file_count':len(files),'expanded_bytes':sum(f['bytes'] for f in files),'all_git_blobs_verified':True,'external_perl_uses':requires,'checkhandin':checks,'lua_bit':'provided by pinned server zone/lua_parser.cpp; remaining imports use retained full quest tree','files':files},indent=2)+'\n')
# Copy only source-pinned data assets; do not invoke any repository scripts.
assets=[]
for path in subprocess.check_output(['git','ls-tree','-r','--name-only',COMMIT,'utils/patches'],cwd=S,text=True).splitlines():
 if not path.endswith('.conf'):continue
 raw=subprocess.check_output(['git','show',COMMIT+':'+path],cwd=S)
 dest=R/'media/opcodes'/Path(path).name;dest.parent.mkdir(exist_ok=True)
 assert not dest.exists();dest.write_bytes(raw)
 assets.append({'source_path':path,'media_path':str(dest.relative_to(R/'media')),'bytes':len(raw),'sha256':sha(raw),'commit':COMMIT})
(R/'evidence/opcode-inspection.json').write_text(json.dumps(assets,indent=2)+'\n')
print(json.dumps({'sql_tables':len(alltables),'quest_files':len(files),'opcodes':len(assets),'db_version':version,'external_perl':requires}))
