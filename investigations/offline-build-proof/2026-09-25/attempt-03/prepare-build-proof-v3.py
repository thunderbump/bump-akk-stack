"""Prepare attempt 03 without altering failed attempts or earlier launch inputs."""
from pathlib import Path
import json,shutil,subprocess
B=Path(__file__).resolve().parent;old=B/'build-proof-inputs-v2';new=B/'build-proof-inputs-v3'
assert not new.exists();new.mkdir()
for name in ['guest.py','host-transport.py','suite-body.py','test-build-proof.py','prepare.py']:
 shutil.copyfile(old/name,new/name)
seal=json.loads((B/'build-inputs-20260925-v3/sealed-bundle-proof.json').read_text())
for name in ['guest.py','host-transport.py']:
 p=new/name;s=p.read_text();assert s.count('9875b7669ff9c55b1374d3b5bf38246daba616df6f1364240e11757ed1078988')==1;s=s.replace('9875b7669ff9c55b1374d3b5bf38246daba616df6f1364240e11757ed1078988',seal['manifest_sha256']);p.write_text(s)
p=new/'guest.py';s=p.read_text();anchor="def build():\n"
probe='''def system_zlib_probe():
 """Exercise the upstream test target's plain -lz link before the full build."""
 source=WORK/'system-zlib-probe.cpp';binary=WORK/'system-zlib-probe'
 source.write_text('#include <zlib.h>\\n#include <cstdio>\\nint main() { const char* version = zlibVersion(); if (!version || !*version) return 1; std::puts(version); return 0; }\\n')
 command('system-zlib-link',['/usr/bin/g++',str(source),'-o',str(binary),'-lz'],timeout=30)
 return command('system-zlib-run',[str(binary)],timeout=10).read_text().strip()

'''
assert s.count(anchor)==1;s=s.replace(anchor,probe+anchor)
s=s.replace('before=sha(P(\'/var/lib/dpkg/status\'));after=apt_preflight()',"before=sha(P('/var/lib/dpkg/status'));after=apt_preflight();zlib_version=system_zlib_probe()")
s=s.replace(' tools={}\n'," tools={'system-zlib':zlib_version}\n")
s=s.replace("'perl':True,'build':True", "'perl':True,'system_zlib':True,'build':True")
p.write_text(s)
p=new/'host-transport.py';s=p.read_text().replace("'perl','build','tests'","'perl','system_zlib','build','tests'")
s=s.replace("if not isinstance(v['tools'],dict) or len(v['tools'])>10", "if not isinstance(v['tools'],dict) or not v['tools'].get('system-zlib') or len(v['tools'])>10");p.write_text(s)
p=new/'suite-body.py';s=p.read_text().replace('build-proof-01','build-proof-02').replace('8fd0bbe67f3b4c81d06eb795286b6aaf819b087566aa48e581bf891253b5cf6e','8d9f19ec8217b869ebe391b32648c11cde31476119a54e61ce01a0afbc758438');p.write_text(s)
p=new/'prepare.py';s=p.read_text().replace('-v2','-v3').replace('proof-02','proof-03').replace('build-02','build-03').replace('build02','build03').replace("468101120,'7bc933747f2d4a089129c0dde78355f53306939bee31eb206e29a2c7d3609145'",str(seal['iso_bytes'])+",'"+seal['iso_sha256']+"'");p.write_text(s)
p=new/'test-build-proof.py';s=p.read_text().replace('-v2','-v3').replace("'perl','build','tests'","'perl','system_zlib','build','tests'").replace("'negative_control':True,'tools':{}","'negative_control':True,'tools':{'system-zlib':'1.3'}")
anchor=' def test_incomplete_success(self):'
extra=''' def test_missing_zlib_evidence(self):
  p=W.BuildProtocol(NONCE);ready(p)
  with self.assertRaisesRegex(RuntimeError,'Invalid tool facts'):
   p.accept({'kind':'preflight','nonce':NONCE,'before_status':'1'*64,'after_status':'2'*64,'solver_sha256':'3'*64,'ports':51,'negative_control':True,'tools':{}})
  preflight(p);v=success();del v['checks']['system_zlib']
  with self.assertRaisesRegex(RuntimeError,'Invalid success result'):p.accept(v)
'''
assert anchor in s;s=s.replace(anchor,extra+anchor);p.write_text(s)
subprocess.run(['/usr/bin/python3',str(new/'prepare.py')],check=True)
