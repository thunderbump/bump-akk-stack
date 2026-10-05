#!/usr/bin/python3
"""Fixed offline guest build experiment. Never execute this workload on the host."""
import hashlib,json,os,pathlib,re,select,selectors,shutil,signal,subprocess,tarfile,time,tty
P=pathlib.Path
MEDIA=P('/opt/build-inputs');WORK=P('/opt/eqemu-build');LOGS=WORK/'logs'
MANIFEST_SHA='95eb1cf160fdc3704d17d9d18be0919ed393f6951a98f6143a144b2c91b8f7e4'
FD=None;NONCE=None;DEADLINE=0;EMIT=lambda value:None
ENV={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','DEBIAN_FRONTEND':'noninteractive','HOME':'/root','VCPKG_DISABLE_METRICS':'1','VCPKG_MAX_CONCURRENCY':'1','VCPKG_BINARY_SOURCES':'clear','X_VCPKG_ASSET_SOURCES':'clear;x-block-origin','CCACHE_DISABLE':'1'}

def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def emit(value):
 data=('\nEQEMU_BUILD '+json.dumps(dict(value,nonce=NONCE),separators=(',',':'))+'\n').encode()
 if len(data)>16384:raise RuntimeError('Outgoing frame overflow')
 end=time.monotonic()+10
 while data:
  if time.monotonic()>=end:raise RuntimeError('Serial write deadline')
  if select.select([],[FD],[],.2)[1]:
   try:data=data[os.write(FD,data):]
   except BlockingIOError:pass
def kill_group(p):
 try:os.killpg(p.pid,signal.SIGKILL)
 except ProcessLookupError:pass
 p.wait(timeout=10)

def command(name,args,timeout=300,cwd=None,cap=64*1024**2,expected_exit=0):
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
  if rc!=expected_exit:raise RuntimeError(name+': exit '+str(rc))
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

def system_zlib_probe():
 """Exercise the upstream test target's plain -lz link before the full build."""
 source=WORK/'system-zlib-probe.cpp';binary=WORK/'system-zlib-probe'
 source.write_text('#include <zlib.h>\n#include <cstdio>\nint main() { const char* version = zlibVersion(); if (!version || !*version) return 1; std::puts(version); return 0; }\n')
 command('system-zlib-link',['/usr/bin/g++',str(source),'-o',str(binary),'-lz'],timeout=30)
 return command('system-zlib-run',[str(binary)],timeout=10).read_text().strip()

def build():
    raise RuntimeError('Consumer cannot compile source')


def main():
 global FD,NONCE,DEADLINE,EMIT,EXPECTED_ARTIFACT
 if os.geteuid()!=0 or not P('/opt/eqemu-proof/BUILD_GUEST_ONLY').exists():raise RuntimeError('Guest-only workload guard')
 WORK.mkdir();LOGS.mkdir()
 subprocess.run(['systemctl','stop','serial-getty@ttyS0.service'],check=True,timeout=30)
 FD=os.open('/dev/ttyS0',os.O_RDWR|os.O_NOCTTY);tty.setraw(FD);os.set_blocking(FD,False);EMIT=emit
 try:
  if sorted(p.name for p in P('/sys/class/net').iterdir())!=['lo']:raise RuntimeError('Unexpected guest NIC')
  if any(x in P('/proc/mounts').read_text() for x in [' virtiofs ',' 9p ',' nfs ',' nfs4 ']):raise RuntimeError('Unexpected host mount')
  emit({'kind':'ready','manifest_sha256':MANIFEST_SHA,'experiment_sha256':'1499707f727a4a8af16c47a569b00a49612670ef17283a95261e0010bead44b6'})
  end=time.monotonic()+60;pending=b''
  while b'\n' not in pending and time.monotonic()<end:
   if select.select([FD],[],[],1)[0]:pending+=os.read(FD,1024)
   if len(pending)>2048:raise RuntimeError('Oversized command')
  c=json.loads(pending)
  if set(c)!={'op','nonce','artifact_manifest_sha256'} or c['op']!='build' or not re.fullmatch('[0-9a-f]{32}',c['nonce']):raise RuntimeError('Bad command')
  EXPECTED_ARTIFACT=c['artifact_manifest_sha256']
  if not isinstance(EXPECTED_ARTIFACT,str) or not re.fullmatch('[a-f0-9]{64}',EXPECTED_ARTIFACT):raise RuntimeError('Artifact identity command')
  NONCE=c['nonce'];DEADLINE=time.monotonic()+1800
  MEDIA.mkdir();command('mount-input',['mount','-o','ro,nosuid,nodev,noexec','/dev/disk/by-label/EQEMUBUILD',str(MEDIA)])
  verify_inputs();result=build();emit(dict(result,kind='result',ok=True))
 except Exception as e:emit({'kind':'result','ok':False,'error':str(e)[-4500:]})
 finally:subprocess.run(['systemctl','poweroff'],timeout=15,check=False)

"""Bounded diagnostic data and utility completion acceptance, with no process-kill policy."""
import json


class DiagnosticTail:
    def __init__(self, secrets=(), limit=32768):
        if not 0 < limit <= 32768 or len(secrets) > 16 or any(len(s) > 1024 for s in secrets):
            raise ValueError('Diagnostic bounds')
        self.secrets = [s.encode() for s in secrets if s]
        self.limit = limit
        self.capacity = limit + max(map(len, self.secrets), default=0)
        self.data = b''
        self.total = 0

    def feed(self, chunk):
        self.total += len(chunk)
        self.data = (self.data + chunk[-self.capacity:])[-self.capacity:]

    def export(self):
        data = self.data
        for secret in sorted(self.secrets, key=len, reverse=True):
            data = data.replace(secret, b'[redacted]')
        # Truncate decoded text by encoded bytes, including replacement characters.
        text = ''.join(c if c in '\n\t' or ord(c) >= 32 and not 127 <= ord(c) <= 159 else '?'
                       for c in data.decode('utf-8', 'replace'))
        encoded = text.encode()
        text = encoded[-self.limit:].decode('utf-8', 'ignore')
        return {'text': text, 'input_bytes': self.total,
                'retained_bytes': len(text.encode()), 'truncated': self.total > self.limit}



def utility_result(output, exit_code):
    if len(output) > 1024 * 1024:
        raise ValueError('Utility output budget')
    lines = [line[len('EQEMU_TEST_RESULT '):] for line in output.splitlines()
             if line.startswith('EQEMU_TEST_RESULT ')]
    if len(lines) != 1 or len(lines[0]) > 2048:
        raise ValueError('Missing or duplicate utility completion')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate completion key')
            result[key] = value
        return result
    result = json.loads(lines[0], object_pairs_hook=unique)
    if not isinstance(result, dict) or type(result.get('version')) is not int or result.get('version') != 1:
        raise ValueError('Completion version')
    for key in ['selected', 'started', 'completed', 'failed']:
        if type(result.get(key)) is not int or not 0 <= result[key] <= 1000000:
            raise ValueError('Completion count')
    passed = (exit_code == 0 and result.get('passed') is True and result.get('finalized') is True
              and result['selected'] > 0 and result['selected'] == result['started'] == result['completed']
              and result['failed'] == 0)
    if not passed:
        raise ValueError('Utility suite failed or incomplete')
    return result

"""Exact outcomes for the six fixed C++ runner controls; no process execution."""
import json

EXPECTED = {
    'pass': (0, 1, 1, 1, 0, True, True),
    'fail': (1, 1, 1, 1, 1, True, False),
    'empty': (1, 0, 0, 0, 0, True, False),
    'setup-exception': (1, 1, 1, 0, 0, False, False),
    'body-exception': (1, 1, 1, 1, 1, True, False),
    'teardown-exception': (1, 1, 1, 0, 0, False, False),
}


def control_result(output, exit_code, mode):
    if len(output) > 1024**2: raise ValueError('Control output budget')
    lines = [line.removeprefix('EQEMU_TEST_RESULT ') for line in output.splitlines()
             if line.startswith('EQEMU_TEST_RESULT ')]
    if len(lines) != 1 or len(lines[0]) > 2048: raise ValueError('Control completion missing/duplicated')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise ValueError('Duplicate control field')
            value[key] = item
        return value
    result = json.loads(lines[0], object_pairs_hook=unique)
    keys = ['version', 'selected', 'started', 'completed', 'failed', 'finalized', 'passed']
    if not isinstance(result, dict) or set(result) != set(keys): raise ValueError('Control completion shape')
    if any(type(result[k]) is not int for k in keys[:5]) or any(type(result[k]) is not bool for k in keys[5:]):
        raise ValueError('Control completion types')
    if result['version'] != 1 or (exit_code, *(result[k] for k in keys[1:])) != EXPECTED[mode]:
        raise ValueError('Unexpected control outcome: ' + mode)
    return dict(result, exit_code=exit_code)

# Inserted into the fixed guest recipe. This code runs only inside the offline VM.

def apply_candidate(src):
    raise RuntimeError('Consumer cannot prepare source')


def completed_output(path, parser, *args):
    output = path.read_text()
    try:
        return parser(output, *args)
    except (ValueError, TypeError, KeyError) as error:
        tail = DiagnosticTail(limit=3000); tail.feed(output.encode())
        raise RuntimeError(path.stem + ': ' + str(error)[:500] + '\n' + tail.export()['text']) from error


def runner_controls(build_controls=True):
    if build_controls:
        command('runner-control-build', ['cmake', '--build', str(WORK/'build'),
                '--target', 'tests_runner_controls', 'tests_reporting_controls',
                '--parallel', '1'], timeout=600)
    for mode in EXPECTED:
        expected_exit = EXPECTED[mode][0]
        path = command('runner-' + mode, [str(WORK/'build/bin/tests_runner_controls'), mode],
                       timeout=30, cwd=WORK/'build', cap=1024**2, expected_exit=expected_exit)
        record = completed_output(path, control_result, expected_exit, mode)
        emit({'kind': 'observation', 'name': 'runner-' + mode, 'value': record})
    path = command('reporting-controls', [str(WORK/'build/bin/tests_reporting_controls')],
                   timeout=30, cwd=WORK/'build', cap=1024**2)
    record = completed_output(path, reporting_result, 0)
    emit({'kind': 'observation', 'name': 'reporting-controls', 'value': record})


def reporting_result(output, exit_code):
    if exit_code != 0 or output != 'Reporting controls passed\n':
        raise ValueError('Reporting control completion missing or failed')
    return {'exit_code': 0, 'passed': True}


def real_utility_suite():
    path = command('upstream-tests', [str(WORK/'build/bin/tests')], timeout=600,
                   cwd=WORK/'build', cap=1024**2)
    record = completed_output(path, utility_result, 0)
    emit({'kind': 'observation', 'name': 'utility', 'value': record})


def measure_outputs():
    """Measure direct ELF metadata and loader-resolved transitive libraries, guest only.

    This does not prove dlopen, Perl/Lua modules, maps, or a reusable runtime image.
    Unstripped binaries retain their embedded debug sections. No export is promoted.
    """
    paths = {str(WORK/'build/bin'/name) for name in ['world', 'zone', 'shared_memory', 'tests', 'tests_runner_controls', 'tests_reporting_controls']}
    executables = sorted(paths)
    for index, executable in enumerate(executables):
        output = command('loader-' + str(index), ['ldd', executable], timeout=30, cap=1024**2).read_text()
        if 'not found' in output:
            tail = DiagnosticTail(limit=3000); tail.feed(output.encode())
            raise RuntimeError('Unresolved loader dependency: ' + executable + '\n' + tail.export()['text'])
        resolved = []
        for line in output.splitlines():
            match = re.search(r'(?:=>\s+)?(/\S+)\s+\(0x[0-9a-f]+\)', line)
            if match:
                resolved.append(match[1]); paths.add(str(P(match[1]).resolve(strict=True)))
            elif line.strip() and not line.strip().startswith('linux-vdso.so.'):
                raise RuntimeError('Unrecognized loader output: ' + line[:500])
        if not resolved:
            raise RuntimeError('Missing loader dependency evidence')
        emit({'kind': 'observation', 'name': 'loader-' + str(index),
              'value': {'executable': executable, 'resolved_paths': resolved}})
    if len(paths) > 128:
        raise RuntimeError('ELF measurement inventory exceeds 128 files')
    files = []; build_bytes = 0; system_bytes = 0
    for index, name in enumerate(sorted(paths)):
        path = P(name)
        if not path.is_file(): raise RuntimeError('Missing ELF file')
        out = command('elf-' + str(index), ['readelf', '-W', '-l', '-d', '-n', '-S', name],
                      timeout=30, cap=1024**2).read_text()
        build_file = path.is_relative_to(WORK)
        debug_info = bool(re.search(r'\] \.debug_info\s', out))
        if name in executables and not debug_info:
            raise RuntimeError('Expected embedded debug information: ' + name)
        build_id = re.findall(r'Build ID: ([a-f0-9]+)', out)
        if len(build_id) != 1: raise RuntimeError('Missing or ambiguous ELF build ID')
        record = {'path': name, 'bytes': path.stat().st_size, 'sha256': sha(path),
                  'build_file': build_file, 'debug_info': debug_info, 'build_id': build_id[0],
                  'needed': re.findall(r'\(NEEDED\).*?\[(.*?)\]', out),
                  'rpath': re.findall(r'\((?:RPATH|RUNPATH)\).*?\[(.*?)\]', out),
                  'interpreter': re.findall(r'Requesting program interpreter: ([^\]]+)', out)}
        files.append(record)
        if build_file: build_bytes += record['bytes']
        else: system_bytes += record['bytes']
        emit({'kind': 'observation', 'name': 'elf-' + str(index), 'value': record})
    emit({'kind': 'observation', 'name': 'measurement', 'value': {
        'files': len(files), 'build_bytes': build_bytes, 'system_bytes': system_bytes,
        'total_bytes': build_bytes + system_bytes,
        'within_payload_budget': build_bytes + system_bytes <= 3*1024**3,
        'artifact_eligible': False, 'runtime_closure_proven': False}})

"""Bounded artifact primitives. Host functions handle opaque bytes only."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

BLOCK = 1024 * 1024
WRITE_WINDOW = 16 * BLOCK


def check_deadline(deadline, operation):
    if time.monotonic() >= deadline:
        raise TimeoutError('Artifact ' + operation + ' deadline')


def regular_fd(path, expected_size=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or (expected_size is not None and info.st_size != expected_size):
        os.close(fd)
        raise ValueError('Artifact type or length mismatch')
    return fd


def hash_file(path, size, deadline):
    check_deadline(deadline, 'hash')
    digest = hashlib.sha256()
    with os.fdopen(regular_fd(path, size), 'rb') as source:
        remaining = size
        while remaining:
            check_deadline(deadline, 'hash')
            block = source.read(min(BLOCK, remaining))
            if not block:
                raise ValueError('Truncated artifact')
            digest.update(block)
            remaining -= len(block)
        if source.read(1):
            raise ValueError('Artifact grew')
    check_deadline(deadline, 'hash')
    return digest.hexdigest()


def copy_blob(source, target, size, expected, deadline):
    """Copy into a new owned file; remove only that file on any failure."""
    check_deadline(deadline, 'copy')
    with os.fdopen(regular_fd(source, size), 'rb') as src:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as dst:
                if size:
                    os.posix_fallocate(dst.fileno(), 0, size)
                digest = hashlib.sha256()
                remaining = size
                synced = 0
                while remaining:
                    check_deadline(deadline, 'copy')
                    block = src.read(min(BLOCK, remaining))
                    if not block:
                        raise ValueError('Truncated artifact')
                    dst.write(block)
                    digest.update(block)
                    remaining -= len(block)
                    copied = size - remaining
                    if copied - synced >= WRITE_WINDOW or remaining == 0:
                        # Dirty page cache counts against the controller's memory cap.
                        dst.flush()
                        os.fdatasync(dst.fileno())
                        check_deadline(deadline, 'copy')
                        for stream in (src, dst):
                            os.posix_fadvise(stream.fileno(), synced, copied - synced, os.POSIX_FADV_DONTNEED)
                        synced = copied
                if src.read(1) or digest.hexdigest() != expected:
                    raise ValueError('Artifact bytes changed')
                dst.flush()
                os.fsync(dst.fileno())
                check_deadline(deadline, 'copy')
        except BaseException:
            Path(target).unlink()
            raise


def validate_inventory(value, identity, max_bytes=3 * 1024**3, max_files=4096):
    """Guest-side content policy; callers must bound JSON before decoding it."""
    if not isinstance(value, dict) or type(value.get('version')) is not int or value.get('version') != 1 or value.get('identity') != identity:
        raise ValueError('Artifact identity mismatch')
    files = value.get('files')
    if not isinstance(files, list) or not 0 < len(files) <= max_files:
        raise ValueError('Artifact file count')
    seen = set()
    total = 0
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError('Artifact entry')
        name = entry.get('path')
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.\-/]{1,240}', name):
            raise ValueError('Artifact path')
        path = PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or str(path) != name or name in seen:
            raise ValueError('Artifact path or duplicate')
        if entry.get('type') != 'file' or type(entry.get('bytes')) is not int or entry['bytes'] < 0:
            raise ValueError('Artifact type or size')
        if not isinstance(entry.get('sha256'), str) or not re.fullmatch('[a-f0-9]{64}', entry['sha256']):
            raise ValueError('Artifact hash')
        total += entry['bytes']
        if total > max_bytes:
            raise ValueError('Artifact payload budget')
        seen.add(name)
    return files


def consume_files(root, target, inventory, identity, deadline):
    """Copy flat admitted payloads in the first proof, never follow guest links."""
    files = validate_inventory(inventory, identity)
    # A flat initial payload keeps directory traversal out of the copy implementation.
    if any('/' in entry['path'] for entry in files):
        raise ValueError('Nested payloads are not implemented in this synthetic proof')
    for entry in files:
        copy_blob(Path(root) / entry['path'], Path(target) / entry['path'],
                  entry['bytes'], entry['sha256'], deadline)
    return len(files)

"""Fixed four-executable payload policy. Guest paths never become host actions."""
import hashlib
import json
import re

NAMES = {'world', 'zone', 'shared_memory', 'tests', 'tests_runner_controls', 'tests_reporting_controls'}


def manifest_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def validate_payload(value, identity):
    # validate_inventory is the existing bounded flat-file policy, included by preparation.
    entries = validate_inventory(value, identity)
    if {entry['path'] for entry in entries} != NAMES or len(entries) != len(NAMES):
        raise ValueError('Expected six executable files')
    libraries = value.get('libraries')
    if not isinstance(libraries, list) or not 1 <= len(libraries) <= 128:
        raise ValueError('Library inventory size')
    seen = set()
    for entry in libraries:
        if (not isinstance(entry, dict) or not isinstance(entry.get('path'), str)
                or not re.fullmatch(r'/usr/lib/x86_64-linux-gnu/[A-Za-z0-9_.+-]+', entry['path'])
                or entry['path'] in seen or type(entry.get('bytes')) is not int or not 0 < entry['bytes'] <= 1024**3
                or not isinstance(entry.get('sha256'), str) or not re.fullmatch('[a-f0-9]{64}', entry['sha256'])):
            raise ValueError('Invalid system library identity')
        seen.add(entry['path'])
    if not isinstance(value.get('build'), dict) or not isinstance(value.get('preflight'), dict):
        raise ValueError('Build provenance missing')
    if value['preflight'].get('after_status') is None:
        raise ValueError('Package identity missing')
    return entries


def parse_manifest(data, identity, expected_sha):
    if len(data) > 262144 or hashlib.sha256(data).hexdigest() != expected_sha:
        raise ValueError('Artifact manifest identity/size')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('Duplicate manifest field')
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=unique)
    validate_payload(value, identity)
    return value

# Inserted into the corrected-build guest before main. No host execution.
import errno
import stat

ROLE = 'consumer'
BUILD_ID = '1499707f727a4a8af16c47a569b00a49612670ef17283a95261e0010bead44b6'
ARTIFACT_SIZE = 4*1024**3
MOUNT = P('/opt/build-artifact')
DEVICE = '/dev/vdb'
EXPECTED_ARTIFACT = None
OBSERVATIONS = {}
PREFLIGHT = {}
original_emit = emit
original_build = build


def emit(value):
    if value.get('kind') == 'observation': OBSERVATIONS[value['name']] = value['value']
    if value.get('kind') == 'preflight': PREFLIGHT.update(value)
    original_emit(value)


def artifact_mount(producer):
    if not stat.S_ISBLK(os.stat(DEVICE).st_mode) or int(P('/sys/class/block/vdb/size').read_text())*512 != ARTIFACT_SIZE:
        raise RuntimeError('Artifact device identity')
    MOUNT.mkdir()
    if producer:
        command('artifact-format', ['mkfs.ext4', '-F', '-m', '0', '-E',
            'nodiscard,lazy_itable_init=0,lazy_journal_init=0', DEVICE], timeout=120)
    command('artifact-mount', ['mount', '-o', 'nosuid,nodev,noexec' if producer else
            'ro,noload,nosuid,nodev,noexec', DEVICE, str(MOUNT)])


def export_build(result):
    inventory = {'version': 1, 'identity': BUILD_ID, 'files': [], 'libraries': [],
                 'build': result, 'preflight': PREFLIGHT}
    for name, entry in OBSERVATIONS.items():
        if not name.startswith('elf-'): continue
        if entry['build_file']:
            path = P(entry['path'])
            if path.parent != WORK/'build/bin' or path.name not in NAMES or not entry['debug_info']:
                raise RuntimeError('Unmeasured build-tree dependency or missing debug information')
            inventory['files'].append({'path': path.name, 'type': 'file',
                                      'bytes': entry['bytes'], 'sha256': entry['sha256']})
        else:
            inventory['libraries'].append({k: entry[k] for k in ['path', 'bytes', 'sha256']})
    validate_payload(inventory, BUILD_ID)
    data = manifest_bytes(inventory)
    if len(data) > 262144: raise RuntimeError('Manifest size budget')
    artifact_mount(True)
    try:
        for entry in inventory['files']:
            copy_blob(WORK/'build/bin'/entry['path'], MOUNT/entry['path'], entry['bytes'], entry['sha256'], DEADLINE)
        (MOUNT/'manifest.json').write_bytes(data)
    finally:
        command('artifact-unmount', ['umount', str(MOUNT)], timeout=120)
    return {'identity': BUILD_ID, 'manifest_sha256': hashlib.sha256(data).hexdigest(),
            'files': len(NAMES), 'payload_bytes': sum(entry['bytes'] for entry in inventory['files']), 'unmounted': True}


def consume_build():
    before = sha(P('/var/lib/dpkg/status')); after = apt_preflight()
    artifact_mount(False)
    try:
        with (MOUNT/'manifest.json').open('rb') as stream: data = stream.read(262145)
        inventory = parse_manifest(data, BUILD_ID, EXPECTED_ARTIFACT)
        if after != inventory['preflight']['after_status']:
            raise RuntimeError('Consumer package state differs from producer')
        # Check package-provided files in place. Never overwrite guest system libraries.
        libraries = {}
        for entry in inventory['libraries']:
            if hash_file(P(entry['path']), entry['bytes'], DEADLINE) != entry['sha256']:
                raise RuntimeError('Consumer library differs: ' + entry['path'])
            libraries[entry['path']] = entry['sha256']
        target = WORK/'build/bin'; target.mkdir(parents=True)
        consume_files(MOUNT, target, inventory, BUILD_ID, DEADLINE)
        for name in sorted(NAMES): (target/name).chmod(0o700)
        # Exercise the read-only attachment on this disposable consumer copy only.
        try:
            fd = os.open(DEVICE, os.O_WRONLY)
            try: os.pwrite(fd, b'X', ARTIFACT_SIZE-1); os.fsync(fd)
            finally: os.close(fd)
        except OSError as error:
            if error.errno not in [errno.EROFS, errno.EPERM, errno.EACCES, errno.EIO]: raise
        else: raise RuntimeError('Read-only artifact accepted a write')
    finally:
        command('artifact-unmount', ['umount', str(MOUNT)], timeout=120)
    # Resolve all six in the new filesystem, and ask its loader to verify each ELF.
    observed = set()
    for index, name in enumerate(sorted(NAMES)):
        path = target/name
        output = command('consumer-loader-'+str(index), ['ldd', str(path)], timeout=30, cap=1024**2).read_text()
        if 'not found' in output: raise RuntimeError('Unresolved consumer dependency: '+name+'\n'+output[-2000:])
        paths = []
        for line in output.splitlines():
            match = re.search(r'(?:=>\s+)?(/\S+)\s+\(0x[0-9a-f]+\)', line)
            if match: paths.append(str(P(match[1]).resolve(strict=True)))
            elif line.strip() and not line.strip().startswith('linux-vdso.so.'):
                raise RuntimeError('Unrecognized consumer loader output: '+line[:500])
        if not paths or any(path not in libraries for path in paths):
            raise RuntimeError('Consumer dependency outside measured package set')
        observed.update(paths)
        command('consumer-verify-'+str(index), ['/lib64/ld-linux-x86-64.so.2', '--verify', str(path)], timeout=30)
    if observed != set(libraries): raise RuntimeError('Consumer dependency set differs')
    runner_controls(build_controls=False)
    real_utility_suite()
    return {'identity': BUILD_ID, 'manifest_sha256': EXPECTED_ARTIFACT,
            'utility': OBSERVATIONS['utility'],
            'controls': {name: OBSERVATIONS[name] for name in ['reporting-controls', *('runner-' + mode for mode in EXPECTED)]},
            'binaries': {e['path']: e['sha256'] for e in inventory['files']},
            'libraries': libraries, 'before_status': before, 'after_status': after,
            'readonly': True, 'unmounted': True, 'compiled': False}


def build():
    if ROLE == 'consumer': return {'consumer': consume_build()}
    result = original_build()
    artifact = export_build(result)
    return dict(result, artifact=artifact)

if __name__=='__main__':main()
