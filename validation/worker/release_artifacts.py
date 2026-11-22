"""Dedicated fixed ELF release channel. Console/integration budgets are unchanged."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import selectors
import subprocess
import tarfile
import time

from staging_release import binding, canonical, contract, sha, sync_dir, write_json

PREFIX = b'EQEMU_RELEASE '
CHUNK = 12288
FRAME_LIMIT = 20000
WIRE_LIMIT = 1024**3
TAR_LIMIT = 724566016


def wire(value):
    raw = PREFIX + canonical(value) + b'\n'
    if len(raw) > FRAME_LIMIT:
        raise ValueError('release-frame-limit')
    return raw


def file_caps():
    budget = contract()['release_budget']
    binaries = {e['path']: e['proposed_max_bytes'] for e in budget['binary_caps']}
    return {name: binaries.get(name, 2 * 1024**2 if name.startswith('logs/') else 8 * 1024**2)
            for name in budget['required_exact_regular_files']}


def validate_tar(path, fixed):
    """Inspect bounded regular members as bytes; never extract or execute on the host."""
    if Path(path).stat().st_size > TAR_LIMIT:
        raise ValueError('release-tar-limit')
    caps = file_caps(); records = {}; documents = {}; total = 0; groups = {'metadata': 0, 'logs': 0}
    with tarfile.open(path, mode='r:') as archive:
        for entry in archive:
            if (entry.name not in caps or entry.name in records or not entry.isfile()
                    or entry.pax_headers or entry.issparse() or entry.uid != 0 or entry.gid != 0
                    or entry.mode != (0o755 if entry.name.startswith('bin/') else 0o600)
                    or entry.mtime != 0 or entry.size < (0 if entry.name.startswith('logs/') else 1)
                    or entry.size > caps[entry.name]):
                raise ValueError('release-tar-member')
            total += entry.size
            if total > 723517440:
                raise ValueError('release-payload-limit')
            group = 'logs' if entry.name.startswith('logs/') else 'metadata'
            if not entry.name.startswith('bin/'):
                groups[group] += entry.size
                if groups[group] > (8 if group == 'logs' else 16) * 1024**2:
                    raise ValueError('release-group-limit')
            digest = hashlib.sha256(); prefix = b''; content = bytearray()
            with archive.extractfile(entry) as source:
                while block := source.read(1024**2):
                    digest.update(block)
                    if len(prefix) < 20: prefix = (prefix + block)[:20]
                    if not entry.name.startswith('bin/'): content.extend(block)
            if entry.name.startswith('bin/') and (entry.size < 64 or prefix[:7] != b'\x7fELF\x02\x01\x01'
                    or prefix[16:18] not in (b'\x02\x00', b'\x03\x00') or prefix[18:20] != b'\x3e\x00'):
                raise ValueError('release-elf-architecture')
            records[entry.name] = dict(bytes=entry.size, sha256=digest.hexdigest())
            if not entry.name.startswith('bin/'): documents[entry.name] = bytes(content)
    if set(records) != set(caps):
        raise ValueError('release-tar-incomplete')
    manifest = json.loads(documents['MANIFEST.json'])
    listed = {k: v for k, v in records.items() if k not in ('MANIFEST.json', 'SHA256SUMS')}
    if manifest != dict(binding=fixed, files=listed):
        raise ValueError('release-manifest-binding')
    sums = ''.join(v['sha256'] + '  ' + name + '\n' for name, v in sorted(records.items()) if name != 'SHA256SUMS')
    if documents['SHA256SUMS'] != sums.encode() or json.loads(documents['SOURCE.json']) != fixed:
        raise ValueError('release-source-or-checksum-binding')
    inputs = json.loads(documents['INPUTS.json'])
    if inputs != contract()['combined_manifest']:
        raise ValueError('release-input-binding')
    if hashlib.sha256(documents['metadata/Cargo.lock']).hexdigest() != inputs['preserved_bindings']['Cargo_lock_sha256']:
        raise ValueError('release-cargo-lock-binding')
    build = json.loads(documents['BUILD.json'])
    checks = build.get('checks', {})
    if (checks != {name: 0 for name in ('rust-format', 'rust-dependencies', 'rust-clippy', 'rust-tests', 'rust-doctests', 'native-configure', 'native-build', 'artifact-checks')}
            or any(type(value) is not int for value in checks.values())
            or build.get('targets') != ['world', 'zone', 'shared_memory', 'eqlaunch', 'ucs', 'queryserv']
            or build.get('abi_complete') is not True):
        raise ValueError('release-build-incomplete')
    return records


class Sink:
    """Keep partial bytes under a fresh private directory; only complete archives get a final name."""
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, parents=False)
        self.stream = (self.directory / 'release.tar.partial').open('xb')
        os.chmod(self.stream.name, 0o600)
        info = os.fstat(self.stream.fileno()); self.identity = (info.st_dev, info.st_ino)
        self.fixed = None; self.expected = None; self.total = 0; self.wire_bytes = 0
        self.digest = hashlib.sha256(); self.complete = False; self.ended = False

    def accept(self, frame):
        self.wire_bytes += len(wire(frame))
        if self.ended or self.wire_bytes > WIRE_LIMIT:
            raise ValueError('release-stream-state')
        if self.fixed is None:
            if set(frame) != {'kind', 'binding', 'bytes', 'sha256'} or frame['kind'] != 'begin':
                raise ValueError('release-begin')
            fixed = binding(frame['binding'].get('run_id'))
            if frame['binding'] != fixed or type(frame['bytes']) is not int or not 0 < frame['bytes'] <= TAR_LIMIT:
                raise ValueError('release-begin-binding')
            if not isinstance(frame['sha256'], str) or len(frame['sha256']) != 64 or any(c not in '0123456789abcdef' for c in frame['sha256']):
                raise ValueError('release-digest')
            self.fixed = fixed; self.expected = frame
        elif frame.get('kind') == 'chunk':
            if set(frame) != {'kind', 'offset', 'data'} or type(frame['offset']) is not int or frame['offset'] != self.total or not isinstance(frame['data'], str) or len(frame['data']) > CHUNK * 4 // 3:
                raise ValueError('release-offset')
            block = base64.b64decode(frame['data'], validate=True)
            if not 0 < len(block) <= CHUNK or self.total + len(block) > self.expected['bytes']:
                raise ValueError('release-chunk-limit')
            self.stream.write(block); self.digest.update(block); self.total += len(block)
        elif frame == {'kind': 'end', 'complete': True}:
            self.ended = True
            if self.total != self.expected['bytes'] or self.digest.hexdigest() != self.expected['sha256']:
                raise ValueError('release-terminal-digest')
            self.stream.flush(); os.fsync(self.stream.fileno())
            self.check_file(self.directory / 'release.tar.partial')
            validate_tar(self.directory / 'release.tar.partial', self.fixed)
            self.check_file(self.directory / 'release.tar.partial')
            os.rename(self.directory / 'release.tar.partial', self.directory / 'release.tar')
            sync_dir(self.directory); self.complete = True
        elif frame == {'kind': 'end', 'complete': False}:
            self.ended = True
        else:
            raise ValueError('release-frame-schema')

    def ack(self):
        if not self.complete: raise ValueError('release-no-ack-for-partial')
        self.check_file(self.directory / 'release.tar')
        return dict(kind='release-ack', binding=self.fixed, bytes=self.total, sha256=self.digest.hexdigest())

    def check_file(self, path):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != self.identity
                or info.st_size != self.total or sha(path) != self.digest.hexdigest()):
            raise ValueError('release-sink-file-changed')

    def close(self):
        self.stream.flush(); os.fsync(self.stream.fileno()); self.stream.close()


def frames(path, fixed, *, complete=True):
    path = Path(path)
    yield dict(kind='begin', binding=fixed, bytes=path.stat().st_size, sha256=sha(path))
    with path.open('rb') as source:
        offset = 0
        while block := source.read(CHUNK):
            yield dict(kind='chunk', offset=offset, data=base64.b64encode(block).decode())
            offset += len(block)
    yield dict(kind='end', complete=complete)


def supervise(runtime, args, scratch, log, connection, deadline, nonce, started, sink, detail):
    """Reuse VM ownership, with one fixed virtio port and a separate bounded decoder."""
    address = scratch / 'release.sock'
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peer = None; process = None; pending = {}; result = None; console_bytes = 0
    try:
        listener.bind(str(address)); os.chmod(address, 0o600); listener.listen(1); listener.setblocking(False)
        endpoint_info = address.lstat()
        args = [*args, '-device', 'virtio-serial-pci', '-chardev',
                'socket,id=release,path=' + str(address) + ',server=off',
                '-device', 'virtserialport,chardev=release,name=eqemu-release']
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=scratch, start_new_session=True, close_fds=True,
            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': str(scratch)})
        started(process.pid)
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector, log.open('xb') as console:
            selector.register(listener, selectors.EVENT_READ, 'listener')
            selector.register(process.stdout, selectors.EVENT_READ, 'console')
            pending = {'console': bytearray(), 'release': bytearray()}
            eof = set()
            while process.poll() is None or not {'console', 'release'} <= eof:
                if time.monotonic() >= deadline: raise TimeoutError('release-vm-deadline')
                if runtime.disconnected(connection): raise RuntimeError('release-client-disconnected')
                for key, _ in selector.select(.1):
                    name = key.data
                    if name == 'listener':
                        if peer is not None: raise ValueError('release-duplicate-channel')
                        peer, _ = listener.accept(); peer.setblocking(False)
                        selector.unregister(listener); selector.register(peer, selectors.EVENT_READ, 'release')
                        continue
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj); eof.add(name); continue
                    if name == 'console':
                        console_bytes += len(block)
                        if console_bytes > 64 * 1024**2: raise ValueError('release-console-limit')
                        console.write(block)
                    pending[name].extend(block)
                    while b'\n' in pending[name]:
                        line, _, rest = pending[name].partition(b'\n'); pending[name] = bytearray(rest)
                        if name == 'release':
                            if not line.startswith(PREFIX) or len(line) + 1 > FRAME_LIMIT: raise ValueError('release-channel-frame')
                            sink.accept(json.loads(line[len(PREFIX):]))
                            if sink.fixed and sink.fixed != binding(nonce): raise ValueError('release-guest-run')
                        elif line.startswith(b'EQEMU_WORKER_RESULT '):
                            if result is not None or len(line) > 16384: raise ValueError('release-guest-result-duplicate')
                            result = json.loads(line[len(b'EQEMU_WORKER_RESULT '):])
                    if len(pending[name]) > (FRAME_LIMIT if name == 'release' else 65536):
                        raise ValueError('release-channel-line-limit')
                if process.poll() is not None and peer is None:
                    raise ValueError('release-channel-not-established')
            if process.wait(timeout=5) != 0 or any(pending.values()): raise ValueError('release-vm-or-truncated-frame')
        if (not isinstance(result, dict) or type(result.get('version')) is not int or result.get('version') != 1 or result.get('nonce') != nonce
                or result.get('scope') != 'staging-build-export' or type(result.get('exit_code')) is not int
                or result['exit_code'] not in (0, 1, 2)):
            raise ValueError('release-guest-result')
        detail.update(result)
        if result['exit_code'] == 0 and (not sink.complete or result.get('guest_export_complete') is not True
                or result.get('build_exit_code') != 0 or result.get('container_cleanup') is not True
                or result.get('native_cleanup') is not True or result.get('engine_cleanup') is not True
                or result.get('container_exit_code') != 0 or result.get('native_build_exit_code') != 0):
            raise ValueError('release-guest-incomplete')
        return result['exit_code']
    finally:
        try:
            if process is not None:
                runtime.stop_process(process)
                process.stdout.close()
        finally:
            if peer is not None: peer.close()
            listener.close()
            if 'endpoint_info' in locals():
                current = address.lstat()
                if (current.st_dev, current.st_ino, current.st_mode) != (endpoint_info.st_dev, endpoint_info.st_ino, endpoint_info.st_mode):
                    raise ValueError('release-channel-path-changed')
                address.unlink()


def export(sink, connection, report):
    """Export retained bytes once; only an exact durable client ACK completes transfer."""
    receipt = dict(complete=False, client_ack=None, guest_capture_complete=sink.complete,
                   bytes=sink.total, sha256=sink.digest.hexdigest())
    try:
        path = sink.directory / ('release.tar' if sink.complete else 'release.tar.partial')
        sink.stream.flush(); os.fsync(sink.stream.fileno())
        if sink.total and sink.fixed:
            connection.settimeout(900)
            complete = sink.complete and report['exit_code'] == 0 and report['cleanup_complete'] is True
            for frame in frames(path, sink.fixed, complete=complete): connection.sendall(wire(frame))
            if complete:
                raw = bytearray()
                connection.settimeout(30)
                while not raw.endswith(b'\n'):
                    part = connection.recv(1)
                    if not part or len(raw) >= 1024: raise ValueError('release-client-ack-uncertain')
                    raw.extend(part)
                ack = json.loads(raw)
                if ack != sink.ack(): raise ValueError('release-client-ack-binding')
                receipt.update(complete=True, client_ack=ack)
        return receipt
    finally:
        connection.settimeout(None)


def exchange(path, request, media, output):
    """Exactly one connection; uncertain submission is never retried."""
    from staging_release import validate_request
    validate_request(request)
    sink = Sink(output); result = None; ack = None; deployable = False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(18330); connection.connect(str(path))
            connection.sendall(canonical(request) + b'\n')
            with Path(media).open('rb') as source:
                while block := source.read(1024**2): connection.sendall(block)
            with connection.makefile('rb') as source:
                while True:
                    line = source.readline(65537)
                    if not line or len(line) > 65536 or not line.endswith(b'\n'):
                        raise ValueError('release-final-report-missing')
                    if line.startswith(PREFIX):
                        if len(line) > FRAME_LIMIT: raise ValueError('release-frame-limit')
                        sink.accept(json.loads(line[len(PREFIX):]))
                        if sink.complete:
                            ack = sink.ack(); connection.sendall(canonical(ack) + b'\n')
                        continue
                    result = json.loads(line); break
        if (not isinstance(result, dict) or type(result.get('version')) is not int or result['version'] != 1
                or type(result.get('exit_code')) is not int or result['exit_code'] not in (0, 1, 2)
                or result.get('operation') != 'staging-build-export' or result.get('candidate') != request['candidate']
                or result.get('tree') != request['tree'] or result.get('payload_sha256') != request['sha256']):
            raise ValueError('release-result-binding')
        if sink.fixed is not None and result.get('run_id') != sink.fixed['run_id']:
            raise ValueError('release-result-run')
        if result['exit_code'] == 0 and (not sink.complete or result.get('cleanup_complete') is not True
                or result.get('vm_started') is not True or result.get('scope') != 'fixed-e35-staging-build-export-v1'
                or result.get('release_export', {}).get('client_ack') != ack or not result.get('guest', {}).get('container_cleanup') is True
                or result.get('guest', {}).get('build_exit_code') != 0
                or result.get('guest', {}).get('container_exit_code') != 0 or result.get('guest', {}).get('native_build_exit_code') != 0
                or result.get('guest', {}).get('native_cleanup') is not True or result.get('guest', {}).get('engine_cleanup') is not True):
            raise ValueError('release-success-incomplete')
        deployable = result['exit_code'] == 0
        return result
    finally:
        sink.close()
        write_json(sink.directory / 'client-receipt.json', dict(complete=sink.complete, deployable=deployable, client_ack=ack,
            bytes=sink.total, sha256=sink.digest.hexdigest(), worker_result=result))
