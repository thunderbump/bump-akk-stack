"""Harmless fixed-operation tests. No candidate, engine, VM or installed socket runs."""
import copy
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import pwd
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

WORKER = Path(__file__).resolve().parents[2] / 'validation/worker'
sys.path.insert(0, str(WORKER))
import staging_release as contract
import staging_container as container
import staging_guest as guest
import staging_worker as worker
import release_artifacts as artifacts
import runtime
import prepare_staging_release as package


def archive(root, run='a' * 32):
    release = root / 'files'; release.mkdir()
    caps = artifacts.file_caps()
    for name in set(caps) - {'MANIFEST.json', 'SHA256SUMS'}:
        path = release / name; path.parent.mkdir(parents=True, exist_ok=True)
        data = b'bounded fixture\n'
        if name.startswith('bin/'):
            data = b'\x7fELF\x02\x01\x01' + b'\0' * 9 + b'\x02\0\x3e\0' + b'\0' * 44
        path.write_bytes(data)
    (release / 'SOURCE.json').write_bytes(contract.canonical(contract.binding(run)))
    (release / 'INPUTS.json').write_bytes(contract.canonical(artifacts.contract()['combined_manifest']))
    (release / 'BUILD.json').write_bytes(contract.canonical(dict(checks={name: 0 for name in container.CHECKS},
        targets=list(container.TARGETS), abi_complete=True)))
    destination = root / 'fixture.tar'
    container.make_tar(release, destination, contract.binding(run))
    return destination


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        # Small synthetic lock only inside temporary archive fixtures, not a new accepted production pin.
        fixture = copy.deepcopy(contract.contract())
        fixture['combined_manifest']['preserved_bindings']['Cargo_lock_sha256'] = hashlib.sha256(b'bounded fixture\n').hexdigest()
        for module in (artifacts, container):
            patcher = patch.object(module, 'contract', return_value=fixture)
            patcher.start(); self.addCleanup(patcher.stop)

    def test_request_is_exact_and_old_limit_unchanged(self):
        contract.validate_request(contract.request())
        for name, value in [('candidate', 'b' * 40), ('operation', 'build'), ('selection', 'any'), ('bytes', 1)]:
            request = contract.request(); request[name] = value
            with self.assertRaises(ValueError): contract.validate_request(request)
        request = contract.request(); request['command'] = 'anything'
        with self.assertRaises(ValueError): contract.validate_request(request)
        self.assertEqual(runtime.PAYLOAD_LIMIT, 1024**3)
        self.assertEqual(runtime.BUILD_SECONDS, 18000)
        self.assertNotIn('staging-build-export', runtime.CONTROLS)

    def test_storage_rejects_all_fallbacks_and_wrong_backing(self):
        info = dict(Driver='overlay2', DriverStatus=[['Backing Filesystem', 'extfs'], ['Supports d_type', 'true']])
        contract.validate_storage(info, 'ext4')
        for name in ('vfs', 'fuse-overlayfs', 'overlayfs'):
            with self.assertRaises(ValueError): contract.validate_storage(dict(info, Driver=name), 'ext4')
        with self.assertRaises(ValueError): contract.validate_storage(info, 'xfs')
        with self.assertRaises(ValueError): contract.validate_storage(dict(Driver='overlay2', DriverStatus=[]), 'ext4')

    def test_daemon_and_container_have_fixed_offline_operands(self):
        config = guest.daemon_config(); args = guest.container_args()
        self.assertEqual(config['storage-driver'], 'overlay2')
        self.assertEqual(config['features'], {'containerd-snapshotter': False})
        for name in ('iptables', 'ip6tables', 'ip-forward', 'ip-masq', 'userland-proxy'): self.assertIs(config[name], False)
        self.assertIn('--network=none', args); self.assertIn('--read-only', args)
        self.assertNotIn('--privileged', args)
        self.assertNotIn('/var/run/docker.sock', ' '.join(args))
        self.assertEqual(args[-2:], [guest.IMAGE, '/opt/release-helper/staging_container.py'])
        self.assertIn('--memory=3g', args); self.assertIn('--pids-limit=64', args)

    def test_guest_seed_contains_actual_helpers_not_ordinary_suites(self):
        # Seed generation is source data only.
        data = json.loads(worker.user_data('a' * 32, WORKER).split('\n', 1)[1])
        files = {entry['path']: entry for entry in data['write_files']}
        self.assertEqual(files['/opt/staging_guest.py']['content'], (WORKER / 'staging_guest.py').read_text())
        self.assertNotIn('/opt/normal_world.py', files)
        self.assertNotIn('entrypoint.pl', data['runcmd'][0][2])

    def test_tar_roundtrip_exact_inventory_durable_ack(self):
        path = archive(self.root); sink = artifacts.Sink(self.root / 'sink')
        try:
            for frame in artifacts.frames(path, contract.binding('a' * 32)): sink.accept(frame)
            self.assertTrue(sink.complete)
            self.assertEqual(len(artifacts.validate_tar(sink.directory / 'release.tar', sink.fixed)), 28)
            self.assertEqual(sink.ack()['sha256'], contract.sha(path))
            self.assertFalse((sink.directory / 'release.tar.partial').exists())
        finally: sink.close()

    def test_tar_unknown_members_symlinks_modes_and_source_refuse(self):
        path = archive(self.root)
        with tarfile.open(path) as stream:
            records = [(entry, stream.extractfile(entry).read()) for entry in stream]
        for change in ('extra', 'symlink', 'mode', 'source'):
            altered = self.root / (change + '.tar')
            with tarfile.open(altered, 'w', format=tarfile.USTAR_FORMAT) as stream:
                for index, (original, raw) in enumerate(records):
                    entry = copy.copy(original)
                    if index == 0:
                        if change == 'symlink': entry.type = tarfile.SYMTYPE; entry.linkname = '/tmp/unrelated'
                        if change == 'mode': entry.mode = 0o777
                    if change == 'source' and entry.name == 'SOURCE.json': raw = b'{}'; entry.size = len(raw)
                    stream.addfile(entry, io.BytesIO(raw))
                if change == 'extra':
                    extra = tarfile.TarInfo('UNKNOWN'); extra.size = 1; stream.addfile(extra, io.BytesIO(b'x'))
            with self.assertRaises(ValueError): artifacts.validate_tar(altered, contract.binding('a' * 32))

    def test_stream_gap_digest_and_truncation_never_ack(self):
        path = archive(self.root); frames = list(artifacts.frames(path, contract.binding('a' * 32)))
        for name in ('gap', 'digest', 'truncated', 'partial', 'wrong-run'):
            sink = artifacts.Sink(self.root / name)
            try:
                modified = copy.deepcopy(frames)
                if name == 'gap': modified[1]['offset'] += 1
                if name == 'digest': modified[0]['sha256'] = '0' * 64
                if name == 'truncated': modified = modified[:-1]
                if name == 'partial': modified[-1]['complete'] = False
                if name == 'wrong-run': modified[0]['binding']['run_id'] = 'not-a-run'
                try:
                    for frame in modified: sink.accept(frame)
                except ValueError: pass
                self.assertFalse(sink.complete)
                with self.assertRaises(ValueError): sink.ack()
                self.assertTrue((sink.directory / 'release.tar.partial').exists())
            finally: sink.close()

    def test_archive_extract_rejects_escape_duplicate_special_and_engine_mismatch(self):
        for name in ('escape', 'duplicate', 'special', 'engine'):
            path = self.root / (name + '.tar')
            with tarfile.open(path, 'w') as stream:
                entry = tarfile.TarInfo('../outside' if name == 'escape' else 'member')
                if name == 'special': entry.type = tarfile.FIFOTYPE
                stream.addfile(entry)
                if name == 'duplicate': stream.addfile(entry)
            with self.assertRaises(ValueError):
                guest.extract(path, self.root / name, engine={} if name == 'engine' else None)
        self.assertFalse((self.root.parent / 'outside').exists())

    def test_input_inventory_and_hash_enforced(self):
        root = self.root / 'media'; root.mkdir(); (root / 'x').write_bytes(b'fixed')
        manifest = {'files': [dict(name='x', bytes=5, sha256=contract.sha(root / 'x'))]}
        raw = contract.canonical(manifest); (root / 'COMBINED-INPUT-MANIFEST.json').write_bytes(raw)
        c = dict(combined_manifest=manifest, combined_manifest_sha256=hashlib.sha256(raw).hexdigest())
        with patch.object(contract, 'contract', return_value=c):
            contract.verify_inputs(root)
            (root / 'x').write_bytes(b'wrong')
            with self.assertRaises(ValueError): contract.verify_inputs(root)
            (root / 'x').write_bytes(b'fixed'); (root / 'extra').mkdir()
            with self.assertRaises(ValueError): contract.verify_inputs(root)

    def test_media_type_and_identity_refusal(self):
        path = self.root / 'media'; path.write_bytes(b'fixed')
        c = copy.deepcopy(contract.contract()); c['media'] = dict(bytes=5, sha256=contract.sha(path))
        with patch.object(contract, 'contract', return_value=c):
            contract.verify_media(path)
            path.write_bytes(b'wrong')
            with self.assertRaises(ValueError): contract.verify_media(path)
            link = self.root / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError): contract.verify_media(link)

    def test_cli_prepare_and_once_are_exclusive_no_connection(self):
        loader = importlib.machinery.SourceFileLoader('release_cli', str(WORKER.parents[1] / 'scripts/build-staging-release'))
        spec = importlib.util.spec_from_loader(loader.name, loader); cli = importlib.util.module_from_spec(spec); loader.exec_module(cli)
        with patch.object(cli, 'verify_media', return_value=contract.request()), patch.object(cli, 'exchange') as exchange:
            path = self.root / 'request.json'
            self.assertEqual(cli.main(['--media', '/fixture/media', '--prepare-only', str(path)]), 0)
            self.assertEqual(cli.main(['--media', '/fixture/media', '--prepare-only', str(path)]), 2)
            exchange.assert_not_called()
            self.assertEqual(json.loads(path.read_text())['scope'], 'prepared-only')

    def test_abi_unknown_dependency_version_symbol_interpreter_refuse(self):
        library = dict(elf=dict(soname=['libc.so.6'], defined_dynamic_symbols=['known'], version_definitions=['GLIBC_2.2.5']))
        inventory = dict(runtime_libraries={'usr/lib/libc.so.6': library})
        facts = dict(needed=['libc.so.6'], runpath=[], version_needs={'libc.so.6': ['GLIBC_2.2.5']},
                     undefined=['known'], interpreter=['/lib64/ld-linux-x86-64.so.2'])
        container.check_abi(facts, inventory)
        for key, value in [('needed', ['new.so']), ('version_needs', {'libc.so.6': ['GLIBC_99']}),
                           ('undefined', ['missing']), ('interpreter', ['/tmp/loader']), ('runpath', ['/build/leak'])]:
            with self.assertRaises(ValueError): container.check_abi(dict(facts, **{key: value}), inventory)

    def test_readelf_parsing_strong_symbols_versions(self):
        raw = '''Class: ELF64
Machine: Advanced Micro Devices X86-64
 [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
 0x00000001 (NEEDED) Shared library: [libc.so.6]
  1: 000000000000 0 FUNC GLOBAL DEFAULT UND known@GLIBC_2.2.5 (2)
  2: 000000000000 0 NOTYPE WEAK DEFAULT UND optional
Version needs section '.gnu.version_r' contains 1 entry:
 0x0010: Version: 1 File: libc.so.6 Cnt: 1
 0x0020: Name: GLIBC_2.2.5 Flags: none Version: 2
'''
        facts = container.readelf_facts(raw)
        self.assertEqual(facts['undefined'], ['known'])
        self.assertEqual(facts['version_needs'], {'libc.so.6': ['GLIBC_2.2.5']})

    def test_missing_root_admission_refuses_before_lock_or_launch(self):
        with patch.object(runtime, 'root_file', side_effect=ValueError('not admitted')), patch.object(runtime, 'acquire') as acquire:
            with self.assertRaises(ValueError): worker.run({'code_dir': str(self.root)}, None, contract.request())
            acquire.assert_not_called()

    def test_socket_transfer_actual_client_ack_and_cleanup_binding(self):
        path = archive(self.root); address = self.root / 'server.sock'
        listener = socket.socket(socket.AF_UNIX); listener.bind(str(address)); listener.listen(1)
        errors = []; acks = []
        def serve():
            try:
                with listener.accept()[0] as conn, conn.makefile('rb') as stream:
                    request = json.loads(stream.readline()); self.assertEqual(request, contract.request())
                    self.assertEqual(stream.read(5), b'media')
                    for frame in artifacts.frames(path, contract.binding('a' * 32)): conn.sendall(artifacts.wire(frame))
                    ack = json.loads(stream.readline()); acks.append(ack)
                    result = dict(version=1, operation='staging-build-export', candidate=request['candidate'], tree=request['tree'],
                        scope=contract.SELECTION, vm_started=True,
                        payload_sha256=request['sha256'], run_id='a' * 32, exit_code=0, cleanup_complete=True,
                        guest=dict(container_cleanup=True, native_cleanup=True, engine_cleanup=True,
                            build_exit_code=0, native_build_exit_code=0, container_exit_code=0), release_export=dict(client_ack=ack))
                    conn.sendall(contract.canonical(result) + b'\n')
            except BaseException as error: errors.append(error)
            finally: listener.close()
        thread = threading.Thread(target=serve); thread.start()
        media = self.root / 'media'; media.write_bytes(b'media')
        try:
            result = artifacts.exchange(address, contract.request(), media, self.root / 'client')
            self.assertEqual(result['exit_code'], 0)
        finally:
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive()); self.assertEqual(errors, []); self.assertEqual(len(acks), 1)

    def test_dedicated_virtio_decoder_with_real_harmless_child(self):
        path = archive(self.root)
        raw = b''.join(artifacts.wire(frame) for frame in artifacts.frames(path, contract.binding('a' * 32)))
        original_popen = subprocess.Popen
        report = dict(version=1, nonce='a' * 32, scope='staging-build-export', exit_code=0,
            build_exit_code=0, native_build_exit_code=0, container_exit_code=0,
            container_cleanup=True, native_cleanup=True, engine_cleanup=True, guest_export_complete=True)
        script = '''import socket,sys,base64
s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);s.sendall(base64.b64decode(sys.argv[2]));s.close()
print(sys.argv[3],flush=True)
'''
        import base64
        for name, content in [('valid', raw), ('truncated', raw[:-1])]:
            scratch = self.root / name; scratch.mkdir(); sink = artifacts.Sink(self.root / (name + '-sink'))
            observed = []
            def start(args, **kwargs):
                self.assertIn('virtserialport,chardev=release,name=eqemu-release', args)
                return original_popen([sys.executable, '-B', '-c', script, str(scratch / 'release.sock'),
                    base64.b64encode(content).decode(), 'EQEMU_WORKER_RESULT ' + json.dumps(report)], **kwargs)
            fake = types.SimpleNamespace(stop_process=runtime.stop_process, disconnected=lambda c: False)
            detail = {}
            try:
                with patch.object(artifacts.subprocess, 'Popen', side_effect=start):
                    if name == 'valid':
                        self.assertEqual(artifacts.supervise(fake, ['NO-QEMU'], scratch, scratch / 'serial.log', None,
                            time.monotonic() + 5, 'a' * 32, observed.append, sink, detail), 0)
                        self.assertEqual(detail['build_exit_code'], 0)
                    else:
                        with self.assertRaises(ValueError): artifacts.supervise(fake, ['NO-QEMU'], scratch,
                            scratch / 'serial.log', None, time.monotonic() + 5, 'a' * 32, observed.append, sink, detail)
                self.assertEqual(len(observed), 1)
                self.assertFalse((scratch / 'release.sock').exists())
                self.assertLess((scratch / 'serial.log').stat().st_size, 16384)
            finally: sink.close()

    def test_vm_failure_keeps_partial_receipt_and_unknown_cleanup_separate(self):
        state = self.root / 'state'; state.mkdir()
        config = dict(code_dir=str(WORKER.parents[1]), state_dir=str(state), base_image=str(self.root / 'base'))
        (self.root / 'base').write_bytes(b'base')
        connection = types.SimpleNamespace(settimeout=lambda value: None)
        limits = {'memory.max': str(6 * 1024**3), 'memory.swap.max': '0', 'pids.max': '64'}
        fd = os.open(self.root / 'fixture-lock', os.O_RDWR | os.O_CREAT, 0o600)
        c = copy.deepcopy(contract.contract()); c['base_image_sha256'] = contract.sha(self.root / 'base')
        def payload(conn, target, request, deadline): target.write_bytes(b'opaque fixture media')
        with patch.object(worker, 'admitted', return_value='fixed-helper-identity'), patch.object(runtime, 'acquire', return_value=fd), \
             patch.object(runtime, 'ready', return_value={'exit_code': 0}), patch.object(runtime, 'resource_state', return_value=limits), \
             patch.object(runtime, 'invocation', return_value='fixture'), patch.object(runtime, 'root_file', side_effect=Path), \
             patch.object(runtime, 'receive_payload', side_effect=payload), patch.object(runtime, 'tool'), \
             patch('shutil.disk_usage', return_value=types.SimpleNamespace(free=60 * 1024**3)), \
             patch.object(worker, 'contract', return_value=c), patch.object(artifacts, 'supervise', side_effect=runtime.CleanupError('fixture')):
            result = worker.run(config, connection, contract.request())
        self.assertEqual(result['exit_code'], 2)
        self.assertFalse(result['cleanup_complete'])
        self.assertFalse(result['release_export']['complete'])
        self.assertNotIn('build_exit_code', result['guest'])
        self.assertTrue((state / 'active.json').exists())
        self.assertTrue((Path(result['release_retained_directory']) / 'worker-receipt.json').exists())

    def test_baseline_overlay_changes_only_hook_and_inventory(self):
        original = {'validation/worker/runtime.py': ("def request():\n" + package.HOOK_BEFORE + '        pass\n').encode(),
            'integration-release.json': json.dumps(dict(source_commit='a' * 40, files={'validation/worker/runtime.py': {'bytes': 1, 'sha256': 'old'}})).encode(),
            'retained-helper': b'unchanged historical bytes'}
        out = package.overlay(original, {'new-helper': b'new'}, 'b' * 40)
        self.assertEqual(out['retained-helper'], original['retained-helper'])
        self.assertEqual(out['validation/worker/runtime.py'].replace(package.HOOK.encode(), b''), original['validation/worker/runtime.py'])
        self.assertEqual(json.loads(out['integration-release.json'])['files']['validation/worker/runtime.py']['sha256'],
            hashlib.sha256(out['validation/worker/runtime.py']).hexdigest())
        with self.assertRaises(ValueError): package.overlay(out, {}, 'b' * 40)

    def test_bounds_refuse_before_large_allocation(self):
        sink = artifacts.Sink(self.root / 'sink')
        try:
            with self.assertRaises(ValueError): sink.accept(dict(kind='begin', binding=contract.binding('a' * 32), bytes=artifacts.TAR_LIMIT + 1, sha256='a' * 64))
        finally: sink.close()
        for name in ('bin/zone', 'metadata/CMakeCache.txt', 'logs/build.log'):
            path = self.root / name.replace('/', '-')
            entry = tarfile.TarInfo(name); entry.uid = 0; entry.gid = 0; entry.mode = 0o755 if name.startswith('bin/') else 0o600
            entry.size = artifacts.file_caps()[name] + 1
            path.write_bytes(entry.tobuf(format=tarfile.USTAR_FORMAT) + b'\0' * 1024)
            with self.assertRaises(ValueError): artifacts.validate_tar(path, contract.binding('a' * 32))

    def test_owned_engine_stop_timeout_and_signal_sequence(self):
        # Actual helper branches for normal and forced termination, no engine executable.
        process = types.SimpleNamespace(pid=123, poll=lambda: None, wait=unittest.mock.Mock(side_effect=[subprocess.TimeoutExpired('fixture', 10), 0]))
        def kill(pid, sig):
            if sig == 0: raise ProcessLookupError()
        with patch.object(guest.os, 'killpg', side_effect=kill) as signals:
            self.assertTrue(guest.stop_owned(process))
            self.assertEqual([args.args[1] for args in signals.call_args_list], [15, 9, 0])

    def test_real_fixed_command_helper_timeout_and_output_limit(self):
        # Only harmless trusted Python fixture commands, no compiler/engine/candidate code.
        with self.assertRaises(TimeoutError): container.run([sys.executable, '-c', 'import time; time.sleep(5)'], seconds=.01)
        with self.assertRaises(ValueError): container.run([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(b"x"*(9*1024**2))'])
        with self.assertRaises(container.CommandFailure) as error: container.run([sys.executable, '-c', 'raise SystemExit(7)'])
        self.assertEqual(error.exception.code, 7)

    def test_replaced_sink_file_cannot_ack(self):
        path = archive(self.root); sink = artifacts.Sink(self.root / 'sink')
        try:
            for frame in artifacts.frames(path, contract.binding('a' * 32)): sink.accept(frame)
            artifact = sink.directory / 'release.tar'
            artifact.unlink(); artifact.write_bytes(path.read_bytes())
            with self.assertRaises(ValueError): sink.ack()
        finally: sink.close()

    def test_fixed_oci_graph_and_blob_digest_guards(self):
        config = dict(architecture='amd64', os='linux', rootfs={'diff_ids': ['sha256:' + 'd' * 64]})
        config_raw = contract.canonical(config); config_id = hashlib.sha256(config_raw).hexdigest()
        layer = b'fixture layer data'; layer_id = hashlib.sha256(layer).hexdigest()
        manifest = {'config': {'digest': 'sha256:' + config_id}, 'layers': [{'digest': 'sha256:' + layer_id}]}
        manifest_raw = contract.canonical(manifest); manifest_id = hashlib.sha256(manifest_raw).hexdigest()
        index_raw = contract.canonical({'manifests': [{'digest': 'sha256:' + manifest_id}]})
        index_id = hashlib.sha256(index_raw).hexdigest()
        rows = {'oci-layout': contract.canonical({'imageLayoutVersion': '1.0.0'}),
            'index.json': contract.canonical({'manifests': [{'digest': 'sha256:' + index_id}]}),
            'manifest.json': contract.canonical([{'Config': 'blobs/sha256/' + config_id, 'Layers': ['blobs/sha256/' + layer_id]}]),
            'blobs/sha256/' + config_id: config_raw, 'blobs/sha256/' + manifest_id: manifest_raw,
            'blobs/sha256/' + index_id: index_raw, 'blobs/sha256/' + layer_id: layer}
        c = copy.deepcopy(contract.contract()); pins = c['combined_manifest']['preserved_bindings']
        pins.update(builder_OCI_index='sha256:' + index_id, builder_amd64_manifest='sha256:' + manifest_id, builder_config='sha256:' + config_id)
        for bad in (False, True):
            path = self.root / ('bad-oci.tar' if bad else 'oci.tar')
            with tarfile.open(path, 'w') as stream:
                for name, raw in rows.items():
                    if bad and name.endswith(layer_id): raw += b'changed'
                    entry = tarfile.TarInfo(name); entry.size = len(raw); stream.addfile(entry, io.BytesIO(raw))
            with patch.object(guest, 'contract', return_value=c), patch.object(guest, 'IMAGE', 'sha256:' + config_id):
                if bad:
                    with self.assertRaisesRegex(ValueError, 'blob-digest'): guest.builder_config(path)
                else: self.assertEqual(guest.builder_config(path), config)

    def test_actual_request_dispatch_keeps_old_build_schema(self):
        config = {'submitter': pwd.getpwuid(os.getuid()).pw_name}
        def invoke(request):
            a, b = socket.socketpair()
            try:
                a.sendall(contract.canonical(request) + b'\n')
                return runtime.request(b, config)
            finally: a.close(); b.close()
        with patch.object(worker, 'run', return_value={'fixture': True}) as fixed, patch.object(runtime, 'run_vm') as old:
            self.assertEqual(invoke(contract.request()), {'fixture': True})
            fixed.assert_called_once()
            with self.assertRaises(ValueError): invoke(dict(contract.request(), operation='build'))
            old.assert_not_called()
        with patch.object(runtime, 'ready', return_value={'fixture': 'old readiness'}) as ready:
            self.assertEqual(invoke({'version': 1, 'operation': 'check'}), {'fixture': 'old readiness'})
            ready.assert_called_once()

    def test_actual_configuration_gate_requires_lua_perl_rust_and_no_sanitizer(self):
        cache = 'CMAKE_BUILD_TYPE:STRING=RelWithDebInfo\nEQEMU_BUILD_LUA:BOOL=ON\nEQEMU_BUILD_PERL:BOOL=ON\n'
        commands = [{'file': '/fixed/source/zone/actor_population.cpp', 'arguments': ['clang++', '-DEQEMU_RUST_BOOTSTRAP_BRIDGE', '-c', 'actor_population.cpp']}]
        container.check_configuration(cache, commands)
        with self.assertRaises(ValueError): container.check_configuration(cache.replace('PERL:BOOL=ON', 'PERL:BOOL=OFF'), commands)
        with self.assertRaises(ValueError): container.check_configuration(cache, [dict(commands[0], arguments=['clang++'])])
        with self.assertRaises(ValueError): container.check_configuration(cache + '-fsanitize=address', commands)

    def test_both_actual_cli_help_entrypoints_under_isolated_python(self):
        for path in (WORKER / 'prepare_staging_release.py', WORKER.parents[1] / 'scripts/build-staging-release'):
            result = subprocess.run([sys.executable, '-I', '-B', str(path), '--help'], capture_output=True, check=True)
            self.assertIn(b'--media', result.stdout)


if __name__ == '__main__': unittest.main()
