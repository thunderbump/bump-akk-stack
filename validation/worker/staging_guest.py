"""Fixed release launcher, executed only by cloud-init inside the offline VM."""
import hashlib
import base64
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import select
import signal
import subprocess
import sys
import tarfile
import time

import build_guest
from staging_release import binding, canonical, contract, sha, validate_storage, verify_inputs

ROOT = Path('/opt/eqemu-build')
MEDIA = Path('/media/eqemu-release')
IMAGE = 'sha256:fb6cfbccbb01c8ae0a7dea09b948ae5692c4f89102fce0c7da0bd32a2e17f1ad'


def daemon_config():
    return {'data-root': str(ROOT / 'docker'), 'exec-root': str(ROOT / 'docker-run'),
        'pidfile': str(ROOT / 'dockerd.pid'), 'hosts': ['unix://' + str(ROOT / 'docker.sock')],
        'storage-driver': 'overlay2', 'features': {'containerd-snapshotter': False},
        'bridge': 'none', 'iptables': False, 'ip6tables': False, 'ip-forward': False,
        'ip-masq': False, 'userland-proxy': False, 'log-driver': 'none',
        'containerd': str(ROOT / 'containerd.sock')}


def extract(archive, target, *, limit=3 * 1024**3, engine=None):
    """Guest extraction is finite and rejects duplicates, escapes and special files."""
    target.mkdir(parents=True, exist_ok=False)
    seen = set(); total = 0
    with tarfile.open(archive) as source:
        for member in source:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or '..' in name.parts or member.name in seen or member.issparse()
                    or not (member.isfile() or member.isdir() or member.issym()) or member.islnk()):
                raise ValueError('release-archive-member')
            seen.add(member.name); total += member.size
            if total > limit or len(seen) > 50000: raise ValueError('release-archive-bound')
            if member.issym():
                resolved = (target / member.name).parent.joinpath(member.linkname).resolve()
                if not resolved.is_relative_to(target.resolve()): raise ValueError('release-archive-link')
            if engine is not None:
                entry = engine.get(member.name)
                if entry is None or member.size != entry['bytes'] or member.mode != int(entry['mode'], 8):
                    raise ValueError('release-engine-member')
                if not (member.isfile() if entry['type'] == 'file' else member.isdir()):
                    raise ValueError('release-engine-type')
            source.extract(member, target, filter='data')
            if engine is not None and member.isfile() and sha(target / member.name) != entry['sha256']:
                raise ValueError('release-engine-digest')
    if engine is not None and seen != set(engine): raise ValueError('release-engine-incomplete')


def container_args():
    args = ['run', '--name', 'eqemu-fixed-release', '--network=none', '--read-only',
            '--cpus=2', '--memory=3g', '--memory-swap=3g', '--pids-limit=64',
            '--cap-drop=ALL', '--security-opt=no-new-privileges', '--entrypoint=/usr/bin/python3',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=268435456']
    for source, target in ((ROOT / 'source', ROOT / 'source'), (ROOT / 'native/vcpkg_installed', Path('/opt/eqemu-deps')),
                           (ROOT / 'rust/toolchain', ROOT / 'rust/toolchain'), (ROOT / 'rust/vendor', ROOT / 'rust/vendor'),
                           (MEDIA, ROOT / 'media'), (ROOT / 'helpers', Path('/opt/release-helper')),
                           (ROOT / 'run-id', ROOT / 'run-id')):
        args += ['--mount', f'type=bind,src={source},dst={target},readonly']
    for name in ('build', 'rust/home', 'rust/target'):
        args += ['--mount', f'type=bind,src={ROOT / name},dst={ROOT / name}']
    # Only the output parent is writable. The container helper uses this fixed alias.
    args += ['--mount', f'type=bind,src={ROOT / "release-output"},dst=/opt/release-output']
    environment = {'PATH': str(ROOT / 'rust/toolchain/bin') + ':/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        'HOME': '/tmp', 'LANG': 'C.UTF-8', 'CARGO_HOME': str(ROOT / 'rust/home'),
        'CARGO_TARGET_DIR': str(ROOT / 'rust/target'), 'CARGO_NET_OFFLINE': 'true',
        'CARGO_BUILD_JOBS': '1', 'CARGO_INCREMENTAL': '0', 'RUSTC_WRAPPER': '', 'RUSTC_WORKSPACE_WRAPPER': '',
        'CC': 'clang', 'CXX': 'clang++', 'CFLAGS': '', 'CXXFLAGS': '', 'LDFLAGS': '',
        'RUSTC': str(ROOT / 'rust/toolchain/bin/rustc'), 'RUSTDOC': str(ROOT / 'rust/toolchain/bin/rustdoc'),
        'CARGO': str(ROOT / 'rust/toolchain/bin/cargo'), 'VCPKG_ROOT': str(ROOT / 'source/submodules/vcpkg'),
        'RUSTFLAGS': '', 'CMAKE_BUILD_PARALLEL_LEVEL': '1', 'CCACHE_DISABLE': '1',
        'VCPKG_DISABLE_METRICS': '1', 'VCPKG_BINARY_SOURCES': 'clear',
        'X_VCPKG_ASSET_SOURCES': 'clear;x-block-origin', 'PYTHONDONTWRITEBYTECODE': '1'}
    for key, value in sorted(environment.items()): args += ['--env', key + '=' + value]
    return [*args, IMAGE, '/opt/release-helper/staging_container.py']


def builder_config(archive):
    """Validate the fixed OCI graph before asking the engine to import it."""
    pins = contract()['combined_manifest']['preserved_bindings']
    index_id = pins['builder_OCI_index'].removeprefix('sha256:')
    manifest_id = pins['builder_amd64_manifest'].removeprefix('sha256:')
    config_id = pins['builder_config'].removeprefix('sha256:')
    metadata = {}
    with tarfile.open(archive, 'r:') as source:
        seen = set()
        for member in source:
            if member.name in seen or member.pax_headers or len(seen) >= 64 or not (member.isfile() or member.isdir()):
                raise ValueError('release-oci-members')
            seen.add(member.name)
            if member.isdir():
                if member.name not in ('blobs', 'blobs/sha256'): raise ValueError('release-oci-directory')
                continue
            if member.name in ('oci-layout', 'index.json', 'manifest.json'):
                if member.size > 65536: raise ValueError('release-oci-metadata')
                metadata[member.name] = json.load(source.extractfile(member))
                continue
            parts = member.name.split('/')
            if len(parts) != 3 or parts[:2] != ['blobs', 'sha256'] or len(parts[2]) != 64:
                raise ValueError('release-oci-path')
            with source.extractfile(member) as stream:
                if parts[2] in (index_id, manifest_id, config_id):
                    if member.size > 1024**2: raise ValueError('release-oci-metadata')
                    raw = stream.read(); metadata[parts[2]] = json.loads(raw)
                    digest = hashlib.sha256(raw).hexdigest()
                else:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if digest != parts[2]: raise ValueError('release-oci-blob-digest')
    if not {index_id, manifest_id, config_id} <= set(metadata): raise ValueError('release-oci-closure')
    if metadata.get('oci-layout') != {'imageLayoutVersion': '1.0.0'}:
        raise ValueError('release-oci-layout')
    if not any(e.get('digest') == 'sha256:' + index_id for e in metadata.get('index.json', {}).get('manifests', [])):
        raise ValueError('release-oci-root-index')
    if not any(e.get('digest') == 'sha256:' + manifest_id for e in metadata[index_id].get('manifests', [])):
        raise ValueError('release-oci-platform-binding')
    if metadata[manifest_id].get('config', {}).get('digest') != IMAGE:
        raise ValueError('release-oci-config-binding')
    legacy = metadata.get('manifest.json', [])
    if (len(legacy) != 1 or legacy[0].get('Config') != 'blobs/sha256/' + config_id
            or legacy[0].get('Layers') != ['blobs/sha256/' + e['digest'].removeprefix('sha256:')
                                          for e in metadata[manifest_id]['layers']]):
        raise ValueError('release-oci-legacy-binding')
    config = metadata[config_id]
    if config.get('architecture') != 'amd64' or config.get('os') != 'linux':
        raise ValueError('release-oci-platform')
    return config


def stop_owned(process):
    if process is None: return True
    try:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=10)
        try: os.killpg(process.pid, 0)
        except ProcessLookupError: return True
        return False
    except (OSError, subprocess.TimeoutExpired):
        return False


def main():
    run_id = Path('/opt/eqemu-worker-nonce').read_text().strip()
    fixed = binding(run_id)
    report = dict(version=1, nonce=run_id, scope='staging-build-export', exit_code=2,
                  build_exit_code=None, native_cleanup=None, container_cleanup=None,
                  engine_cleanup=None, guest_export_complete=False, container_exit_code=None,
                  stage='input-verification')
    daemon = None; containerd = None; docker = None; daemon_log = None
    container_requested = False
    try:
        ROOT.mkdir(mode=0o700); MEDIA.mkdir(mode=0o700)
        build_guest.DEADLINE = time.monotonic() + 17900
        build_guest.command('mount-release-inputs', ['mount', '-o', 'ro,nosuid,nodev', '/dev/sr1', str(MEDIA)])
        verify_inputs(MEDIA)
        (ROOT / 'run-id').write_text(run_id)
        report['stage'] = 'guest-storage'
        # Guest-local evidence only. Actual OverlayFS mount/daemon gate follows this check.
        if not Path('/sys/fs/cgroup/cgroup.controllers').is_file(): raise ValueError('release-cgroup-v2-required')
        build_guest.command('overlay-module', ['modprobe', 'overlay'])
        build_guest.command('virtio-export-module', ['modprobe', 'virtio_console'])
        if 'overlay' not in Path('/proc/filesystems').read_text().split(): raise ValueError('release-overlay-unavailable')
        filesystem = build_guest.command('guest-backing-fs', ['findmnt', '-n', '-o', 'FSTYPE', '-T', str(ROOT)]).strip()
        if filesystem != 'ext4': raise ValueError('release-backing-filesystem')
        budget = json.loads((MEDIA / 'OVERLAY2-PEAK-STORAGE-BUDGET.json').read_bytes())
        if shutil.disk_usage(ROOT).free < budget['modeled_peak_with_reserve_bytes']:
            raise ValueError('release-guest-disk-space')
        engine = json.loads((MEDIA / 'ENGINE-MEMBER-INVENTORY.json').read_bytes())
        extract(MEDIA / 'docker-29.9.3.tgz', ROOT / 'engine', limit=235683676,
                engine={e['name']: e for e in engine['members']})
        binaries = ROOT / 'engine/docker'
        build_guest.ENV['PATH'] = str(binaries) + ':' + build_guest.ENV['PATH']
        docker = [str(binaries / 'docker'), '--host', 'unix://' + str(ROOT / 'docker.sock')]
        daemon_log = open(os.devnull, 'wb')
        containerd = subprocess.Popen([str(binaries / 'containerd'), '--root', str(ROOT / 'containerd'),
            '--state', str(ROOT / 'containerd-run'), '--address', str(ROOT / 'containerd.sock')],
            env=build_guest.ENV, stdin=subprocess.DEVNULL, stdout=daemon_log, stderr=daemon_log, start_new_session=True)
        config = ROOT / 'daemon.json'; config.write_bytes(canonical(daemon_config()))
        daemon = subprocess.Popen([str(binaries / 'dockerd'), '--config-file', str(config)],
            env=build_guest.ENV, stdin=subprocess.DEVNULL, stdout=daemon_log, stderr=daemon_log, start_new_session=True)
        # Bounded startup wait only. A failed daemon never selects another backend.
        for _ in range(60):
            if daemon.poll() is not None or containerd.poll() is not None: raise ValueError('release-engine-start')
            try:
                info = json.loads(build_guest.command('engine-storage', [*docker, 'info', '--format', '{{json .}}'], seconds=2))
                break
            except Exception:
                time.sleep(.5)
        else: raise ValueError('release-engine-start-timeout')
        validate_storage(info, filesystem)
        report['storage'] = {'driver': info['Driver'], 'backing_filesystem': filesystem}
        report['stage'] = 'image-import'
        expected_image = builder_config(MEDIA / 'builder-image.tar')
        build_guest.command('load-pinned-builder', [*docker, 'load', '--input', str(MEDIA / 'builder-image.tar')], seconds=900)
        image = json.loads(build_guest.command('inspect-pinned-builder', [*docker, 'image', 'inspect', IMAGE]))
        if (len(image) != 1 or image[0]['Id'] != IMAGE or image[0]['Architecture'] != 'amd64'
                or image[0].get('RootFS', {}).get('Layers') != expected_image['rootfs']['diff_ids']):
            raise ValueError('release-builder-identity')
        extract(MEDIA / 'source.tar', ROOT / 'source')
        if sha(ROOT / 'source/rust/actors/Cargo.lock') != contract()['combined_manifest']['preserved_bindings']['Cargo_lock_sha256']:
            raise ValueError('release-cargo-lock')
        for name, relative in (('websocketpp', 'submodules/websocketpp'), ('vcpkg', 'submodules/vcpkg')):
            dest = ROOT / 'source' / relative
            if dest.exists(): dest.rmdir()
            extract(MEDIA / (name + '.tar'), dest)
        extract(MEDIA / 'native-dependencies.tar', ROOT / 'native')
        native = json.loads((MEDIA / 'NATIVE-DEPENDENCIES-MANIFEST.json').read_bytes())
        expected = {e['path']: e for e in native['entries']}
        observed = {p.relative_to(ROOT / 'native').as_posix() for p in (ROOT / 'native').rglob('*')}
        if observed != set(expected): raise ValueError('release-native-inventory')
        for name, entry in expected.items():
            path = ROOT / 'native' / name
            if entry['type'] == 'file' and (path.is_symlink() or sha(path) != entry['sha256']): raise ValueError('release-native-bytes')
            if entry['type'] == 'directory' and (path.is_symlink() or not path.is_dir()): raise ValueError('release-native-directory')
            if entry['type'] == 'symlink' and (not path.is_symlink() or os.readlink(path) != entry['target']):
                raise ValueError('release-native-link')
        build_guest.WORK = ROOT
        # Reuse the exact offline installer, with its fixed /media/eqemu-input operand.
        Path('/media/eqemu-input').symlink_to(MEDIA, target_is_directory=True)
        build_guest.prepare_rust()
        for name in ('build', 'rust/target', 'release-output'): (ROOT / name).mkdir()
        helpers = ROOT / 'helpers'; helpers.mkdir()
        from staging_release import HELPERS
        for name in HELPERS:
            if name != 'staging_worker.py': shutil.copyfile(Path('/opt') / name, helpers / name)
        report['stage'] = 'six-target-build'
        container_requested = True
        try:
            build_guest.command('staging-container', [*docker, *container_args()], seconds=16000)
            report['build_exit_code'] = 0
        except Exception:
            raise
        report['stage'] = 'release-validation'
        from release_artifacts import validate_tar
        validate_tar(ROOT / 'release-output/release.tar', fixed)
        report['exit_code'] = 0
    except Exception:
        report['error'] = 'fixed-release-stage-failed'
    finally:
        if container_requested:
            try:
                observed = json.loads(build_guest.command('owned-container-exit', [*docker, 'inspect', '--format', '{{json .State}}', 'eqemu-fixed-release'], seconds=10))
                if observed.get('Running') is False and type(observed.get('ExitCode')) is int:
                    report['container_exit_code'] = observed['ExitCode']
                detail_path = ROOT / 'release-output/container-result.json'
                if detail_path.is_file() and detail_path.stat().st_size <= 8192:
                    report['checks'] = json.loads(detail_path.read_bytes())
                    if report['checks']['checks'].get('native-build') == 0:
                        report['native_build_exit_code'] = 0
                    elif report['checks'].get('failed_check') == 'native-build':
                        report['native_build_exit_code'] = report['checks'].get('failed_exit_code')
            except Exception:
                pass  # Missing observation stays unknown; it cannot make this operation pass.
            try:
                build_guest.command('remove-owned-container', [*docker, 'rm', '--force', 'eqemu-fixed-release'], seconds=30)
                names = build_guest.command('confirm-no-container', [*docker, 'ps', '-aq'], seconds=10).strip()
                report['container_cleanup'] = not names
                report['native_cleanup'] = not names
            except Exception:
                report['container_cleanup'] = False
        else:
            report['container_cleanup'] = 'not-run'; report['native_cleanup'] = 'not-run'
        daemon_stopped = stop_owned(daemon)
        containerd_stopped = stop_owned(containerd)
        report['engine_cleanup'] = daemon_stopped and containerd_stopped
        if daemon_log is not None: daemon_log.close()
        if not (report['container_cleanup'] is True and report['engine_cleanup'] is True): report['exit_code'] = 2
        if report['exit_code'] == 0 and (report.get('container_exit_code') != 0 or report.get('native_build_exit_code') != 0
                or report.get('checks', {}).get('checks') != {name: 0 for name in (
                    'rust-format', 'rust-dependencies', 'rust-clippy', 'rust-tests', 'rust-doctests',
                    'native-configure', 'native-build', 'artifact-checks')}):
            report['exit_code'] = 2
    if report['exit_code'] != 0:
        # Fixed bounded build logs survive VM teardown in the existing capped serial log.
        # Encoding prevents candidate text from masquerading as a completion record.
        for name in ('configure', 'build', 'rust-checks', 'artifact-checks'):
            path = ROOT / 'release-output/release/logs' / (name + '.log')
            if path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024**2:
                with path.open('rb') as stream:
                    while block := stream.read(3072):
                        print('EQEMU_RELEASE_BUILD_LOG ' + name + ' ' + base64.b64encode(block).decode(), flush=True)
    if report['exit_code'] == 0:
        try:
            from release_artifacts import frames, wire
            # A dedicated virtio port avoids the console UART and existing artifact/log limits.
            fd = os.open('/dev/virtio-ports/eqemu-release', os.O_WRONLY | os.O_NONBLOCK)
            try:
                deadline = min(build_guest.DEADLINE, time.monotonic() + 900)
                for frame in frames(ROOT / 'release-output/release.tar', fixed):
                    block = memoryview(wire(frame))
                    while block:
                        if time.monotonic() >= deadline: raise TimeoutError('release-export-timeout')
                        if select.select([], [fd], [], .2)[1]:
                            try: block = block[os.write(fd, block):]
                            except BlockingIOError: pass
            finally:
                os.close(fd)
            report['guest_export_complete'] = True
        except Exception:
            report['exit_code'] = 2; report['error'] = 'fixed-release-export-failed'
    print('EQEMU_WORKER_RESULT ' + canonical(report).decode(), flush=True)


if __name__ == '__main__':
    main()
