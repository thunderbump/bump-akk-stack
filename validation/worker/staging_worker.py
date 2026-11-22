"""Fixed release operation using the exact admitted worker lifecycle primitives."""
import hashlib
import json
import os
from pathlib import Path
import time
import uuid

from staging_release import HELPERS, SELECTION, binding, canonical, contract, sha, validate_request, write_json


def user_data(nonce, helper_root):
    files = [dict(path='/opt/' + name, permissions='0600', content=(helper_root / name).read_text())
             for name in (*HELPERS, 'build_guest.py') if name != 'staging_worker.py']
    files.append(dict(path='/opt/eqemu-worker-nonce', permissions='0600', content=nonce))
    launcher = ('/usr/bin/systemctl mask --runtime --now serial-getty@ttyS0.service || exit 2\n'
                'exec >/dev/ttyS0 2>&1\n/usr/bin/python3 -B -u /opt/staging_guest.py\n'
                '/usr/sbin/poweroff\n')
    return '#cloud-config\n' + json.dumps(dict(hostname='eqemu-fixed-release', ssh_pwauth=False,
        disable_root=True, write_files=files, runcmd=[['/bin/sh', '-c', launcher]])) + '\n'


def admitted(runtime, config):
    """A separately root-admitted finite manifest is mandatory; source checkout is insufficient."""
    if config.get('selection') or config.get('diagnostic_profile'):
        raise ValueError('release-ordinary-policy-only')
    code = Path(config['code_dir'])
    policy = runtime.read_json(runtime.root_file(code / 'staging-release-policy.json'), 32768)
    if set(policy) != {'version', 'selection', 'config_sha256', 'files'} or policy['version'] != 1 or policy['selection'] != SELECTION:
        raise ValueError('release-admission-policy')
    from integration_artifacts import INSTALLED_FILES
    names = set(INSTALLED_FILES) | {'validation/worker/' + name for name in HELPERS}
    if set(policy['files']) != names:
        raise ValueError('release-admission-inventory')
    if sha(runtime.CONFIG) != policy['config_sha256']:
        raise ValueError('release-admission-config')
    for name, expected in policy['files'].items():
        path = code / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size != expected['bytes'] or sha(path) != expected['sha256']:
            raise ValueError('release-admission-closure')
    return hashlib.sha256(canonical(policy)).hexdigest()


def run(config, connection, request):
    """One locked, owned VM. Never retries submission, build, export or cleanup."""
    import runtime
    import release_artifacts
    validate_request(request)
    identity = admitted(runtime, config)
    lock = runtime.acquire(config)
    state = Path(config['state_dir']); run_id = uuid.uuid4().hex
    job = state / run_id; scratch = job / 'scratch'; sink = None
    report = dict(version=1, operation='staging-build-export', scope=SELECTION, run_id=run_id,
                  candidate=request['candidate'], tree=request['tree'], payload_sha256=request['sha256'],
                  implementation_sha256=identity, exit_code=2, vm_started=False, cleanup_complete=False,
                  guest={}, stage='active-work', release_export={'complete': False, 'client_ack': None})
    try:
        if (state / 'active.json').exists() or (state / 'active.json').is_symlink():
            raise ValueError('release-active-work')
        report['stage'] = 'host-readiness'
        report['readiness'] = runtime.ready(config)
        if report['readiness']['exit_code'] != 0: raise ValueError('release-worker-readiness')
        report['stage'] = 'host-resources'
        limits = runtime.resource_state()
        if (int(limits['memory.max']) != 6 * 1024**3 or limits['memory.swap.max'] != '0'
                or int(limits['pids.max']) != 64): raise ValueError('release-worker-caps')
        import shutil
        if shutil.disk_usage(state).free < 50 * 1024**3: raise ValueError('release-host-space')
        record = dict(run_id=run_id, invocation_id=runtime.invocation(), control='build', qemu_pid=None)
        runtime.atomic_json(state / 'active.json', record)
        job.mkdir(mode=0o700); scratch.mkdir(mode=0o700)
        sink = release_artifacts.Sink(job / 'release')
        deadline = time.monotonic() + runtime.BUILD_SECONDS
        report['stage'] = 'base-binding'
        base = runtime.root_file(config['base_image'])
        if sha(base) != contract()['base_image_sha256']: raise ValueError('release-base-image')
        report['stage'] = 'input-receive'
        runtime.receive_payload(connection, scratch / 'payload.iso', request, min(deadline, time.monotonic() + 300))
        report['stage'] = 'vm-prepare'
        (scratch / 'user-data').write_text(user_data(run_id, Path(config['code_dir']) / 'validation/worker'))
        (scratch / 'meta-data').write_text('instance-id: eqemu-release-' + run_id + '\n')
        runtime.tool([runtime.QEMU_IMG, 'create', '-q', '-f', 'qcow2', '-F', 'qcow2', '-b', str(base), str(scratch / 'disk.qcow2'), '48G'], deadline)
        runtime.tool([runtime.GENISOIMAGE, '-output', str(scratch / 'seed.iso'), '-volid', 'cidata', '-joliet', '-rock',
                      str(scratch / 'user-data'), str(scratch / 'meta-data')], deadline)
        args = [runtime.QEMU, '-no-user-config', '-nodefaults', '-machine', 'q35,accel=kvm', '-cpu', 'host',
            '-smp', '2', '-m', '4096', '-object', 'main-loop,id=main-loop,thread-pool-min=0,thread-pool-max=8',
            '-nic', 'none', '-display', 'none', '-monitor', 'none', '-serial', 'stdio', '-no-reboot',
            '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny',
            '-drive', 'file=' + str(scratch / 'disk.qcow2') + ',if=virtio,format=qcow2,cache=none',
            '-drive', 'file=' + str(scratch / 'seed.iso') + ',media=cdrom,readonly=on,format=raw',
            '-drive', 'file=' + str(scratch / 'payload.iso') + ',media=cdrom,readonly=on,format=raw']
        def started(pid):
            report['vm_started'] = True; report['qemu_pid'] = pid
            record['qemu_pid'] = pid; runtime.atomic_json(state / 'active.json', record)
        report['stage'] = 'guest-build-export'
        report['exit_code'] = release_artifacts.supervise(runtime, args, scratch, job / 'serial.log', connection,
            deadline, run_id, started, sink, report['guest'])
        report['stage'] = 'closure-recheck'
        if admitted(runtime, config) != identity: raise ValueError('release-implementation-changed')
    except Exception as error:
        report.update(exit_code=2, error='fixed-release-operation-failed')
        if isinstance(error, runtime.CleanupError): report['cleanup_error'] = 'owned-process-cleanup-unknown'
    finally:
        try:
            try:
                if 'cleanup_error' not in report:
                    if job.exists(): runtime.scratch_cleanup(job)
                    report['cleanup_complete'] = True
            except Exception:
                report.update(exit_code=2, cleanup_error='owned-scratch-cleanup-unknown')
            if sink is not None:
                try:
                    report['release_export'] = release_artifacts.export(sink, connection, report)
                    if not report['release_export']['complete']: report['exit_code'] = 2
                except Exception:
                    report.update(exit_code=2, release_export=dict(complete=False, client_ack=None,
                        guest_capture_complete=sink.complete, bytes=sink.total))
                finally:
                    sink.close()
                report['release_retained_directory'] = str(job / 'release')
                write_json(job / 'release' / 'worker-receipt.json', report)
            if job.exists(): runtime.atomic_json(state / 'last-result.json', report)
            active = state / 'active.json'
            if active.exists() and runtime.read_json(active).get('run_id') == run_id and report['cleanup_complete']:
                active.unlink()
        finally:
            os.close(lock)
    return report
