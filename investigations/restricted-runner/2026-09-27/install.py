#!/usr/bin/python3 -I
"""One reviewed installation; refuses upgrades and existing paths. No VM launch."""
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parent
BASE = Path('/var/lib/eqemu-test')
LIB = Path('/usr/local/lib/eqemu-test')
ENTRY = Path('/usr/local/sbin/eqemu-test-request')
CLIENT = Path('/usr/local/bin/eqemu-test')
POLICY = Path('/etc/sudoers.d/eqemu-test')
GROUP = 'eqemu-test'
PROOF_USER = 'eqemu-test-proof'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
RULE = '%eqemu-test ALL=(root) NOPASSWD: NOSETENV: /usr/local/sbin/eqemu-test-request ""\n'


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, env=ENV, cwd='/', timeout=30)


def parent_safe(path):
    for parent in reversed(Path(path).parents):
        s = parent.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise RuntimeError('Unsafe parent: ' + str(parent))


def regular_bytes(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        s = os.fstat(stream.fileno())
        if not stat.S_ISREG(s.st_mode) or s.st_size > maximum:
            raise RuntimeError('Unsafe package file')
        data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise RuntimeError('Package file grew')
        return data


def write(path, data, mode):
    with Path(path).open('xb') as stream:
        stream.write(data)
        os.fchmod(stream.fileno(), mode)


def make_dir(path, mode, group=0):
    Path(path).mkdir(mode=mode)
    os.chmod(path, mode)
    os.chown(path, 0, group)


def copy_input(source, target, identity):
    fd = os.open(source, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    deadline = time.monotonic() + 600
    with os.fdopen(fd, 'rb') as src:
        facts = os.fstat(src.fileno())
        if not stat.S_ISREG(facts.st_mode) or facts.st_size != identity['bytes']:
            raise RuntimeError('Input type/length changed')
        digest = hashlib.sha256()
        with target.open('xb') as dst:
            remaining = identity['bytes']
            while remaining:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Input copy deadline')
                block = src.read(min(1024 * 1024, remaining))
                if not block:
                    raise RuntimeError('Input truncated')
                dst.write(block)
                digest.update(block)
                remaining -= len(block)
            if src.read(1) or digest.hexdigest() != identity['sha256']:
                raise RuntimeError('Input bytes changed')
            dst.flush()
            os.fsync(dst.fileno())
            os.fchmod(dst.fileno(), 0o400)


def install():
    if os.geteuid() != 0:
        raise RuntimeError('Administrator installation requires sudo')
    os.umask(0o077)
    manifest_data = regular_bytes(SOURCE / 'manifest.json', 16384)
    manifest = json.loads(manifest_data)
    package = {}
    for name, digest in manifest['files'].items():
        if '/' in name or name in ('.', '..'):
            raise RuntimeError('Invalid package path')
        data = regular_bytes(SOURCE / name, 256 * 1024)
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError('Package changed: ' + name)
        package[name] = data
    # Installer itself is part of the manifest. Administrator reviews this package before invoking it.
    release = hashlib.sha256(manifest_data).hexdigest()[:16]
    version = LIB / release
    for path in (BASE, LIB, ENTRY, CLIENT, POLICY):
        parent_safe(path)
        if path.exists() or path.is_symlink():
            raise RuntimeError('Existing installation path; refuse overwrite: ' + str(path))
    try:
        grp.getgrnam(GROUP)
    except KeyError:
        pass
    else:
        raise RuntimeError('Existing submit group; refuse adopting it')
    try:
        pwd.getpwnam(PROOF_USER)
    except KeyError:
        pass
    else:
        raise RuntimeError('Existing proof account; refuse adopting it')
    pwd.getpwnam('bump')
    if shutil.disk_usage('/var/lib').free < 180 * 1024**3:
        raise RuntimeError('Installation requires 180 GiB free disk')
    inputs = json.loads(package['inputs.json'])
    if set(inputs) != {'base.qcow2', 'seed.iso', 'fixture.iso', 'runtime.iso'}:
        raise RuntimeError('Unexpected input manifest')
    if sum(item['bytes'] for item in inputs.values()) > 2 * 1024**3:
        raise RuntimeError('Installed input budget')
    # Create a private installation journal before any account or authorization changes.
    make_dir(BASE, 0o711)
    record = {'version': str(version), 'group_created': False, 'proof_user_created': False,
              'bump_added': False, 'enabled': False, 'manifest_sha256': hashlib.sha256(manifest_data).hexdigest()}
    def save():
        p = BASE / 'installation.json'
        p.write_text(json.dumps(record, indent=2) + '\n')
        p.chmod(0o600)
    save()
    try:
        make_dir(LIB, 0o755)
        make_dir(version, 0o755)
        for name, data in package.items():
            write(version / name, data, 0o644)
        write(version / 'manifest.json', manifest_data, 0o644)
        make_dir(BASE / 'inputs', 0o700)
        for name, identity in inputs.items():
            copy_input(identity['source'], BASE / 'inputs' / name, identity)
        make_dir(BASE / 'runs', 0o711)
        write(BASE / 'request.lock', b'', 0o600)
        run(['/usr/sbin/groupadd', '--system', GROUP])
        record['group_created'] = True
        save()
        group_id = grp.getgrnam(GROUP).gr_gid
        run(['/usr/sbin/useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent',
             '--shell', '/usr/sbin/nologin', '--gid', GROUP, PROOF_USER])
        record['proof_user_created'] = True
        save()
        make_dir(BASE / 'reports', 0o750, group_id)
        run(['/usr/sbin/usermod', '-a', '-G', GROUP, 'bump'])
        record['bump_added'] = True
        save()
        wrapper = '#!/bin/sh\n[ "$#" -eq 0 ] || exit 2\nexec /usr/bin/python3 -I ' + str(version / 'control.py') + '\n'
        write(ENTRY, wrapper.encode(), 0o755)
        write(CLIENT, package['client.py'], 0o755)
        draft = BASE / 'sudoers.checked'
        write(draft, RULE.encode(), 0o440)
        run(['/usr/sbin/visudo', '-cf', str(draft)])
        # Validate installed code, all input digests and generated domain/AppArmor syntax before permission is enabled.
        run(['/usr/bin/python3', '-I', str(version / 'preflight.py')])
        write(POLICY, RULE.encode(), 0o440)
        try:
            run(['/usr/sbin/visudo', '-c'])
        except Exception:
            POLICY.unlink()
            raise
        run(['/usr/bin/python3', '-I', str(version / 'probe.py')])
        record['enabled'] = True
        save()
        print(json.dumps({'installed': True, 'version': str(version), 'vm_started': False,
                          'next': 'Authorization checks passed. Ready for the separately requested diagnostic VM proof',
                          'rollback': 'sudo python3 -I ' + str(version / 'remove.py')}))
    except Exception:
        if POLICY.is_file() and not POLICY.is_symlink() and POLICY.read_bytes() == RULE.encode():
            POLICY.unlink()
        record['enabled'] = False
        save()
        print('Installation incomplete; no VM was launched. Retain installation.json and use the reviewed removal procedure.', file=sys.stderr)
        raise


if __name__ == '__main__':
    try:
        if len(sys.argv) != 1:
            raise RuntimeError('Installer takes no arguments')
        install()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
