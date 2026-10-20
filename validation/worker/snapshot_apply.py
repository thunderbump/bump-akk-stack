"""Explicit caller-side application of a verified formatter artifact. No VM or tools."""
import base64
import contextlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import signal
import uuid

from snapshot import capture, canonical, sha, read_file, validate_result, RESULT_LIMIT

CANCEL_SIGNALS = {signal.SIGTERM, signal.SIGINT}


class ApplyCancelled(RuntimeError):
    pass


@contextlib.contextmanager
def defer_cancellation():
    """A pending signal is delivered after replacement and ownership agree."""
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, CANCEL_SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


@contextlib.contextmanager
def cancellation_handler():
    """The first cancellation enters rollback; further signals cannot interrupt it."""
    state = dict(recovering=False, cancelled=False)
    previous = {number: signal.getsignal(number) for number in CANCEL_SIGNALS}
    def cancel(number, _frame):
        already_cancelled = state['cancelled']
        state['cancelled'] = True
        if not state['recovering'] and not already_cancelled:
            raise ApplyCancelled('Formatter apply cancelled by signal ' + str(number))
    try:
        for number in CANCEL_SIGNALS:
            signal.signal(number, cancel)
        yield state
    finally:
        state['recovering'] = True
        for number, handler in previous.items():
            signal.signal(number, handler)


def parent_fd(root, name):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in PurePosixPath(name).parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def prepare_file(fd, data, mode):
    name = '.eqemu-format-' + uuid.uuid4().hex
    target = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(target, 'wb') as stream:
            stream.write(data); stream.flush(); os.fchmod(stream.fileno(), mode); os.fsync(stream.fileno())
        return name
    except BaseException:
        os.unlink(name, dir_fd=fd)
        raise


def current_bytes(fd, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > RESULT_LIMIT:
            raise ValueError('Apply target is no longer a bounded regular file')
        data = stream.read(RESULT_LIMIT + 1)
        if len(data) != info.st_size:
            raise ValueError('Apply target changed during read')
        return data, stat.S_IMODE(info.st_mode)


def apply_result(repo, base, artifact, identity, expected_input, publish_receipt=None):
    """CLI/main-thread entry point with cooperative SIGTERM/SIGINT recovery."""
    with cancellation_handler() as cancellation:
        return _apply_result(repo, base, artifact, identity, expected_input, publish_receipt, cancellation)


def _apply_result(repo, base, artifact, identity, expected_input, publish_receipt, cancellation):
    """Stage all bytes first. Roll back only writes still owned by this invocation."""
    from snapshot import FILE_LIMIT
    descriptor = os.open(artifact, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > RESULT_LIMIT:
            raise ValueError('Formatter artifact must be a bounded regular file')
        encoded = stream.read(RESULT_LIMIT + 1)
    if len(encoded) > RESULT_LIMIT:
        raise ValueError('Oversized formatter artifact')
    result = json.loads(encoded)
    snapshot = capture(repo, base, identity['recipe_sha256'])
    if sha(canonical(snapshot)) != expected_input:
        raise ValueError('Stale source snapshot; no changes applied')
    validate_result(result, snapshot, 'format', identity['implementation_sha256'])
    if result['exit_code'] != 0:
        raise ValueError('Only successful format results can be applied')
    pending = []
    try:
        for change in result['changed_files']:
            fd = parent_fd(repo, change['path'])
            name = PurePosixPath(change['path']).name
            item = dict(fd=fd, name=name, path=change['path'], installed=False)
            pending.append(item)
            original, mode = current_bytes(fd, name)
            if len(original) > FILE_LIMIT or sha(original) != change['before_sha256']:
                raise ValueError('Apply target changed; no changes applied')
            data = base64.b64decode(change['content_base64'], validate=True)
            item.update(original=original, formatted=data, mode=mode)
            with defer_cancellation():
                item['backup'] = prepare_file(fd, original, mode)
                item['replacement'] = prepare_file(fd, data, mode)
        if capture(repo, base, identity['recipe_sha256']) != snapshot:
            raise ValueError('Source changed while staging formatter output')
        for item in pending:
            if current_bytes(item['fd'], item['name']) != (item['original'], item['mode']):
                raise ValueError('Apply target changed before replacement')
            with defer_cancellation():
                os.replace(item['replacement'], item['name'], src_dir_fd=item['fd'], dst_dir_fd=item['fd'])
                item['installed'] = True
            os.fsync(item['fd'])
        actual = capture(repo, base, identity['recipe_sha256'])
        if sha(canonical(actual)) != result['output_snapshot_sha256']:
            raise ValueError('Source changed while applying formatter output')
        receipt = dict(version=1, scope='working-snapshot-apply', exit_code=0, base=base, head=snapshot['head'],
                    input_snapshot_sha256=expected_input, output_snapshot_sha256=result['output_snapshot_sha256'],
                    recipe_sha256=identity['recipe_sha256'], implementation_sha256=identity['implementation_sha256'],
                    applied_paths=[item['path'] for item in pending], vm_started=False)
        # Publication is the completion boundary. Do not roll back after a
        # successful receipt has claimed these exact source bytes.
        with defer_cancellation():
            if publish_receipt is not None:
                publish_receipt(receipt)
            cancellation['recovering'] = True
        return receipt
    except BaseException as original_error:
        cancellation['recovering'] = True
        uncertain = []
        for item in reversed(pending):
            if not item['installed']:
                continue
            try:
                # Preserve a newer edit rather than overwriting it during recovery.
                if current_bytes(item['fd'], item['name']) != (item['formatted'], item['mode']):
                    uncertain.append(item['path']); continue
                os.replace(item['backup'], item['name'], src_dir_fd=item['fd'], dst_dir_fd=item['fd'])
                os.fsync(item['fd'])
            except BaseException:
                uncertain.append(item['path'])
        if uncertain:
            raise RuntimeError('Apply failed; newer or uncertain files preserved: ' + ', '.join(uncertain)) from original_error
        raise
    finally:
        cancellation['recovering'] = True
        for item in pending:
            for kind in ('backup', 'replacement'):
                if kind in item:
                    try:
                        os.unlink(item[kind], dir_fd=item['fd'])
                    except FileNotFoundError:
                        pass
            os.close(item['fd'])


def publish(path, result, limit=RESULT_LIMIT):
    """A private fresh artifact; never replace an existing receipt or follow its link."""
    encoded = canonical(result) + b'\n'
    if len(encoded) > limit:
        raise ValueError('Formatter result size limit exceeded')
    directory = parent_fd('/', path.absolute().as_posix().lstrip('/'))
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
        except BaseException:
            os.unlink(path.name, dir_fd=directory)
            raise
    finally:
        os.close(directory)
