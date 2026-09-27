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


def regular_fd(path, expected_size=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or (expected_size is not None and info.st_size != expected_size):
        os.close(fd)
        raise ValueError('Artifact type or length mismatch')
    return fd


def hash_file(path, size, deadline):
    digest = hashlib.sha256()
    with os.fdopen(regular_fd(path, size), 'rb') as source:
        remaining = size
        while remaining:
            if time.monotonic() >= deadline:
                raise TimeoutError('Artifact hash deadline')
            block = source.read(min(BLOCK, remaining))
            if not block:
                raise ValueError('Truncated artifact')
            digest.update(block)
            remaining -= len(block)
        if source.read(1):
            raise ValueError('Artifact grew')
    return digest.hexdigest()


def copy_blob(source, target, size, expected, deadline):
    """Copy into a new owned file; remove only that file on any failure."""
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
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Artifact copy deadline')
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
                        for stream in (src, dst):
                            os.posix_fadvise(stream.fileno(), synced, copied - synced, os.POSIX_FADV_DONTNEED)
                        synced = copied
                if src.read(1) or digest.hexdigest() != expected:
                    raise ValueError('Artifact bytes changed')
                dst.flush()
                os.fsync(dst.fileno())
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
