"""Prepare complete source inputs as data, without host extraction or execution."""
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tarfile
import tempfile

SOURCE_LIMIT = 256 * 1024**2
MANIFEST_LIMIT = 1024**2
ARCHIVE_LIMIT = SOURCE_LIMIT + 16 * 1024**2


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def relative(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or str(path) != name
            or any(p in ('.', '..', '.git') for p in path.parts)):
        raise ValueError('Unsafe input path: ' + repr(name))
    return name


@contextlib.contextmanager
def regular(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError('Not a bounded regular file: ' + str(path))
        yield stream, info


def file_record(path, limit):
    with regular(path, limit) as (stream, info):
        hashed = hashlib.sha256()
        count = 0
        while block := stream.read(1024**2):
            count += len(block)
            if count > limit:
                raise ValueError('File grew beyond limit')
            hashed.update(block)
        if count != info.st_size:
            raise ValueError('File changed during read')
    return {'bytes': count, 'sha256': hashed.hexdigest()}


class GitTree:
    """Read objects through an empty Git configuration, never the candidate's hooks."""
    def __init__(self, repo, scratch):
        self.repo = Path(repo).resolve()
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(scratch), 'LANG': 'C.UTF-8',
                    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
                    'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_ATTR_NOSYSTEM': '1',
                    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_TERMINAL_PROMPT': '0',
                    'GIT_OPTIONAL_LOCKS': '0'}
        common = self.location('--git-common-dir')
        self.gitdir = Path(scratch) / 'view.git'
        self.run(['/usr/bin/git', 'init', '--bare', '--template=', str(self.gitdir)])
        self.env['GIT_OBJECT_DIRECTORY'] = str(Path(common) / 'objects')

    def run(self, argv, **kwargs):
        return subprocess.run(argv, env=self.env, check=True, stderr=subprocess.PIPE,
                              stdout=kwargs.pop('stdout', subprocess.PIPE), timeout=60, **kwargs).stdout

    def location(self, *arguments):
        # rev-parse reads repository metadata; it does not run hooks or filters.
        return self.run(['/usr/bin/git', '-C', str(self.repo), 'rev-parse',
                         '--path-format=absolute', *arguments]).decode().strip()

    def git(self, *args, **kwargs):
        return self.run(['/usr/bin/git', '--git-dir=' + str(self.gitdir), *args], **kwargs)

    def inventory(self, commit, tree):
        if self.git('rev-parse', commit + '^{tree}').decode().strip() != tree:
            raise ValueError('Candidate tree mismatch')
        entries, links = [], {}
        for record in self.git('ls-tree', '--full-tree', '-rlz', commit).split(b'\0'):
            if not record:
                continue
            meta, path = record.split(b'\t', 1)
            mode, kind, blob, size = meta.decode().split()
            name = relative(path.decode())
            if mode == '160000':
                links[name] = blob
            elif mode in ('100644', '100755') and kind == 'blob':
                entries.append(dict(path=name, mode=mode, blob=blob, bytes=int(size)))
            else:
                raise ValueError('Unsupported Git entry: ' + name)
        if len(entries) > 10000 or sum(e['bytes'] for e in entries) > SOURCE_LIMIT:
            raise ValueError('Source inventory exceeds budget')
        return entries, links

    def archive(self, commit, destination):
        with destination.open('xb') as output:
            self.git('archive', '--format=tar', commit, stdout=output)

    def clean(self, commit, entries, links):
        # Raw bytes avoid worktree attribute/filter normalization hiding changes.
        if self.location('HEAD') != commit:
            raise ValueError('Source HEAD mismatch')
        expected = {e['path']: e for e in entries}
        # Inspect a bounded index snapshot through the isolated Git view. Reading
        # raw checkout bytes alone misses staged edits whose worktree was restored.
        index = Path(self.location('--git-path', 'index'))
        snapshot = self.gitdir / 'candidate-index'
        with regular(index, 16 * 1024**2) as (stream, _):
            data = stream.read(16 * 1024**2 + 1)
        if len(data) > 16 * 1024**2:
            raise ValueError('Index exceeds budget')
        snapshot.write_bytes(data)
        self.env['GIT_INDEX_FILE'] = str(snapshot)
        try:
            staged = {}
            for record in self.git('ls-files', '--stage', '-z').split(b'\0'):
                if not record:
                    continue
                meta, path = record.split(b'\t', 1)
                mode, blob, stage = meta.decode().split()
                name = path.decode()
                if stage != '0' or name in staged:
                    raise ValueError('Unmerged source index')
                staged[name] = (mode, blob)
        finally:
            del self.env['GIT_INDEX_FILE']
            snapshot.unlink()
        expected_index = {e['path']: (e['mode'], e['blob']) for e in entries}
        expected_index.update({path: ('160000', commit) for path, commit in links.items()})
        if staged != expected_index:
            raise ValueError('Dirty source index')
        found = set()
        for parent, dirs, files in os.walk(self.repo, followlinks=False):
            rel = Path(parent).relative_to(self.repo)
            for name in list(dirs):
                path = (rel / name).as_posix()
                if rel == Path('.') and name == '.git':
                    dirs.remove(name)
                elif path in links:
                    if (Path(parent) / name).is_symlink():
                        raise ValueError('Symlink submodule')
                    dirs.remove(name)
                elif (Path(parent) / name).is_symlink():
                    raise ValueError('Untracked or symlink directory: ' + path)
            for name in files:
                if rel == Path('.') and name == '.git':
                    continue
                path = (rel / name).as_posix()
                if path not in expected:
                    raise ValueError('Untracked source file: ' + path)
                entry = expected[path]
                with regular(self.repo / path, entry['bytes']) as (stream, info):
                    if bool(info.st_mode & 0o111) != (entry['mode'] == '100755'):
                        raise ValueError('Dirty executable mode: ' + path)
                    hashed = hashlib.sha1(('blob ' + str(entry['bytes']) + '\0').encode())
                    hashed.update(stream.read(entry['bytes'] + 1))
                    if info.st_size != entry['bytes'] or hashed.hexdigest() != entry['blob']:
                        raise ValueError('Dirty source bytes: ' + path)
                found.add(path)
        if found != set(expected):
            raise ValueError('Missing tracked source file')


def verify_archive(path, entries, links):
    """Check archive members without materializing any candidate path on the host."""
    expected = {e['path']: e for e in entries}
    if len(expected) != len(entries):
        raise ValueError('Duplicate inventory path')
    directories = set(links)
    for name in (*expected, *links):
        relative(name)
        directories.update(str(p) for p in PurePosixPath(name).parents if str(p) != '.')
    found, dirs, verified = set(), set(), []
    with regular(path, ARCHIVE_LIMIT) as (stream, _):
        with tarfile.open(fileobj=stream, mode='r:') as archive:
            for member in archive:
                name = relative(member.name.rstrip('/') if member.isdir() else member.name)
                if member.isdir():
                    if name not in directories or name in dirs:
                        raise ValueError('Unexpected or duplicate archive directory')
                    dirs.add(name)
                    continue
                if not member.isfile() or name not in expected or name in found:
                    raise ValueError('Unexpected, duplicate or non-regular archive member: ' + name)
                entry = expected[name]
                if (member.size != entry['bytes'] or member.mode & 0o7000
                        or bool(member.mode & 0o111) != (entry['mode'] == '100755')):
                    raise ValueError('Archive size/mode mismatch: ' + name)
                blob = hashlib.sha1(('blob ' + str(member.size) + '\0').encode())
                sha = hashlib.sha256()
                content = archive.extractfile(member)
                while block := content.read(1024**2):
                    blob.update(block)
                    sha.update(block)
                if blob.hexdigest() != entry['blob'] or entry.get('sha256', sha.hexdigest()) != sha.hexdigest():
                    raise ValueError('Archive bytes mismatch: ' + name)
                verified.append({**entry, 'sha256': sha.hexdigest()})
                found.add(name)
    if found != set(expected):
        raise ValueError('Missing archive members')
    return sorted(verified, key=lambda entry: entry['path'])


def check_dependencies(profile, store):
    for name, identity in profile['dependencies'].items():
        actual = file_record(Path(store) / relative(identity['path']), identity['bytes'])
        if actual != {k: identity[k] for k in ('bytes', 'sha256')}:
            raise ValueError('Dependency identity mismatch: ' + name)


def verify(directory, expected_manifest, profile, expected_input=None):
    """Require the caller's separately retained seal, not an adjacent checksum file."""
    directory = Path(directory)
    with regular(directory / 'manifest.json', MANIFEST_LIMIT) as (stream, _):
        data = stream.read(MANIFEST_LIMIT + 1)
    if hashlib.sha256(data).hexdigest() != expected_manifest:
        raise ValueError('Manifest seal mismatch')
    manifest = json.loads(data)
    if manifest['profile'] != profile or manifest['schema_version'] != 1:
        raise ValueError('Frozen profile mismatch')
    inputs = {k: v for k, v in manifest.items() if k != 'input_id'}
    if manifest['input_id'] != digest(inputs) or (expected_input is not None and manifest['input_id'] != expected_input):
        raise ValueError('Input binding mismatch; stale build/artifact input identity')
    names = {'manifest.json'}
    for source in manifest['sources'].values():
        name = relative(source['archive']['path'])
        names.add(name)
        if file_record(directory / name, ARCHIVE_LIMIT) != {k: source['archive'][k] for k in ('bytes', 'sha256')}:
            raise ValueError('Archive seal mismatch')
        verify_archive(directory / name, source['entries'], source['gitlinks'])
    if {p.name for p in directory.iterdir()} != names:
        raise ValueError('Unexpected package contents')
    return manifest


def prepare(profile, repositories, store, output):
    """Publish one verified source package; failures remove only this call's scratch."""
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('Output already exists; preserve the prepared input')
    if any(output.is_relative_to(Path(r).resolve()) for r in repositories.values()):
        raise ValueError('Output must be outside source repositories')
    if shutil.disk_usage(output.parent).free < 2 * 1024**3:
        raise ValueError('Preparation needs 2 GiB free scratch space')
    check_dependencies(profile, store)
    with tempfile.TemporaryDirectory(prefix='.candidate-input-', dir=output.parent) as tmp:
        root = Path(tmp)
        package = root / 'package'
        package.mkdir(mode=0o700)
        sources, views = {}, {}
        for name, wanted in profile['sources'].items():
            scratch = root / name
            scratch.mkdir()
            view = GitTree(repositories[name], scratch)
            entries, links = view.inventory(wanted['commit'], wanted['tree'])
            if links != wanted['gitlinks']:
                raise ValueError('Submodule pin mismatch')
            if name == 'eqemu':
                observed = {e['path']: e['blob'] for e in entries}
                if any(observed.get(path) != blob for path, blob in profile['dependency_blobs'].items()):
                    raise ValueError('Unsupported dependency closure')
            view.clean(wanted['commit'], entries, links)
            archive = package / (name + '.tar')
            view.archive(wanted['commit'], archive)
            verified = verify_archive(archive, entries, links)
            sources[name] = {**wanted, 'entries': verified,
                             'archive': {'path': archive.name, **file_record(archive, ARCHIVE_LIMIT)}}
            views[name] = (view, entries, links)
        if sum(e['bytes'] for s in sources.values() for e in s['entries']) > SOURCE_LIMIT:
            raise ValueError('Combined source exceeds budget')
        # Initialized candidate submodules must agree too; empty gitlink directories
        # may use the approved external object stores identified by the profile.
        for path, name in profile['submodule_sources'].items():
            module = Path(repositories['eqemu']) / path
            if module.exists() and any(module.iterdir()):
                if not (module / '.git').exists():
                    raise ValueError('Untracked files in an uninitialized submodule')
                scratch = root / ('checkout-' + name)
                scratch.mkdir()
                view = GitTree(module, scratch)
                wanted = profile['submodules'][name]
                entries, links = view.inventory(wanted['commit'], wanted['tree'])
                view.clean(wanted['commit'], entries, links)
                views['checkout-' + name] = (view, entries, links)
        for name, (view, entries, links) in views.items():
            wanted = profile['submodules'][name.removeprefix('checkout-')] if name.startswith('checkout-') else profile['sources'][name]
            view.clean(wanted['commit'], entries, links)
        check_dependencies(profile, store)
        manifest = {'schema_version': 1, 'profile': profile, 'sources': sources,
                    'preparer_sha256': file_record(Path(__file__), 1024**2)['sha256'],
                    'scope': 'prepared source input only; build recipe integration and acceptance pending'}
        manifest['input_id'] = digest(manifest)
        data = canonical(manifest)
        if len(data) > MANIFEST_LIMIT:
            raise ValueError('Manifest exceeds budget')
        (package / 'manifest.json').write_bytes(data)
        seal = hashlib.sha256(data).hexdigest()
        verify(package, seal, profile, manifest['input_id'])
        for path in package.iterdir():
            path.chmod(0o400)
        # A claimed destination is never overwritten, including a concurrent creator.
        output.mkdir(mode=0o700)
        try:
            for path in package.iterdir():
                path.rename(output / path.name)
        except BaseException:
            shutil.rmtree(output)
            raise
        return {'manifest_sha256': seal, 'input_id': manifest['input_id'],
                'package_bytes': sum(p.stat().st_size for p in output.iterdir()),
                'source_bytes': sum(e['bytes'] for s in sources.values() for e in s['entries']),
                'files': sum(len(s['entries']) for s in sources.values()), 'accepted': False}
