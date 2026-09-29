import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import inputs


class InputProofTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='candidate-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repositories = {}
        for name in ('eqemu', 'websocketpp'):
            repo = self.root / name
            repo.mkdir()
            self.repositories[name] = repo
            self.git(repo, 'init', '-q')
            (repo / 'code.cpp').write_text('int main() { return 0; }\n')
            (repo / 'tool').write_text('source data, not executed\n')
            (repo / 'tool').chmod(0o755)
            self.commit(repo)
        web = self.snapshot('websocketpp')
        eq = self.repositories['eqemu']
        (eq / 'vcpkg.json').write_text('{"dependencies":[]}\n')
        (eq / '.gitmodules').write_text('fixed synthetic submodules\n')
        for name in ('websocketpp', 'vcpkg'):
            (eq / 'submodules' / name).mkdir(parents=True)
            self.git(eq, 'update-index', '--add', '--cacheinfo', '160000,' + web['commit'] + ',submodules/' + name)
        self.commit(eq)
        self.store = self.root / 'store'
        self.store.mkdir()
        (self.store / 'dependency').write_bytes(b'fixed offline dependency')
        self.profile = {
            'name': 'synthetic', 'repository': 'synthetic/eqemu',
            'sources': {'eqemu': self.snapshot('eqemu'), 'websocketpp': web},
            'submodules': {n: web for n in ('websocketpp', 'vcpkg')},
            'submodule_sources': {'submodules/' + n: n for n in ('websocketpp', 'vcpkg')},
            'dependency_blobs': {p: self.git(eq, 'rev-parse', 'HEAD:' + p).strip() for p in ('.gitmodules', 'vcpkg.json')},
            'dependencies': {'media': {'path': 'dependency', **inputs.file_record(self.store / 'dependency', 1000)}},
            'build_profile': {'integration': 'synthetic input-only proof'}}
        self.output = self.root / 'output'

    def git(self, repo, *args):
        return subprocess.check_output(['/usr/bin/git', '-C', str(repo), '-c', 'user.name=Test',
            '-c', 'user.email=test@example.invalid', '-c', 'commit.gpgSign=false', *args],
            stderr=subprocess.PIPE, text=True)

    def commit(self, repo):
        self.git(repo, 'add', '.')
        self.git(repo, 'commit', '-qm', 'fixture')

    def snapshot(self, name):
        repo = self.repositories[name]
        links = {}
        for line in self.git(repo, 'ls-tree', '-r', 'HEAD').splitlines():
            meta, path = line.split('\t')
            if meta.startswith('160000'):
                links[path] = meta.split()[2]
        return dict(commit=self.git(repo, 'rev-parse', 'HEAD').strip(),
                    tree=self.git(repo, 'rev-parse', 'HEAD^{tree}').strip(), gitlinks=links)

    def prepare(self):
        return inputs.prepare(self.profile, self.repositories, self.store, self.output)

    def verify(self, receipt):
        return inputs.verify(self.output, receipt['manifest_sha256'], self.profile, receipt['input_id'])

    def assert_refuses(self):
        with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
            self.prepare()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob('.candidate-input-*')), [])

    def test_roundtrip_seals_all_source_and_preserves_existing_output(self):
        receipt = self.prepare()
        manifest = self.verify(receipt)
        self.assertFalse(receipt['accepted'])
        self.assertEqual(receipt['files'], 6)
        self.assertEqual(manifest['sources']['eqemu']['gitlinks'], self.profile['sources']['eqemu']['gitlinks'])
        with self.assertRaisesRegex(ValueError, 'already exists'):
            self.prepare()
        self.verify(receipt)
        self.assertEqual(list(self.root.glob('.candidate-input-*')), [])

    def test_wrong_expected_commit_tree_and_submodule_pins(self):
        original = copy.deepcopy(self.profile)
        for field in ('commit', 'tree', 'gitlinks'):
            with self.subTest(field=field):
                self.profile = copy.deepcopy(original)
                self.profile['sources']['eqemu'][field] = {} if field == 'gitlinks' else '0' * 40
                self.assert_refuses()

    def test_dirty_bytes_mode_missing_and_untracked_even_if_ignored(self):
        eq = self.repositories['eqemu']
        for case in ('bytes', 'mode', 'missing', 'untracked'):
            with self.subTest(case=case):
                path = eq / 'code.cpp'
                old = path.read_bytes()
                if case == 'bytes': path.write_bytes(b'changed\n')
                if case == 'mode': path.chmod(0o755)
                if case == 'missing': path.unlink()
                if case == 'untracked':
                    (eq / '.git/info/exclude').write_text('ignored\n')
                    (eq / 'ignored').write_text('must not disappear')
                self.assert_refuses()
                path.write_bytes(old)
                path.chmod(0o644)
                (eq / 'ignored').unlink(missing_ok=True)

    def test_archive_attributes_cannot_omit_or_rewrite_tracked_bytes(self):
        eq = self.repositories['eqemu']
        for attribute in ('export-ignore', 'export-subst'):
            with self.subTest(attribute=attribute):
                (eq / '.gitattributes').write_text('code.cpp ' + attribute + '\n')
                (eq / 'code.cpp').write_text('$Format:%H$\n')
                self.commit(eq)
                self.profile['sources']['eqemu'] = self.snapshot('eqemu')
                self.assert_refuses()

    def test_candidate_local_helpers_and_inherited_git_configuration_are_unused(self):
        eq = self.repositories['eqemu']
        marker = self.root / 'helper-ran'
        helper = self.root / 'helper'
        helper.write_text('#!/bin/sh\ntouch ' + str(marker) + '\nexit 1\n')
        helper.chmod(0o755)
        self.git(eq, 'config', 'core.fsmonitor', str(helper))
        self.git(eq, 'config', 'tar.tar.command', str(helper))
        self.git(eq, 'config', 'core.hooksPath', str(self.root))
        with patch.dict(os.environ, {'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'tar.tar.command',
                                    'GIT_CONFIG_VALUE_0': str(helper), 'GIT_DIR': '/nonexistent'}):
            self.verify(self.prepare())
        self.assertFalse(marker.exists())

    def test_initialized_submodule_dirty_and_wrong_head_refuse(self):
        eq = self.repositories['eqemu']
        path = eq / 'submodules/websocketpp'
        path.rmdir()
        self.git(eq, 'clone', str(self.repositories['websocketpp']), str(path))
        receipt = self.prepare()
        self.verify(receipt)
        shutil.rmtree(self.output)
        (path / 'code.cpp').write_text('dirty')
        self.assert_refuses()
        self.commit(path)
        self.assert_refuses()

    def test_uninitialized_submodule_with_untracked_data_refuses(self):
        path = self.repositories['eqemu'] / 'submodules/vcpkg/untracked'
        path.write_text('not part of pinned registry')
        self.assert_refuses()

    def test_changed_dependency_file_and_candidate_closure_refuse(self):
        original = (self.store / 'dependency').read_bytes()
        (self.store / 'dependency').write_bytes(b'changed offline dependency')
        self.assert_refuses()
        (self.store / 'dependency').write_bytes(original)
        eq = self.repositories['eqemu']
        (eq / 'vcpkg.json').write_text('{"dependencies":["unavailable"]}')
        self.commit(eq)
        self.profile['sources']['eqemu'] = self.snapshot('eqemu')
        self.assert_refuses()

    def test_staged_archive_manifest_and_stale_binding_rejected(self):
        receipt = self.prepare()
        with self.assertRaisesRegex(ValueError, 'stale'):
            inputs.verify(self.output, receipt['manifest_sha256'], self.profile, '0' * 64)
        path = self.output / 'eqemu.tar'
        path.chmod(0o600)
        with path.open('r+b') as stream:
            stream.seek(4096)
            stream.write(b'changed')
        with self.assertRaisesRegex(ValueError, 'Archive seal'):
            self.verify(receipt)
        manifest_path = self.output / 'manifest.json'
        manifest_path.chmod(0o600)
        manifest_path.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'Manifest seal'):
            self.verify(receipt)

    def test_archive_member_controls(self):
        receipt = self.prepare()
        source = self.verify(receipt)['sources']['websocketpp']
        for case in ('missing', 'extra', 'mode', 'bytes', 'duplicate', 'symlink', 'traversal'):
            with self.subTest(case=case):
                path = self.root / 'bad.tar'
                with tarfile.open(path, 'w') as archive:
                    for entry in source['entries']:
                        if case == 'missing' and entry['path'] == 'code.cpp': continue
                        content = (self.repositories['websocketpp'] / entry['path']).read_bytes()
                        info = tarfile.TarInfo(entry['path'])
                        info.size = len(content)
                        info.mode = 0o755 if entry['mode'] == '100755' else 0o644
                        if entry['path'] == 'code.cpp':
                            if case == 'mode': info.mode = 0o755
                            if case == 'bytes': content = b'x' * len(content)
                            if case == 'symlink': info.type = tarfile.SYMTYPE; info.linkname = '/etc/passwd'
                            if case == 'traversal': info.name = '../escape'
                        archive.addfile(info, io.BytesIO(content))
                        if case == 'duplicate': archive.addfile(info, io.BytesIO(content))
                    if case == 'extra': archive.addfile(tarfile.TarInfo('extra'))
                with self.assertRaises(ValueError):
                    inputs.verify_archive(path, source['entries'], {})

    def test_resource_limits_and_nonregular_input_refuse_without_blocking(self):
        with patch.object(inputs, 'SOURCE_LIMIT', 1):
            self.assert_refuses()
        with patch.object(inputs, 'MANIFEST_LIMIT', 1):
            self.assert_refuses()
        (self.store / 'dependency').unlink()
        os.mkfifo(self.store / 'dependency')
        self.assert_refuses()

    def test_source_race_detected_before_publication(self):
        original = inputs.verify_archive
        changed = False
        def verify_then_change(*args):
            nonlocal changed
            result = original(*args)
            if not changed:
                (self.repositories['eqemu'] / 'code.cpp').write_text('changed after archive')
                changed = True
            return result
        with patch.object(inputs, 'verify_archive', side_effect=verify_then_change):
            self.assert_refuses()


if __name__ == '__main__':
    unittest.main()
