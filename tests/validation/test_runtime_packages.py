"""Exercise the shared guest installer with a metadata-sensitive fake solver; no apt/VM."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'validation'))
import actor_runtime
import debugger


class Packages(unittest.TestCase):
    def exercise(self, installed='', plan='Inst example (1 Ubuntu [amd64])\n', fail=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); media = root/'media'; media.mkdir()
            for name in ('apt-lists', 'debs', 'provenance'):
                (media/name).mkdir()
            (media/'apt-lists/runtime_Packages').write_text('Package: example\nVersion: 1\n')
            (media/'debs/example.deb').write_bytes(b'opaque-deb')
            sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
            proof = {'packages': [dict(Package='example', Version='1', Architecture='amd64',
                                      Filename='pool/example.deb', Size=10,
                                      SHA256=sha(media/'debs/example.deb'))]}
            (media/'provenance/runtime-package-proof.json').write_text(json.dumps(proof))
            # Verify inputs through the same production gate as all three callers.
            manifest = {'files': [dict(path=str(p.relative_to(media)), bytes=p.stat().st_size,
                                       sha256=sha(p)) for p in media.rglob('*') if p.is_file()]}
            (media/'runtime-bundle-manifest.json').write_text(json.dumps(manifest))
            env = {'APT_CONFIG': '/native/apt.conf'}
            build = SimpleNamespace(WORK=root, ENV=env, sha=sha, DEADLINE=float('inf'))
            runtime = actor_runtime.Runtime(build, None, dict(manifest=manifest,
                           manifest_sha256=sha(media/'runtime-bundle-manifest.json')))
            calls = []
            def command(name, args, **kwargs):
                calls.append(name)
                config = Path(build.ENV['APT_CONFIG'])
                self.assertEqual(config.parent, root/'runtime-apt')
                self.assertIn('Dir::State::status "/var/lib/dpkg/status";', config.read_text())
                self.assertEqual((config.parent/'lists/runtime_Packages').read_text(),
                                 (media/'apt-lists/runtime_Packages').read_text())
                self.assertEqual((config.parent/'archives/example_1_amd64.deb').read_bytes(), b'opaque-deb')
                if name == 'actor-package-current': return installed
                if name == 'actor-package-plan': return plan
                if name == 'actor-package-identities': return 'example\t1\n'
                if name == 'actor-package-install':
                    self.assertIn('--no-download', args); self.assertIn('--no-remove', args)
                    if fail: raise RuntimeError('install interrupted')
                return ''
            def local_path(value):
                return root/'policy-rc.d' if value == '/usr/sbin/policy-rc.d' else Path(value)
            with patch.object(actor_runtime, 'MEDIA', media), patch.object(runtime, 'guard'), \
                    patch.object(runtime, 'command', side_effect=command), \
                    patch.object(actor_runtime, 'Path', side_effect=local_path), \
                    patch.object(actor_runtime.subprocess, 'run', return_value=SimpleNamespace(returncode=1)), \
                    patch.object(debugger, 'inventory', return_value={}):
                runtime.verify_inputs()
                try:
                    runtime.install_packages()
                finally:
                    self.assertIs(build.ENV, env)
                    self.assertFalse((root/'policy-rc.d').exists())
            self.assertIn('actor-package-identities', calls)

    def test_runtime_metadata_and_fresh_install(self):
        self.exercise()

    def test_already_installed_pin_is_not_required_in_install_plan(self):
        self.exercise(installed='example\t1\tinstalled\n', plan='')

    def test_partial_overlap_ignores_unrelated_installed_packages(self):
        self.exercise(installed='native-tool\t9\tinstalled\n')

    def test_changed_installed_version_or_unpinned_plan_refuses(self):
        for kwargs in (dict(installed='example\t0\tinstalled\n'),
                       dict(plan='Inst other (1 Ubuntu [amd64])\n'),
                       dict(plan='Remv native-tool [9]\n'), dict(plan=''),
                       dict(plan='Inst example [0] (1 Ubuntu [amd64])\n')):
            with self.subTest(kwargs=kwargs), self.assertRaises(RuntimeError):
                self.exercise(**kwargs)

    def test_install_interruption_restores_environment_and_service_policy(self):
        with self.assertRaisesRegex(RuntimeError, 'install interrupted'):
            self.exercise(fail=True)
