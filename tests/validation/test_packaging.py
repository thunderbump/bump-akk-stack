"""Static package preparation and recipe tampering controls; never start a VM."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'validation'))
import common
import prepare
import render

FACTS = dict(candidate='a'*40, tree='b'*40, input_id='c'*64, manifest_sha256='d'*64,
             iso_sha256='e'*64, iso_bytes=1)


class PackagePreparation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='eqemu-packaging-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root/'maintained'; shutil.copytree(ROOT/'validation', self.package)
        self.store = self.root/'public-inputs'; self.store.mkdir()
        self.websocketpp = self.root/'websocketpp'; self.websocketpp.mkdir()
        def git(*args):
            return subprocess.check_output(['git', '-C', str(self.websocketpp), *args]).decode().strip()
        git('init', '-q')
        (self.websocketpp/'header.hpp').write_text('retained public source\n')
        git('add', 'header.hpp')
        git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'source')
        profile = json.loads((self.package/'profile.json').read_text())
        profile['sources']['websocketpp'] = dict(commit=git('rev-parse','HEAD'), tree=git('rev-parse','HEAD^{tree}'), gitlinks={})
        for name in profile['dependencies']:
            path = self.store/(name+'.data'); path.write_bytes(name.encode())
            profile['dependencies'][name] = dict(path=path.name, bytes=path.stat().st_size, sha256=common.sha(path))
        (self.package/'profile.json').write_text(json.dumps(profile))
        manifest = json.loads((self.package/'recipe-manifest.json').read_text())
        manifest['files']['profile.json'] = common.sha(self.package/'profile.json')
        (self.package/'recipe-manifest.json').write_text(json.dumps(manifest))

    def prepare(self):
        return prepare.prepare(self.root/'output', self.store, self.websocketpp, self.package)

    def test_explicit_inputs_work_without_any_historical_directory(self):
        result = self.prepare()
        self.assertFalse(result['vm_started'])
        output = self.root/'output'
        self.assertEqual(set(p.name for p in output.iterdir()),
                         set(prepare.RUNTIME) | set(prepare.RECIPES) | {'host-inputs.json','client-config.json','manifest.json'})
        config = json.loads((output/'client-config.json').read_text())
        self.assertEqual(config, dict(input_store=str(self.store), websocketpp=str(self.websocketpp)))
        for name in ('base.qcow2', 'fixture.iso'):
            self.assertTrue(Path(json.loads((output/'host-inputs.json').read_text())[name]['source']).is_relative_to(self.store))
        installer = common.load('prepared_installer', output/'install.py')
        _, verified = installer.verified_package(output)
        self.assertEqual(set(verified),set(prepare.RUNTIME) | set(prepare.RECIPES) | {'host-inputs.json','client-config.json'})
        with self.assertRaisesRegex(ValueError,'already exists'):self.prepare()

    def test_wrong_hash_absent_dependency_and_dirty_websocketpp_refuse(self):
        media = self.store/'media.data'; original = media.read_bytes()
        media.write_bytes(b'other')
        with self.assertRaises(ValueError):self.prepare()
        media.unlink()
        with self.assertRaises(FileNotFoundError):self.prepare()
        media.write_bytes(original)
        (self.websocketpp/'untracked').write_text('wrong')
        with self.assertRaisesRegex(ValueError,'Untracked'):self.prepare()
        self.assertFalse((self.root/'output').exists())

    def test_wrong_recipe_hash_and_nonregular_recipe_refuse(self):
        path = self.package/'recipes/producer-user.json'; content = path.read_bytes()
        path.write_bytes(content+b' ')
        with self.assertRaisesRegex(ValueError,'Recipe identity mismatch'):self.prepare()
        path.unlink(); path.symlink_to(ROOT/'validation/recipes/producer-user.json')
        with self.assertRaises(OSError):self.prepare()
        self.assertFalse((self.root/'output').exists())

    def test_unverified_input_helper_never_executes(self):
        marker=self.root/'executed'
        (self.package/'inputs.py').write_text('from pathlib import Path; Path('+repr(str(marker))+').touch()')
        with self.assertRaisesRegex(ValueError,'Recipe identity mismatch'):self.prepare()
        self.assertFalse(marker.exists())

    def test_output_inside_dependency_checkout_is_refused(self):
        with self.assertRaisesRegex(ValueError,'outside'):
            prepare.prepare(self.websocketpp/'output',self.store,self.websocketpp,self.package)
        self.assertFalse((self.websocketpp/'output').exists())

    def test_symlinked_output_parent_cannot_write_to_protected_roots(self):
        for target in (self.websocketpp,self.store,self.package):
            with self.subTest(target=target):
                alias=self.root/'alias';alias.symlink_to(target,target_is_directory=True)
                try:
                    with self.assertRaisesRegex(ValueError,'outside'):
                        prepare.prepare(alias/'output',self.store,self.websocketpp,self.package)
                    self.assertFalse((target/'output').exists())
                finally:alias.unlink()

    def test_candidate_input_preparation_canonicalizes_source_and_output(self):
        inputs=common.load('input_containment',ROOT/'validation/inputs.py')
        alias=self.root/'source-alias';alias.symlink_to(self.websocketpp,target_is_directory=True)
        for destination,repository in ((alias/'output',self.websocketpp),
                                       (self.websocketpp/'output',alias),
                                       (alias/'child/../output',self.websocketpp)):
            with self.subTest(destination=destination):
                with self.assertRaisesRegex(ValueError,'outside source'):
                    inputs.prepare({}, {'eqemu':repository},self.store,destination)
                self.assertFalse((self.websocketpp/'output').exists())
        store_alias=self.root/'store-alias';store_alias.symlink_to(self.store,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'outside source'):
            inputs.prepare({}, {'eqemu':self.websocketpp},self.store,store_alias/'output')
        self.assertFalse((self.store/'output').exists())

    def test_rendered_workers_use_owned_inputs_without_history(self):
        self.prepare(); output=self.root/'output'; destination=self.root/'rendered'; destination.mkdir()
        def seed(argv, **kwargs):
            self.assertEqual(argv[0], '/usr/bin/cloud-localds')
            Path(argv[1]).write_bytes(b'synthetic seed')
        with patch.object(render.subprocess,'run',side_effect=seed):
            recipe=render.render('0123456789', FACTS, destination, output)
        self.assertEqual(set(recipe['workers']),{'producer-worker.py','consumer-worker.py'})
        for role in ('producer','consumer'):
            worker=(destination/(role+'-worker.py')).read_text()
            self.assertNotIn('/home/bump',worker)
            self.assertIn('/var/lib/eqemu-build/runs',worker)
            compile(worker,role,'exec')
            user=json.loads((destination/(role+'-user-data')).read_text().split('\n',1)[1])
            for entry in user['write_files']:
                if entry['path'].endswith('/guest_build.py'):compile(entry['content'],role+'-guest','exec')
        suite=(destination/'launcher.py').read_text()
        self.assertNotIn('def prerequisites',suite)
        self.assertNotIn('corrected-build-01',suite)
        self.assertNotIn('/home/bump',suite)
        compile(suite,'suite','exec')


if __name__ == '__main__':unittest.main()
