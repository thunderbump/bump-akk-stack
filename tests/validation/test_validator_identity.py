"""Read-only sealed identity controls without privilege, source preparation or jobs."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation'))
import candidate
import common
import prepare


class ValidatorIdentity(unittest.TestCase):
    @contextlib.contextmanager
    def installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            package=Path(tmp)/'draft';package.mkdir()
            for name in prepare.RUNTIME:(package/name).write_bytes((ROOT/'validation'/name).read_bytes())
            for name in prepare.RECIPES:(package/name).write_bytes((ROOT/'validation/recipes'/name).read_bytes())
            profile=json.loads((package/'profile.json').read_text())
            client={'input_store':'/retained/public','websocketpp':'/retained/websocketpp'}
            host={name:dict(source=str(Path(client['input_store'])/profile['dependencies'][key]['path']),
                           **{k:profile['dependencies'][key][k] for k in ['bytes','sha256']})
                  for name,key in [('base.qcow2','base'),('fixture.iso','media')]}
            (package/'client-config.json').write_text(json.dumps(client))
            (package/'host-inputs.json').write_text(json.dumps(host))
            def reseal():
                manifest={'version':1,'files':{p.name:common.sha(p) for p in package.iterdir() if p.name!='manifest.json'}}
                (package/'manifest.json').write_text(json.dumps(manifest))
                return common.sha(package/'manifest.json')
            digest=reseal();target=package.parent/digest[:16];package.rename(target);package=target
            # Preserve real byte/hash/shape/path checks. Only the OS administrator
            # ownership boundary is synthetic because these tests run unprivileged.
            def read(path,limit):
                if path.is_symlink() or not path.is_file() or path.stat().st_size>limit:
                    raise ValueError('Unsafe installed identity file')
                return path.read_bytes()
            with patch.object(candidate,'identity_file',side_effect=read):
                yield package,digest,reseal

    def test_verified_probe_is_stable_bounded_and_has_no_work_side_effects(self):
        with self.installed() as (package,digest,_),patch.object(candidate,'prepare') as prep,\
             patch.object(candidate,'request') as request,patch.object(candidate,'execute') as execute:
            before={p.name:p.read_bytes() for p in package.iterdir()}
            first=candidate.installed_identity(package)
            self.assertEqual(first,{'schema_version':1,'identity':'sha256:'+digest})
            self.assertEqual(first,candidate.installed_identity(package))
            self.assertLess(len(json.dumps(first).encode()),4096)
            self.assertLessEqual(len(first['identity'].encode()),256)
            self.assertEqual(before,{p.name:p.read_bytes() for p in package.iterdir()})
            with patch.object(candidate.sys,'argv',['eqemu-validate','--identity']),\
                 patch.object(candidate.resource,'setrlimit'),\
                 patch.object(candidate,'installed_identity',return_value=first),\
                 contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(candidate.main(),0)
            self.assertEqual(json.loads(stdout.getvalue()),first)
            self.assertEqual(len(stdout.getvalue().splitlines()),1)
            prep.assert_not_called();request.assert_not_called();execute.assert_not_called()

    def test_cli_identity_failure_is_explicit_nonpass_without_submission_or_stdout(self):
        with patch.object(candidate.sys,'argv',['eqemu-validate','--identity']),\
                 patch.object(candidate.resource,'setrlimit'),\
             patch.object(candidate,'installed_identity',side_effect=ValueError('tampered')),\
             patch.object(candidate,'execute') as execute,\
             contextlib.redirect_stdout(io.StringIO()) as stdout,\
             contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(candidate.main(),2)
            self.assertEqual(stdout.getvalue(),'')
            self.assertIn('identity refused',stderr.getvalue())
            execute.assert_not_called()

    def test_missing_changed_symlink_extra_and_manifest_tampering_refuse(self):
        for kind in ['changed','missing','symlink','extra','manifest']:
            with self.subTest(kind=kind),self.installed() as (package,_,_):
                path=package/'producer-guest.py'
                if kind=='changed':path.write_bytes(path.read_bytes()+b' ')
                if kind=='missing':path.unlink()
                if kind=='symlink':path.unlink();path.symlink_to(ROOT/'validation/recipes/producer-guest.py')
                if kind=='extra':(package/'unexpected.py').write_text('')
                if kind=='manifest':(package/'manifest.json').write_text('{"version":1}')
                with self.assertRaises((ValueError,OSError)):candidate.installed_identity(package)

    def test_reviewed_new_seal_changes_identity_but_contradictory_input_contract_refuses(self):
        with self.installed() as (package,old,reseal):
            path=package/'profile.json';path.write_bytes(path.read_bytes()+b' ')
            new=reseal();target=package.parent/new[:16];package.rename(target)
            self.assertNotEqual(old,new)
            self.assertEqual(candidate.installed_identity(target)['identity'],'sha256:'+new)
        with self.installed() as (package,_,reseal):
            path=package/'host-inputs.json';host=json.loads(path.read_text())
            host['base.qcow2']['sha256']='0'*64;path.write_text(json.dumps(host))
            digest=reseal();target=package.parent/digest[:16];package.rename(target)
            with self.assertRaisesRegex(ValueError,'declared input identity mismatch'):
                candidate.installed_identity(target)

    def test_real_unprivileged_path_ownership_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'data';path.write_text('x')
            with self.assertRaisesRegex(ValueError,'Unsafe installed identity ancestor'):
                candidate.identity_file(path,10)
        # Ordinary users can inspect sealed, nonmutable operating-system files.
        system = Path('/etc/os-release').resolve()
        if system.stat().st_uid == 0 and all(p.stat().st_uid == 0 for p in system.parents):
            self.assertTrue(candidate.identity_file(system,1024))
        else:
            # Managed filesystem views can remap OS ownership; that must refuse.
            with self.assertRaisesRegex(ValueError,'Unsafe installed identity'):
                candidate.identity_file(system,1024)
