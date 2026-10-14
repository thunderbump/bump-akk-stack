"""Exercise the guest build's writable dependency roots and exact source verifier."""
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]


def producer():
    path=ROOT/'validation/recipes/producer-guest.py'
    module=types.ModuleType('vcpkg_root_guest');module.__file__=str(path)
    exec(compile(path.read_text(),str(path),'exec'),module.__dict__)
    return module


class VcpkgBuildRoots(unittest.TestCase):
    def build(self,root,drift=None):
        guest=producer();guest.WORK=root;guest.LOGS=root/'logs';guest.LOGS.mkdir()
        source=root/'eqemu';calls={}
        profile=root/'profile.json';profile.write_text('{}')
        def location(value):
            return profile if str(value)=='/opt/eqemu-proof/candidate-profile.json' else Path(value)
        def materialize(path):
            path.mkdir();(path/'submodules/vcpkg').mkdir(parents=True)
            data=b'candidate input\n';(path/'source.cpp').write_bytes(data)
            authority=dict(entries=[dict(path='source.cpp',bytes=len(data),
                           sha256=hashlib.sha256(data).hexdigest(),mode='100644')],
                           gitlinks={'submodules/vcpkg':'a'*40})
            (root/'source-authority.json').write_text(json.dumps(authority))
        provenance=root/'media/provenance';provenance.mkdir(parents=True)
        (provenance/'static-input-plan.json').write_text('{"ports":[]}')
        downloads=root/'media/downloads';downloads.mkdir()
        tools=root/'media/tools';tools.mkdir();(tools/'vcpkg').write_bytes(b'opaque tool')
        def command(stage,args,**kwargs):
            calls[stage]=list(args);text='tool identity'
            if stage=='registry-clone':Path(args[-1]).mkdir()
            elif stage=='registry-tree':text='57b96538f3990946bbf562080f5d48ed52a2144a'
            elif stage=='vcpkg-plan':
                # Actual pinned vcpkg writes its hash cache even for --dry-run.
                roots=[arg.split('=',1)[1] for arg in args if arg.startswith('--x-install-root=')]
                installed=Path(roots[0]) if roots else Path(kwargs['cwd'])/'vcpkg_installed'
                cache=installed/'vcpkg/compiler-file-hash-cache.json'
                cache.parent.mkdir(parents=True);cache.write_text('{}\n');text=''
            elif stage=='intentional-exit-seven':raise RuntimeError('intentional-exit-seven: exit 7')
            elif stage=='configure':
                build=root/'build';build.mkdir(exist_ok=True)
                (build/'CMakeCache.txt').write_text('PERL_INCLUDE_PATH:PATH='+str(source)+'\nPERL_LIBRARY:FILEPATH='+str(source)+'\n')
            elif stage=='server-build':
                binary=root/'build/bin';binary.mkdir()
                for name in ['world','zone','shared_memory','loginserver','ucs','queryserv','eqlaunch',
                             'tests','tests_runner_controls','tests_reporting_controls']:
                    (binary/name).write_bytes(b'not executed')
                if drift=='extra':(source/'unexpected').write_text('wrong')
                if drift=='changed':(source/'source.cpp').write_text('modified input')
            log=guest.LOGS/(stage+'.log');log.write_text(text);return log
        with patch.object(guest,'P',side_effect=location),patch.object(guest,'MEDIA',root/'media'),\
             patch.object(guest,'materialize_candidate',side_effect=materialize),\
             patch.object(guest,'apt_preflight',return_value='after'),\
             patch.object(guest,'system_zlib_probe',return_value='zlib'),\
             patch.object(guest,'command',side_effect=command),\
             patch.object(guest,'runner_controls'),patch.object(guest,'real_utility_suite'),\
             patch.object(guest,'measure_outputs'),patch.object(guest,'emit'):
            guest.original_build()
        return calls,source

    def test_planning_and_configure_share_a_root_outside_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);calls,source=self.build(root)
            planning=[arg.split('=',1)[1] for arg in calls['vcpkg-plan'] if arg.startswith('--x-install-root=')]
            configure=[arg.split('=',1)[1] for arg in calls['configure'] if arg.startswith('-DVCPKG_INSTALLED_DIR=')]
            self.assertEqual(len(planning),1);self.assertEqual(planning,configure)
            self.assertFalse(Path(planning[0]).is_relative_to(source))
            self.assertTrue((Path(planning[0])/'vcpkg/compiler-file-hash-cache.json').is_file())
            self.assertFalse((source/'vcpkg_installed').exists())
            self.assertIn('--no-downloads',calls['vcpkg-plan'])
            self.assertIn('-DVCPKG_INSTALL_OPTIONS=--no-downloads;--binarysource=clear',calls['configure'])

    def test_build_still_rejects_unexpected_or_modified_source(self):
        for drift,error in [('extra','Unexpected materialized source'),('changed','Materialized source mismatch')]:
            with self.subTest(drift=drift),tempfile.TemporaryDirectory() as tmp:
                with self.assertRaisesRegex(RuntimeError,error):self.build(Path(tmp),drift)

    def test_generated_cache_in_source_is_never_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cache=root/'vcpkg_installed/vcpkg/compiler-file-hash-cache.json'
            cache.parent.mkdir(parents=True);cache.write_text('{}')
            with self.assertRaisesRegex(RuntimeError,'Unexpected materialized source: vcpkg_installed/vcpkg/compiler-file-hash-cache.json'):
                producer().verify_materialized(root,dict(entries=[],gitlinks={}))


if __name__=='__main__':unittest.main()
