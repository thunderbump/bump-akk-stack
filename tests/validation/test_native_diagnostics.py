"""LLVM enforcement and missing-context controls; tiny trusted source, no VM/build."""
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'validation'))
import actor
import common
import native_diagnostics as diagnostic

SAFE = '''#include <utility>
struct Client { void send() {} };
void send(Client* p) { if (p) p->send(); }
int lifetime() { int* p = new int(3); int v = *p; delete p; return v; }
void release() { int* p = new int(1); delete p; p = nullptr; delete p; }
int pointer(int* p) { return p ? *p : 0; }
struct Item { Item(); Item(Item&&); void use(); };
void moved() { Item a; Item b(std::move(a)); b.use(); }
'''
UNSAFE = '''#include <utility>
struct Client { void send() {} };
void send() { Client* p = nullptr; p->send(); }
int lifetime() { int* p = new int(3); delete p; return *p; }
void release() { int* p = new int(1); delete p; delete p; }
int pointer() { int* p = nullptr; return *p; }
struct Item { Item(); Item(Item&&); void use(); };
void moved() { Item a; Item b(std::move(a)); a.use(); }
'''


class NativeDiagnosticPolicy(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.source = self.root/'source'; self.source.mkdir()
        self.build = self.root/'build'; self.build.mkdir(); self.file = self.source/'probe.cpp'
        self.file.write_text(SAFE)
        self.row = dict(directory=str(self.build), file=str(self.file),
                        arguments=['/usr/bin/g++','-std=c++20','-c',str(self.file)])
        self.database = self.build/'compile_commands.json'; self.write_database([self.row])

    def write_database(self, rows):
        self.database.write_text(json.dumps(rows))

    def test_exact_context_and_missing_duplicate_or_malformed_selection(self):
        selected, digest = diagnostic.compile_targets(self.source, self.build, ('probe.cpp',))
        self.assertEqual(selected, [('probe.cpp', self.file)]); self.assertEqual(len(digest), 64)
        for rows in [[], [self.row, self.row], [{}], [dict(self.row,arguments=[])]]:
            self.write_database(rows)
            with self.assertRaises(ValueError): diagnostic.compile_targets(self.source, self.build, ('probe.cpp',))
        self.write_database([self.row])
        for targets in [(), ('absent.cpp',), ('../source/probe.cpp',), ('/etc/passwd',)]:
            with self.assertRaises(ValueError): diagnostic.compile_targets(self.source, self.build, targets)
        self.file.unlink(); self.file.symlink_to(self.root/'outside.cpp')
        with self.assertRaises(ValueError): diagnostic.compile_targets(self.source, self.build, ('probe.cpp',))

    def test_parser_errors_unexpected_diagnostics_and_exit_zero_with_findings_refuse(self):
        item = {'DiagnosticName':diagnostic.CHECKS[0], 'DiagnosticMessage':{'Message':'null access'}}
        import yaml
        raw = yaml.safe_dump({'Diagnostics':[item]}).encode()
        self.assertEqual(len(diagnostic.diagnostic_result(raw, 1)), 1)
        with self.assertRaisesRegex(ValueError,'exit/report'): diagnostic.diagnostic_result(raw, 0)
        for name in ['clang-diagnostic-error','clang-diagnostic-unknown-warning-option','unknown-check']:
            item['DiagnosticName'] = name
            with self.assertRaises(ValueError): diagnostic.diagnostic_result(yaml.safe_dump({'Diagnostics':[item]}).encode(), 1)
        for raw, code in [(b'',1),(b'',2),(b'[]',0),(b'Diagnostics: broken',0),(b'null',0)]:
            with self.assertRaises(ValueError): diagnostic.diagnostic_result(raw, code)
        self.assertEqual(diagnostic.diagnostic_result(b'',0), [])

    @unittest.skipUnless(Path(diagnostic.TIDY).is_file(), 'pinned clang-tidy-18 unavailable')
    def test_real_tidy_safe_unsafe_and_missing_header_controls(self):
        safe = diagnostic.analyze(self.source,self.build,self.root/'safe',('probe.cpp',))
        self.assertTrue(safe['complete']); self.assertEqual(safe['findings'],[])
        self.file.write_text(UNSAFE)
        bad = diagnostic.analyze(self.source,self.build,self.root/'unsafe',('probe.cpp',))
        self.assertTrue(bad['complete']); self.assertEqual(bad['targets'][0]['exit_code'],1)
        self.assertEqual(len(bad['findings']),5)
        self.assertEqual({x['check'] for x in bad['findings']}, set(diagnostic.CHECKS))
        self.file.write_text('#include "missing-project-generated-header.h"\n'+SAFE)
        with self.assertRaisesRegex(ValueError,'Compiler/context'):
            diagnostic.analyze(self.source,self.build,self.root/'incomplete',('probe.cpp',))
        self.assertFalse(json.loads((self.root/'incomplete/report.json').read_text())['complete'])

    @unittest.skipUnless(Path(diagnostic.TIDY).is_file(), 'pinned clang-tidy-18 unavailable')
    def test_actual_cli_status_safe_findings_and_incomplete(self):
        paths=[];rows=[]
        for name in diagnostic.TARGETS:
            path=self.source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(SAFE);paths.append(path)
            rows.append(dict(directory=str(self.build),file=str(path),arguments=['/usr/bin/g++','-std=c++20','-c',str(path)]))
        self.write_database(rows)
        for name,code in [('safe-cli',0),('unsafe-cli',1),('incomplete-cli',2)]:
            if code==1:paths[0].write_text(UNSAFE)
            if code==2:paths[1].write_text('#include "missing-project-header.h"\n'+SAFE)
            result=subprocess.run([sys.executable,'-B',str(ROOT/'validation/native_diagnostics.py'),
                '--source',str(self.source),'--build',str(self.build),'--output',str(self.root/name)],
                capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,code,result.stdout+result.stderr)
            self.assertEqual(json.loads(result.stdout)['complete'],code!=2)

    def test_static_profile_is_distinct_and_does_not_select_actor_or_reuse(self):
        baseline = json.loads((ROOT/'validation/profile.json').read_text())
        ordinary = common.candidate_profile(baseline,'a'*40,'b'*40)
        static = common.candidate_profile(baseline,'a'*40,'b'*40,diagnostic.PROFILE)
        self.assertNotIn('native_diagnostics',ordinary)
        self.assertEqual(static['native_diagnostics']['targets'],list(diagnostic.TARGETS))
        self.assertNotIn('runtime',static['dependencies'])
        self.assertNotEqual(common.seal(static),common.seal(ordinary))
        with self.assertRaises(ValueError): actor.options(diagnostic.PROFILE,retain=True)

    def test_analyzer_findings_are_repairable_only_with_safe_resources_and_cleanup(self):
        worker=dict(resource_observations={'memory.events':'oom 0\noom_kill 0\n','pids.events':'max 0\n'},
            service_result='exit-code',cleanup={'readonly_inputs_unchanged':True},
            checks={'host_pre_resume':True},guest_report_untrusted={'ok':False,'error':'native-static-pilot: exit 1\nknown finding'})
        self.assertTrue(common.candidate_failure(worker))
        worker['guest_report_untrusted']['error']='native-static-pilot: exit 2\nmissing header'
        self.assertFalse(common.candidate_failure(worker))
        worker['guest_report_untrusted']['error']='native-static-pilot: exit 1\nknown finding'
        worker['resource_observations']['memory.events']='oom 1\noom_kill 1\n'
        self.assertFalse(common.candidate_failure(worker))


if __name__ == '__main__': unittest.main()
