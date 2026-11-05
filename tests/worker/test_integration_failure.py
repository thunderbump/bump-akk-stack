"""Injected guest seams only: no native, SQL, worker or external service execution."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'validation'), str(ROOT/'validation/worker')]
import actor_integration as integration
import actor_runtime
import integration_artifacts as artifacts
from test_actor_integration import artifact, CANDIDATE, TREE, RUN


class GuestFailure(unittest.TestCase):
    def exercise(self, method=None, error=None, *, cleanup=True, artifact_error=None,
                 controller_pass=False, controller_output=None, private_artifact=False,
                 controller_failure=11, native_cleanup='not-run', final_error=None):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as patches:
            root = Path(temporary)
            server = root/'server'
            server.mkdir()
            (server/'eqemu_config.json').write_text(json.dumps({'server': {'world': {}}}))
            (server/'shared').mkdir()
            for name in ('items', 'spells'):
                (server/'shared'/name).write_bytes(b'fixture')
            (server/artifacts.NAME).write_bytes(artifacts.encoded(artifact()))
            result = dict(scope=artifacts.SELECTION, exit_code=2,
                          binaries={name: 'f'*64 for name in ('world', 'zone', 'shared_memory')},
                          fixture_sha256=artifacts.FIXTURE_SHA, process_outcomes=[],
                          native_cleanup=native_cleanup, database_cleanup='not-run',
                          summary=dict(integration.initial_summary(), outcome=2, failure_cause=controller_failure))
            if controller_pass:
                result.update(exit_code=0,native_cleanup=True)
                result['summary'].update(outcome=1,failure_cause=0,case_outcomes=[1]*3,check_results=[1]*12)
            calls = []
            class Runtime:
                def __init__(self, *args, **kwargs):
                    self.secrets = [CANDIDATE] if private_artifact else ['PRIVATE-CREDENTIAL']
                def invoke(self, name):
                    calls.append(name)
                    if name == method:
                        raise error
                def command(self, name, *args, **kwargs):
                    self.invoke(name)
                    if name == 'actor-population-integration' and controller_output is not None:
                        return controller_output
                    return 'CDAU_RESULT '+artifacts.encoded(result).decode() if name == 'actor-population-integration' else ''
                def verify_inputs(self):
                    self.invoke('verify_inputs')
                    if final_error and 'actor-population-integration' in calls: raise final_error
                def install_packages(self): self.invoke('install_packages')
                def initialize_database(self): self.invoke('initialize_database')
                def import_database(self): self.invoke('import_database')
                def configure(self):
                    self.invoke('configure')
                    return server
                def cleanup(self):
                    calls.append('cleanup')
                    if isinstance(cleanup, Exception): raise cleanup
                    return cleanup
            is_file, read_bytes, read_text = Path.is_file, Path.read_bytes, Path.read_text
            patches.enter_context(patch.object(Path, 'is_file', lambda p: True if str(p) == '/opt/eqemu-worker-build-guest' else is_file(p)))
            patches.enter_context(patch.object(Path, 'read_bytes', lambda p: b'{}' if str(p) == '/opt/runtime-fixture.json' else read_bytes(p)))
            patches.enter_context(patch.object(Path, 'read_text', lambda p, *a, **k: RUN if str(p) == '/opt/eqemu-worker-nonce' else read_text(p, *a, **k)))
            patches.enter_context(patch.object(actor_runtime, 'ROOT', root/'runtime'))
            patches.enter_context(patch.object(actor_runtime, 'MEDIA', root/'media'))
            patches.enter_context(patch.object(actor_runtime, 'Runtime', Runtime))
            patches.enter_context(patch.object(integration, 'verify_fixture', return_value={}))
            patches.enter_context(patch.object(integration, 'install_quests'))
            patches.enter_context(patch('os.geteuid', return_value=0))
            patches.enter_context(patch('os.chown'))
            patches.enter_context(patch('pwd.getpwnam', return_value=types.SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())))
            patches.enter_context(patch('signal.signal', return_value=None))
            if artifact_error:
                patches.enter_context(patch.object(integration, 'read_public', side_effect=artifact_error))
            emitted = []
            patches.enter_context(patch.object(integration, 'sys_stdout_write', side_effect=emitted.append))
            build = types.SimpleNamespace(DEADLINE=time.monotonic()+3600, WORK=root, sha=lambda _: 'f'*64)
            identity = dict(candidate=CANDIDATE, tree=TREE, stack_commit='d'*40, integration=artifacts.SELECTION)
            with self.assertRaises(RuntimeError) as raised:
                integration.run(build, identity)
            self.assertIn('cleanup', calls)
            self.assertTrue(all(len(frame) <= artifacts.FRAME_CAP for frame in emitted))
            self.assertLessEqual(sum(map(len, emitted)), artifacts.WIRE_CAP)
            normal = raised.exception.result
            integration.validate_result(normal)
            self.assertEqual(normal['exit_code'], 2)
            self.assertNotIn('PRIVATE-CREDENTIAL', str(raised.exception))
            self.assertNotIn('PRIVATE-CREDENTIAL', artifacts.encoded(normal).decode())
            return raised.exception, calls

    def test_setup_and_controller_failures_keep_fixed_phase_and_original_cause(self):
        for method, phase, error, kind in [
                ('configure', 'server-configure', OSError('PRIVATE-CREDENTIAL /private/path'), 'os'),
                ('install_packages', 'runtime-packages', ValueError('PRIVATE-CREDENTIAL'), 'value'),
                ('initialize_database', 'database-initialize', RuntimeError('PRIVATE-CREDENTIAL'), 'runtime'),
                ('import_database', 'database-import', ValueError('PRIVATE-CREDENTIAL'), 'value'),
                ('integration-shared-memory', 'shared-memory', OSError('PRIVATE-CREDENTIAL'), 'os'),
                ('actor-population-integration', 'controller', RuntimeError('PRIVATE-CREDENTIAL'), 'runtime')]:
            with self.subTest(method=method):
                failure, _ = self.exercise(method, error)
                self.assertEqual(str(failure), 'integration-nonpass:'+phase+':'+kind)
                self.assertIs(failure.__cause__, error)

    def test_cleanup_and_missing_artifact_do_not_mask_primary_exception(self):
        original = OSError('PRIVATE-CREDENTIAL original')
        secondary = ValueError('PRIVATE-CREDENTIAL cleanup')
        failure, _ = self.exercise('configure', original, cleanup=secondary)
        self.assertEqual(str(failure), 'integration-nonpass:server-configure:os')
        self.assertIs(failure.__cause__, original)
        self.assertIs(failure.result['database_cleanup'], False)
        missing = FileNotFoundError('PRIVATE-CREDENTIAL /private/artifact')
        failure, _ = self.exercise(artifact_error=missing,controller_pass=True)
        self.assertEqual(str(failure), 'integration-nonpass:artifact-read:os')
        self.assertIs(failure.__cause__, missing)
        failure, _ = self.exercise(cleanup=False,controller_pass=True)
        self.assertEqual(str(failure), 'integration-nonpass:database-cleanup:nonpass')
        self.assertIs(failure.result['database_cleanup'], False)

    def test_fixed_vocabulary_fits_existing_guest_error_schema_without_private_types(self):
        class PRIVATE_CREDENTIAL(Exception): pass
        selected=['rust-format','rust-dependencies','rust-clippy','rust-tests','rust-doctests',
                  'native-configure','native-build','zone-rust-symbol','native-utilities','actor-population-integration']
        for phase in integration.FAILURE_PHASES:
            for cause in (None,TimeoutError('PRIVATE-CREDENTIAL'),PRIVATE_CREDENTIAL('PRIVATE-CREDENTIAL')):
                text=integration.failure_text(phase,cause)
                guest=dict(version=1,scope='worker-build',nonce=RUN,exit_code=2,stage='actor-population-integration',
                           selected_checks=selected,completed_checks=selected[:-1],integration=artifacts.SELECTION,error=text)
                artifacts.validate_guest(guest)
                self.assertLess(len(text.encode()),100)
                self.assertNotIn('PRIVATE',text)
        with self.assertRaises(ValueError): integration.failure_text('PRIVATE-CREDENTIAL',None)

    def test_reported_controller_nonpass_survives_later_artifact_failure(self):
        failure,_=self.exercise(artifact_error=FileNotFoundError('PRIVATE-CREDENTIAL'))
        self.assertEqual(str(failure),'integration-nonpass:controller-result:nonpass')
        self.assertEqual(failure.result['summary']['failure_cause'],11)
        self.assertEqual(failure.result['native_cleanup'],'not-run')

    def test_malformed_controller_and_private_artifact_keep_distinct_safe_phases(self):
        failure,_=self.exercise(controller_output='CDAU_RESULT PRIVATE-CREDENTIAL')
        self.assertEqual(str(failure),'integration-nonpass:controller-result:value')
        self.assertIsInstance(failure.__cause__,ValueError)
        failure,_=self.exercise(controller_pass=True,private_artifact=True)
        self.assertEqual(str(failure),'integration-nonpass:artifact-validate:value')
        self.assertIsInstance(failure.__cause__,ValueError)

    def test_controller_failure_code_and_native_cleanup_survive_final_verification_error(self):
        failure,_=self.exercise(controller_failure=8,native_cleanup=False,final_error=OSError('PRIVATE-CREDENTIAL'))
        self.assertEqual(str(failure),'integration-nonpass:controller-result:nonpass')
        self.assertEqual(failure.result['summary']['failure_cause'],8)
        self.assertIs(failure.result['native_cleanup'],False)


if __name__ == '__main__': unittest.main()
