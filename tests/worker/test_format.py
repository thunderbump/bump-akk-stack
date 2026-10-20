"""Trusted Python/data/socket fixtures only. No Rust, Cargo, candidate or VM execution."""
import base64
import contextlib
import copy
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'validation/worker'))
import client
import format_guest
import format_prepare
import guest
import runtime
import snapshot
import snapshot_apply
import test_runtime


def git(repo, *args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(repo), *args], stderr=subprocess.DEVNULL).decode().strip()


def source_fixture(root):
    repo = root / 'repo'; repo.mkdir()
    git(repo, 'init', '-q'); git(repo, 'config', 'user.name', 'Trusted fixture')
    git(repo, 'config', 'user.email', 'fixture@example.test')
    workspace = repo / 'rust/actors'; workspace.mkdir(parents=True)
    (workspace / 'Cargo.toml').write_text('[workspace]\nmembers=[]\n')
    (workspace / 'old.rs').write_text('fn old() {}\n')
    (workspace / 'deleted.rs').write_text('fn deleted() {}\n')
    (repo / '.gitignore').write_text('rust/actors/ignored.rs\n')
    git(repo, 'add', '.'); git(repo, 'commit', '-qm', 'opaque source fixture')
    return repo, git(repo, 'rev-parse', 'HEAD')


def complete(snapshot_value, operation='format', changes=None):
    changes = changes or []
    output = copy.deepcopy(snapshot_value)
    for change in changes:
        entry = next(e for e in output['files'] if e['path'] == change['path'])
        entry.update(sha256=change['after_sha256'], content_base64=change['content_base64'],
                     bytes=len(base64.b64decode(change['content_base64'])))
    return dict(version=1, scope='working-snapshot-format', operation=operation,
                base=snapshot_value['base'], head=snapshot_value['head'],
                input_snapshot_sha256=snapshot.sha(snapshot.canonical(snapshot_value)),
                output_snapshot_sha256=snapshot.sha(snapshot.canonical(output)),
                recipe_sha256=snapshot_value['recipe_sha256'], implementation_sha256='e'*64,
                rust_input_sha256=snapshot.RUST_INPUT_SHA256, exit_code=0, vm_started=True,
                cleanup_complete=True, changed_files=changes,
                timings=dict(boot_seconds=1, preparation_seconds=2, format_seconds=.1, total_seconds=3.1))


class Snapshots(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.repo, self.base = source_fixture(self.root)

    def capture(self):
        return snapshot.capture(self.repo, self.base, 'd'*64)

    def test_dirty_new_deletion_ignored_vendor_and_source_are_data(self):
        work = self.repo / 'rust/actors'
        (work / 'old.rs').write_text('fn old( ){ }\n')
        (work / 'new.rs').write_text('panic!("must never run on host");\n')
        (work / 'deleted.rs').unlink()
        (work / 'ignored.rs').write_text('ignored')
        for name in ('target', 'vendor', 'generated'):
            (work / name).mkdir(); (work / name / 'a.rs').write_text('excluded')
        (self.repo / '.rustfmt.toml').write_text('edition="2021"\n')
        original = {str(p.relative_to(self.repo)): p.read_bytes() for p in work.rglob('*') if p.is_file()}
        value = self.capture()
        self.assertEqual({e['path'] for e in value['files']}, {
            'rust/actors/Cargo.toml', 'rust/actors/old.rs', 'rust/actors/new.rs', '.rustfmt.toml'})
        self.assertEqual(value['deleted'], ['rust/actors/deleted.rs'])
        self.assertEqual(original, {str(p.relative_to(self.repo)): p.read_bytes() for p in work.rglob('*') if p.is_file()})
        first = snapshot.snapshot_identity(value)
        self.assertNotIn('content_base64', json.dumps(first))
        (work / 'new.rs').write_text('new bytes')
        self.assertNotEqual(first['input_snapshot_sha256'], snapshot.snapshot_identity(self.capture())['input_snapshot_sha256'])

    def test_symlink_file_directory_and_ignored_configuration_refuse(self):
        for kind in ('file', 'directory', 'config'):
            with self.subTest(kind=kind):
                path = self.repo / ('rust/actors/new.rs' if kind == 'file' else 'rust/actors/linked' if kind == 'directory' else '.rustfmt.toml')
                target = self.root / ('outside-dir' if kind == 'directory' else 'outside-file')
                if kind == 'directory':
                    target.mkdir(); (target / 'mod.rs').write_text('outside')
                else:
                    target.write_text('outside')
                path.symlink_to(target)
                try:
                    if kind == 'directory':
                        # Git does not recurse symlinks; selected child read must still refuse.
                        with self.assertRaises(OSError): snapshot.read_file(self.repo, 'rust/actors/linked/mod.rs')
                    else:
                        with self.assertRaises(OSError): self.capture()
                finally:
                    path.unlink()

    def test_snapshot_malformed_paths_hashes_sizes_duplicate_and_stale_binding(self):
        value = self.capture()
        for field, changed in [('path', '../escape.rs'), ('path', '/tmp/out.rs'), ('path', 'rust/actors/vendor/x.rs'),
                               ('sha256', '0'*64), ('bytes', snapshot.FILE_LIMIT+1), ('mode', '120000')]:
            with self.subTest(field=field, changed=changed):
                bad = copy.deepcopy(value); bad['files'][0][field] = changed
                with self.assertRaises((ValueError, TypeError)): snapshot.validate_snapshot(bad)
        bad = copy.deepcopy(value); bad['files'].append(bad['files'][0])
        with self.assertRaises(ValueError): snapshot.validate_snapshot(bad)
        result = complete(value)
        (self.repo / 'rust/actors/old.rs').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'mismatched'): snapshot.validate_result(result, self.capture(), 'format', 'e'*64)

    def test_snapshot_and_file_limits(self):
        (self.repo / 'rust/actors/huge.rs').write_bytes(b'x' * (snapshot.FILE_LIMIT + 1))
        with self.assertRaisesRegex(ValueError, 'type/size'): self.capture()

    def test_selected_index_includes_staged_new_then_missing_file(self):
        path = self.repo / 'rust/actors/new.rs'; path.write_text('new')
        git(self.repo, 'add', 'rust/actors/new.rs'); path.unlink()
        self.assertIn('rust/actors/new.rs', snapshot.indexed_paths(self.repo))
        self.assertNotIn('rust/actors/new.rs', {e['path'] for e in self.capture()['files']})

    def test_format_changes_validate_and_check_noop_preserves_input(self):
        value = self.capture(); entry = next(e for e in value['files'] if e['path'].endswith('old.rs'))
        data = b'fn formatted() {}\n'
        change = dict(path=entry['path'], before_sha256=entry['sha256'], after_sha256=snapshot.sha(data),
                      content_base64=base64.b64encode(data).decode())
        result = complete(value, changes=[change])
        self.assertIs(snapshot.validate_result(result, value, 'format', 'e'*64), result)
        self.assertIsNotNone(snapshot.validate_result(complete(value, 'check'), value, 'check', 'e'*64))
        for update in [dict(operation='check'), dict(exit_code=1), dict(recipe_sha256='0'*64),
                       dict(implementation_sha256='0'*64), dict(cleanup_complete=False),
                       dict(output_snapshot_sha256='0'*64), dict(rust_input_sha256='0'*64),
                       dict(timings={'total_seconds':float('nan')})]:
            with self.subTest(update=update), self.assertRaises(ValueError):
                snapshot.validate_result(dict(result, **update), value, 'format', 'e'*64)
        for path in ('../../out.rs', 'rust/actors/new.rs', 'rust/actors/Cargo.toml'):
            bad = copy.deepcopy(result); bad['changed_files'][0]['path'] = path
            with self.subTest(path=path), self.assertRaises(ValueError): snapshot.validate_result(bad, value, 'format', 'e'*64)
        with patch.object(snapshot, 'CHANGE_LIMIT', 1), self.assertRaises(ValueError):
            snapshot.validate_result(result, value, 'format', 'e'*64)
        with patch.object(snapshot, 'RESULT_LIMIT', 1), self.assertRaises(ValueError):
            snapshot.validate_result(result, value, 'format', 'e'*64)

    def test_guest_output_protection_with_trusted_fake_formatter(self):
        value = self.capture()
        source = self.root / 'extracted'; source.mkdir()
        for entry in value['files']:
            target=source/entry['path'];target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(base64.b64decode(entry['content_base64']))
        path = source / 'rust/actors/old.rs'
        calls = []
        def harmless(name, args, **kwargs):
            calls.append(args); path.write_text('fn changed() {}\n')
        changes = format_guest.format_source(value, source, 'format', harmless)
        self.assertEqual(len(changes), 1)
        self.assertEqual(calls[0], ['/opt/eqemu-format/toolchain/bin/cargo', 'fmt', '--all'])
        # Fresh input so check cannot claim success after a tool unexpectedly mutates it.
        path.write_text('fn old() {}\n')
        def changes_config(*args, **kwargs): (source / 'rust/actors/Cargo.toml').write_text('modified')
        with self.assertRaisesRegex(ValueError, 'protected inventory'):
            format_guest.format_source(value, source, 'check', changes_config)


class ApplyResult(unittest.TestCase):
    setUp = Snapshots.setUp
    capture = Snapshots.capture
    def fixture_result(self):
        value = self.capture()
        changes=[]
        for entry in value['files']:
            if entry['path'].endswith('.rs'):
                data=b'fn formatted() {}\n'
                changes.append(dict(path=entry['path'],before_sha256=entry['sha256'],after_sha256=snapshot.sha(data),
                                    content_base64=base64.b64encode(data).decode()))
        report=complete(value,changes=changes)
        path=self.root/'result.json';path.write_bytes(snapshot.canonical(report))
        identity=dict(recipe_sha256='d'*64,implementation_sha256='e'*64)
        return value,path,identity,report['input_snapshot_sha256']

    def test_shared_apply_preserves_modes_index_and_unrelated_files(self):
        (self.repo/'rust/actors/old.rs').chmod(0o640)
        (self.repo/'native.cpp').write_text('unrelated dirty edit')
        before_index=(self.repo/'.git/index').read_bytes()
        value,path,identity,digest=self.fixture_result()
        result=snapshot_apply.apply_result(self.repo,self.base,path,identity,digest)
        self.assertEqual(result['scope'],'working-snapshot-apply');self.assertEqual(result['exit_code'],0)
        self.assertEqual((self.repo/'rust/actors/old.rs').stat().st_mode&0o777,0o640)
        self.assertEqual((self.repo/'native.cpp').read_text(),'unrelated dirty edit')
        self.assertEqual((self.repo/'.git/index').read_bytes(),before_index)
        self.assertEqual(snapshot.sha(snapshot.canonical(self.capture())),result['output_snapshot_sha256'])
        self.assertFalse(list(self.repo.rglob('.eqemu-format-*')))

    def test_partial_apply_and_receipt_failure_roll_back_every_owned_write(self):
        for kind in ('replace','receipt'):
            with self.subTest(kind=kind):
                value,path,identity,digest=self.fixture_result()
                original={e['path']:base64.b64decode(e['content_base64']) for e in value['files']}
                replace=os.replace;calls=[]
                def fail_second(*args,**kwargs):
                    calls.append(args)
                    if len(calls)==2:raise OSError('trusted injected second replacement failure')
                    return replace(*args,**kwargs)
                def receipt(_):raise OSError('trusted injected receipt publication failure')
                with patch.object(snapshot_apply.os,'replace',side_effect=fail_second if kind=='replace' else replace):
                    with self.assertRaises(OSError):
                        snapshot_apply.apply_result(self.repo,self.base,path,identity,digest,
                            publish_receipt=receipt if kind=='receipt' else None)
                self.assertEqual(original,{name:(self.repo/name).read_bytes() for name in original})
                self.assertFalse(list(self.repo.rglob('.eqemu-format-*')))

    def test_apply_refuses_stale_malformed_symlink_and_newer_edits(self):
        value,path,identity,digest=self.fixture_result()
        (self.repo/'rust/actors/old.rs').write_text('newer edit')
        with self.assertRaisesRegex(ValueError,'Stale'):
            snapshot_apply.apply_result(self.repo,self.base,path,identity,digest)
        self.assertEqual((self.repo/'rust/actors/old.rs').read_text(),'newer edit')
        link=self.root/'link';link.symlink_to(path)
        with self.assertRaises(OSError):snapshot_apply.apply_result(self.repo,self.base,link,identity,digest)
        path.write_text('{}')
        fresh=snapshot.sha(snapshot.canonical(self.capture()))
        with self.assertRaises(ValueError):snapshot_apply.apply_result(self.repo,self.base,path,identity,fresh)
        self.assertFalse(list(self.repo.rglob('.eqemu-format-*')))


class FormatRuntime(unittest.TestCase):
    def setUp(self):
        test_runtime.Runtime.setUp(self)

    def request_data(self):
        return dict(version=1, operation='format', base='a'*40, head='b'*40,
                    input_snapshot_sha256='c'*64, recipe_sha256='d'*64, bytes=3, sha256=snapshot.sha(b'ISO'),
                    files={'snapshot.json':dict(bytes=10,sha256='e'*64),
                           'rust-inputs.tar':dict(bytes=20,sha256=snapshot.RUST_INPUT_SHA256)})

    def test_formatter_uses_same_vm_ownership_without_native_resources(self):
        self.client.sendall(b'ISO'); request = self.request_data()
        def simulate(*args, **kwargs):
            args[-1](12345)
            kwargs['format_result'].update(exit_code=0, changed_files=[], output_snapshot_sha256=request['input_snapshot_sha256'],
                                          preparation_seconds=.1, format_seconds=.2, boot_seconds=.3)
            return 0
        with patch.object(runtime.shutil, 'disk_usage', return_value=type('Disk', (), {'free':100*1024**3})()), \
                patch.object(runtime, 'supervise', side_effect=simulate) as supervisor:
            result = runtime.run_vm(self.value, self.server, formatting=request)
        self.assertEqual(result['exit_code'],0,result); self.assertTrue(result['cleanup_complete'])
        self.assertTrue(result['vm_started']); self.assertIn('total_seconds',result['timings'])
        argv=supervisor.call_args.args[0]
        self.assertEqual(argv[argv.index('-m')+1],'1024'); self.assertEqual(argv[argv.index('-nic')+1],'none')
        self.assertFalse((self.state/'active.json').exists())
        self.assertFalse(any(p.is_dir() for p in self.state.iterdir()))

    def test_formatter_cancel_has_real_process_absence_and_scratch_cleanup(self):
        qemu = Path(runtime.QEMU)
        qemu.write_text('#!'+sys.executable+'\nimport time\ntime.sleep(30)\n')
        self.client.sendall(b'ISO'); reports=[]
        with patch.object(runtime.shutil,'disk_usage',return_value=type('Disk',(),{'free':100*1024**3})()):
            import threading
            thread=threading.Thread(target=lambda:reports.append(runtime.run_vm(self.value,self.server,formatting=self.request_data())))
            thread.start(); time.sleep(.2); self.client.close(); thread.join(3)
        self.assertFalse(thread.is_alive()); result=reports[0]
        self.assertEqual(result['exit_code'],2); self.assertTrue(result['cleanup_complete'])
        self.assertEqual(result['changed_files'],[]); self.assertFalse((self.state/'active.json').exists())
        with self.assertRaises(ProcessLookupError): os.kill(result['qemu_pid'],0)

    def test_formatter_result_framing_large_bounded_and_attributed(self):
        result=dict(version=1,nonce='a'*32,scope='working-snapshot-format',exit_code=0,
                    changed_files=[],output_snapshot_sha256='b'*64,error='x'*20000)
        script=self.root/'frame.py'
        script.write_text('print('+repr('EQEMU_FORMAT_RESULT '+base64.b64encode(snapshot.canonical(result)).decode())+')\n')
        detail={}
        self.assertEqual(runtime.supervise([sys.executable,str(script)],self.root,self.root/'frame.log',self.server,
                                          time.monotonic()+3,'a'*32,format_result=detail),0)
        self.assertEqual(detail['nonce'],'a'*32)
        (self.root/'frame.log').unlink()
        with self.assertRaisesRegex(RuntimeError,'Malformed formatter completion'):
            runtime.supervise([sys.executable,str(script)],self.root,self.root/'frame.log',self.server,
                              time.monotonic()+3,'f'*32,format_result={})

    def test_formatter_persistence_omits_bytes_and_check_never_retries(self):
        report=dict(scope='working-snapshot-format', changed_files=[dict(path='rust/actors/a.rs',
             before_sha256='a'*64, after_sha256='b'*64,content_base64='SOURCE')],
             exit_code=1, error='Diff: PRIVATE_RUST_SOURCE', cleanup_error='PRIVATE_CLEANUP_SOURCE')
        self.assertNotIn('SOURCE',json.dumps(runtime.persisted_report(report)))
        self.assertEqual(runtime.persisted_report(report)['failure_class'],'formatter-candidate-failure')
        self.assertIn('SOURCE',json.dumps(report))
        with patch.object(client,'exchange_once',side_effect=ConnectionResetError) as once:
            with self.assertRaises(ConnectionResetError): client.exchange('/unused',dict(self.request_data(),operation='check'))
            once.assert_called_once()

    def test_legacy_last_result_stdout_has_only_formatter_failure_metadata(self):
        raw=dict(scope='working-snapshot-format',exit_code=1,error='Diff: PRIVATE_SOURCE_MARKER',changed_files=[])
        observation=dict(version=1,scope='worker-observation',operation='last-result',exit_code=0,
                         result=runtime.persisted_report(raw))
        config=self.root/'client.json';config.write_text(json.dumps({'socket':'/unused'}))
        with patch.object(client,'exchange',return_value=observation),contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(client.main(['--last-result','--config',str(config)]),0)
        self.assertNotIn('PRIVATE_SOURCE_MARKER',output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['result']['failure_class'],'formatter-candidate-failure')

    def test_format_launcher_has_no_native_build_or_server_execution(self):
        data=json.loads(guest.format_user_data('a'*32,self.request_data()).split('\n',1)[1])
        self.assertIn('format-guest',data['runcmd'][0][-1])
        self.assertNotIn('native.iso',data['runcmd'][0][-1])
        self.assertEqual({e['path'] for e in data['write_files']},{'/opt/eqemu-worker-format-guest','/opt/build_guest.py',
            '/opt/snapshot.py','/opt/eqemu-worker-nonce','/opt/eqemu-format-request.json'})


class FormatCLI(unittest.TestCase):
    def setUp(self):
        loader=importlib.machinery.SourceFileLoader('formatter_cli',str(ROOT/'scripts/format-worker-snapshot'))
        spec=importlib.util.spec_from_loader(loader.name,loader)
        self.cli=importlib.util.module_from_spec(spec); loader.exec_module(self.cli)

    def test_identity_is_stable_and_pins_final_formatter_bundle_without_worker(self):
        expected=format_prepare.tool_identity(ROOT)
        with patch.object(self.cli,'exchange') as exchange, patch.object(self.cli,'prepare') as prepare, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(self.cli.main(['--identity']),0)
        self.assertEqual(json.loads(output.getvalue()),expected)
        exchange.assert_not_called();prepare.assert_not_called()
        self.assertEqual(expected['rust_input_sha256'],snapshot.RUST_INPUT_SHA256)
        self.assertEqual(expected['implementation_sha256'],runtime.implementation_identity({'code_dir':str(ROOT)}))

    def test_stale_cli_result_has_input_identity_and_private_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);repo,base=source_fixture(root)
            identity=format_prepare.tool_identity(ROOT)
            before=snapshot.capture(repo,base,identity['recipe_sha256'])
            entry=next(e for e in before['files'] if e['path'].endswith('old.rs'))
            data=b'fn formatted() {}\n'
            change=dict(path=entry['path'],before_sha256=entry['sha256'],after_sha256=snapshot.sha(data),
                        content_base64=base64.b64encode(data).decode())
            response=complete(before,changes=[change]);response['implementation_sha256']=identity['implementation_sha256']
            config=root/'config.json';config.write_text(json.dumps({'socket':'/unused'}))
            output=root/'result.json'
            def exchange(*args):
                if args[1]==dict(version=1,operation='check'):return {'exit_code':0}
                (repo/'rust/actors/old.rs').write_text('newer caller edit')
                return response
            with patch.object(self.cli,'exchange',side_effect=exchange),patch.object(self.cli,'prepare',return_value={'operation':'format'}), \
                    contextlib.redirect_stdout(io.StringIO()) as public:
                self.assertEqual(self.cli.main(['--repo',str(repo),'--base',base,'--config',str(config),'--output',str(output)]),2)
            result=json.loads(output.read_text())
            self.assertEqual(result['changed_files'],[])
            self.assertEqual(result['output_snapshot_sha256'],result['input_snapshot_sha256'])
            self.assertNotEqual(result['output_snapshot_sha256'],response['output_snapshot_sha256'])
            self.assertTrue(result['vm_started']);self.assertTrue(result['cleanup_complete'])
            self.assertNotIn('newer caller edit',public.getvalue())
            snapshot.validate_result(result,before,'format',identity['implementation_sha256'])

    def test_malformed_worker_cannot_supply_public_bindings_or_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);repo,base=source_fixture(root)
            identity=format_prepare.tool_identity(ROOT)
            before=snapshot.capture(repo,base,identity['recipe_sha256'])
            forged=dict(version=1,scope='working-snapshot-format',exit_code=0,changed_files=[],
                        input_snapshot_sha256='FORGED_PRIVATE_SOURCE',output_snapshot_sha256='FORGED_OUTPUT',
                        implementation_sha256='FORGED_TOOL',timings={'secret':'FORGED_PRIVATE_SOURCE'})
            config=root/'config.json';config.write_text(json.dumps({'socket':'/unused'}))
            output=root/'result.json'
            with patch.object(self.cli,'exchange',side_effect=[{'exit_code':0},forged]), \
                    patch.object(self.cli,'prepare',return_value={'operation':'format'}),contextlib.redirect_stdout(io.StringIO()) as public:
                self.assertEqual(self.cli.main(['--repo',str(repo),'--base',base,'--config',str(config),'--output',str(output)]),2)
            result=json.loads(output.read_text())
            self.assertEqual(result['input_snapshot_sha256'],snapshot.sha(snapshot.canonical(before)))
            self.assertEqual(result['output_snapshot_sha256'],result['input_snapshot_sha256'])
            self.assertEqual(result['implementation_sha256'],identity['implementation_sha256'])
            self.assertIsNone(result['vm_started']);self.assertFalse(result['cleanup_complete'])
            self.assertNotIn('FORGED',public.getvalue());self.assertNotIn('timings',result)

    def test_fresh_artifact_no_overwrite_and_private_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'result.json'
            self.cli.publish(path,{'exit_code':2})
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            with self.assertRaises(FileExistsError): self.cli.publish(path,{'exit_code':0})
            self.assertEqual(json.loads(path.read_text()),{'exit_code':2})
            link=Path(tmp)/'link';link.symlink_to(path)
            with self.assertRaises(FileExistsError):self.cli.publish(link,{'exit_code':0})


if __name__=='__main__':unittest.main()
