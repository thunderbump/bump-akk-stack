"""Checked root-launch bytes and self-copy controls, exercised without sudo or privilege."""
import hashlib
from pathlib import Path
import stat
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation'))
import common

launch=common.load('rust_checked_launch',ROOT/'validation/rust/launch.py')
vm=common.load('rust_checked_launch_wrapper',ROOT/'validation/rust/prepare_vm_proof.py')


class CheckedLaunch(unittest.TestCase):
    def test_generated_wrapper_quotes_paths_and_embeds_checked_root_side_bootstrap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/"proof's path $(untrusted)";root.mkdir()
            script=root/'controller.py';seed=root/'seed.iso';media=root/'rust.iso'
            for file in (script,seed,media):file.write_text('checked data')
            text=vm.operator_wrapper(root,script,seed,media)
            args=shlex.split(text[text.index('exec /usr/bin/sudo'):])
            self.assertEqual(args[:5],['exec','/usr/bin/sudo','/usr/bin/python3','-I','-c'])
            self.assertEqual(args[-2:],[str(script),common.sha(script)])
            self.assertEqual(args[5],(ROOT/'validation/rust/launch.py').read_text())
            self.assertIn('seed.iso',text);self.assertIn('rust.iso',text)
            wrapper=root/'reviewed-run.sh';wrapper.write_text(text)
            # Shell syntax only, never executes sudo or the controller.
            subprocess.run(['/bin/sh','-n',str(wrapper)],check=True,timeout=10)

    def test_tamper_oversize_symlink_and_special_input_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'controller.py';source.write_bytes(b'print("reviewed")\n')
            digest=hashlib.sha256(source.read_bytes()).hexdigest()
            self.assertEqual(launch.checked_bytes(source,digest),source.read_bytes())
            source.write_bytes(b'print("changed after review")\n')
            with self.assertRaisesRegex(ValueError,'bytes changed'):launch.checked_bytes(source,digest)
            source.write_bytes(b'x'*(launch.LIMIT+1))
            with self.assertRaisesRegex(ValueError,'bounded regular'):launch.checked_bytes(source,digest)
            source.unlink();source.symlink_to(root/'missing')
            with self.assertRaises(OSError):launch.checked_bytes(source,digest)
            with self.assertRaisesRegex(ValueError,'bounded regular'):launch.checked_bytes(root,digest)

    def test_checked_stage_survives_untrusted_source_replacement_and_self_copies_exact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'untrusted.py';copied=root/'service-script.py'
            body=('from pathlib import Path\nimport sys\n'
                  'assert sys.argv == [__file__]\n'
                  'Path('+repr(str(copied))+').write_bytes(Path(__file__).read_bytes())\n').encode()
            source.write_bytes(body);digest=hashlib.sha256(body).hexdigest()
            checked=launch.checked_bytes(source,digest)
            source.write_text('raise RuntimeError("unreviewed replacement executed")\n')
            previous=list(sys.argv)
            with launch.staged_script(checked,root) as staged:
                directory=staged.parent
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode),0o700)
                self.assertEqual(stat.S_IMODE(staged.stat().st_mode),0o600)
                self.assertEqual(staged.read_bytes(),body)
                launch.execute(checked,staged)
                self.assertEqual(copied.read_bytes(),body)
                self.assertEqual(hashlib.sha256(copied.read_bytes()).hexdigest(),digest)
            self.assertFalse(directory.exists())
            self.assertEqual(sys.argv,previous)
            self.assertIn('unreviewed replacement',source.read_text())


if __name__=='__main__':unittest.main()
