"""Initialized dependency cleanliness uses its own finite inventory budget."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation'))
import inputs


def git(repo,*args):
    return subprocess.check_output(['/usr/bin/git','-C',str(repo),*args],stderr=subprocess.DEVNULL).decode().strip()


class InitializedInventory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='eqemu-large-inventory-')
        cls.origin=Path(cls.temp.name)/'origin';cls.origin.mkdir()
        git(cls.origin,'init','-q')
        # More than the transferred-source bound, below the fixed cleanliness bound.
        for index in range(10001):(cls.origin/('%05d'%index)).write_bytes(b'clean\n')
        git(cls.origin,'add','.')
        git(cls.origin,'-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','pinned dependency')
        cls.commit=git(cls.origin,'rev-parse','HEAD');cls.tree=git(cls.origin,'rev-parse','HEAD^{tree}')

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='eqemu-initialized-test-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.repo=self.root/'eqemu';self.repo.mkdir()
        git(self.repo,'init','-q');(self.repo/'source').write_text('candidate source\n')
        git(self.repo,'add','source');git(self.repo,'update-index','--add','--cacheinfo','160000,'+self.commit+',submodules/vcpkg')
        git(self.repo,'-c','user.name=Test','-c','user.email=test@example.invalid','commit','-qm','candidate')
        self.module=self.repo/'submodules/vcpkg'
        subprocess.run(['/usr/bin/git','clone','-q','--shared',str(self.origin),str(self.module)],check=True)
        self.store=self.root/'store';self.store.mkdir()
        self.profile=dict(sources={'eqemu':dict(commit=git(self.repo,'rev-parse','HEAD'),
            tree=git(self.repo,'rev-parse','HEAD^{tree}'),gitlinks={'submodules/vcpkg':self.commit})},
            dependencies={},dependency_blobs={},submodule_sources={'submodules/vcpkg':'vcpkg'},
            submodules={'vcpkg':dict(commit=self.commit,tree=self.tree)})

    def prepare(self):
        return inputs.prepare(self.profile,{'eqemu':self.repo},self.store,self.root/'output')

    def test_initialized_large_pinned_dependency_is_checked_without_transfer(self):
        receipt=self.prepare()
        self.assertEqual(receipt['files'],1)
        manifest=json.loads((self.root/'output/manifest.json').read_text())
        self.assertEqual(set(manifest['sources']),{'eqemu'})
        self.assertEqual({p.name for p in (self.root/'output').iterdir()},{'manifest.json','eqemu.tar'})

    def test_large_initialized_dependency_still_refuses_dirty_staged_swapped_and_untracked(self):
        tracked=self.module/'00000';original=tracked.read_bytes()
        for mode,error in [('raw','Dirty source bytes'),('staged','Dirty source index'),
                           ('head','Source HEAD mismatch'),('untracked','Untracked source file')]:
            with self.subTest(mode=mode):
                if mode in ('raw','staged'):
                    tracked.write_bytes(b'wrong\n')
                    if mode=='staged':git(self.module,'add','00000');tracked.write_bytes(original)
                if mode=='head':git(self.module,'-c','user.name=Test','-c','user.email=test@example.invalid',
                                    'commit','--allow-empty','-qm','different HEAD')
                if mode=='untracked':(self.module/'unexpected').write_text('wrong')
                with self.assertRaisesRegex(ValueError,error):self.prepare()
                self.assertFalse((self.root/'output').exists())
                git(self.module,'reset','--hard',self.commit)
                (self.module/'unexpected').unlink(missing_ok=True)

    def test_transferred_source_keeps_default_file_and_byte_budgets(self):
        scratch=self.root/'view';scratch.mkdir()
        view=inputs.GitTree(self.module,scratch)
        with self.assertRaisesRegex(ValueError,'Source inventory exceeds budget'):
            view.inventory(self.commit,self.tree)
        original=view.git
        def objects(*args,**kwargs):
            if args[0]=='ls-tree':
                return ('100644 blob '+'a'*40+' '+str(inputs.SOURCE_LIMIT+1)+'\toversized\0').encode()
            return original(*args,**kwargs)
        with patch.object(view,'git',objects),self.assertRaisesRegex(ValueError,'Source inventory exceeds budget'):
            view.inventory(self.commit,self.tree)

    def test_initialized_file_and_byte_budgets_stay_finite(self):
        for mode in ('files','bytes'):
            with self.subTest(mode=mode):
                original=inputs.GitTree.git
                def objects(view,*args,**kwargs):
                    if view.repo==self.module and args[0]=='ls-tree':
                        count=20001 if mode=='files' else 1
                        size=1 if mode=='files' else inputs.SOURCE_LIMIT+1
                        return b''.join(('100644 blob '+'a'*40+' '+str(size)+'\tf'+str(i)+'\0').encode() for i in range(count))
                    return original(view,*args,**kwargs)
                with patch.object(inputs.GitTree,'git',objects),self.assertRaisesRegex(ValueError,'Source inventory exceeds budget'):
                    self.prepare()
                self.assertFalse((self.root/'output').exists())

    def test_initialized_index_budget_is_unchanged(self):
        with (self.module/'.git/index').open('r+b') as stream:stream.truncate(16*1024**2+1)
        with self.assertRaisesRegex(ValueError,'bounded regular'):
            self.prepare()
        self.assertFalse((self.root/'output').exists())


if __name__=='__main__':unittest.main()
