"""Sealed opt-in recipe and host evidence controls; no VM or native compilation."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'validation'))
import common
import native_diagnostics as diagnostic
import render
import test_packaging


class StaticRecipe(unittest.TestCase):
    def setUp(self):
        self.fixture=test_packaging.PackagePreparation('test_rendered_workers_use_owned_inputs_without_history')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups);self.fixture.prepare()
        self.package=self.fixture.root/'output';self.destination=self.fixture.root/'rendered';self.destination.mkdir()

    def render(self,profile):
        with patch.object(render.subprocess,'run',side_effect=lambda argv,**_:Path(argv[1]).write_bytes(b'seed')):
            render.render('0123456789',test_packaging.FACTS,self.destination,self.package,profile_name=profile)
        return common.load('static_recipe_worker',self.destination/'producer-worker.py')

    def summary(self):
        return dict(version=1,profile=diagnostic.PROFILE,complete=True,compile_database_sha256='a'*64,
            checks=list(diagnostic.CHECKS),targets=[dict(target=n,exit_code=0,findings=0,wall_seconds=1) for n in diagnostic.TARGETS],
            findings=[],wall_seconds=2,child_peak_rss_kib=90000)

    def test_opt_in_bound_to_producer_with_sealed_helper_and_same_build(self):
        worker=self.render(diagnostic.PROFILE)
        self.assertEqual(worker.VALIDATION_PROFILE,diagnostic.PROFILE)
        user=json.loads((self.destination/'producer-user-data').read_text().split('\n',1)[1])
        files={r['path']:r.get('content') for r in user['write_files']}
        self.assertEqual(files['/opt/eqemu-proof/native_diagnostics.py'],(self.package/'native_diagnostics.py').read_text())
        guest=files['/opt/eqemu-proof/guest_build.py']
        self.assertIn("VALIDATION_PROFILE='build-static-unit-v1'",guest)
        self.assertLess(guest.index("command('server-build'"),guest.index("command('native-static-pilot'"))
        consumer=common.load('static_recipe_consumer',self.destination/'consumer-worker.py')
        self.assertNotIn('runtime.iso',consumer.FILES)
        import xml.etree.ElementTree as ET
        tree=ET.fromstring(consumer.domain({'uuid':'00000000-0000-4000-8000-000000000031','profile':'p'}))
        consumer.validate_devices(tree)
        self.assertEqual(len(tree.findall('./devices/disk')),4)
        consumer.VALIDATION_PROFILE='unknown'
        with self.assertRaisesRegex(RuntimeError,'Unknown guest device profile'):consumer.validate_devices(tree)

    def test_host_refuses_missing_incomplete_or_wrong_profile_static_evidence(self):
        worker=self.render(diagnostic.PROFILE);protocol=worker.BuildProtocol('n'*32);protocol.ready=True
        value=dict(kind='observation',nonce='n'*32,name='native-static-pilot',value=self.summary())
        self.assertEqual(protocol.accept(value),'observation')
        for mutation in ('missing-target','finding','bool-exit','wrong-checks','nonfinite'):
            item=self.summary()
            if mutation=='missing-target':item['targets'].pop()
            elif mutation=='finding':item['findings']=[{}]
            elif mutation=='bool-exit':item['targets'][0]['exit_code']=False
            elif mutation=='wrong-checks':item['checks']=[]
            else:item['wall_seconds']=float('nan')
            with self.subTest(mutation=mutation),self.assertRaises(RuntimeError):
                p=worker.BuildProtocol('n'*32);p.ready=True;p.accept(dict(value,value=item))
        protocol=worker.ProducerBuildProtocol('n'*32);protocol.ready=True
        protocol.observations={n:{} for n in {'candidate','utility','measurement','reporting-controls',
            *('runner-'+m for m in worker.EXPECTED),*('loader-'+str(i) for i in range(6))}}
        with self.assertRaisesRegex(RuntimeError,'Incomplete corrected build evidence'):
            protocol.accept(dict(kind='result',ok=True))
        worker.VALIDATION_PROFILE='build-unit-v1';protocol=worker.BuildProtocol('n'*32);protocol.ready=True
        with self.assertRaisesRegex(RuntimeError,'Unexpected native static'):protocol.accept(value)


if __name__=='__main__':unittest.main()
