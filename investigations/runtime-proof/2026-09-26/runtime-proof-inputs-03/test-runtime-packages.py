"""Run real APT simulation against inert pinned packages. Never install or download."""
import hashlib,importlib.util,json,os,pathlib,re,shutil,subprocess,tempfile,unittest
D=pathlib.Path(__file__).resolve().parent
R=D.parent/'runtime-inputs-20260926'
spec=importlib.util.spec_from_file_location('runtime',D/'guest-runtime.py');G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)

class OfflineCache(unittest.TestCase):
 def test_pool_names_fail_staging_succeeds_missing_archive_fails(self):
  proof=json.loads((R/'evidence/runtime-package-proof.json').read_text());packages=proof['packages']
  allowed={(p['Package'],p['Version']) for p in packages}
  with tempfile.TemporaryDirectory(prefix='eqemu-runtime-apt-') as td:
   a=pathlib.Path(td)/'apt'
   shutil.copytree(R/'apt',a,ignore=shutil.ignore_patterns('cache','log','lock','lock-frontend','partial'))
   for d in ['cache/archives/partial','log','no-parts','no-sources']:(a/d).mkdir(parents=True,exist_ok=True)
   for name in ['apt.conf','sources.list']:
    p=a/name;p.write_text(p.read_text().replace(str(R/'apt'),str(a)))
   source=pathlib.Path(td)/'debs';source.mkdir();cache=a/'cache/archives'
   for f in (R/'apt/cache/archives').glob('*.deb'):shutil.copyfile(f,source/f.name)
   before={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in source.glob('*.deb')}
   for f in source.glob('*.deb'):shutil.copyfile(f,cache/f.name)
   cmd=['apt-get','-s','--no-download','--no-remove','-y','-o','Dpkg::Options::=--force-confdef','-o','Dpkg::Options::=--force-confold','install',*[p+'='+v for p,v in sorted(allowed)]]
   def simulate():
    return subprocess.run(cmd,env={**os.environ,'APT_CONFIG':str(a/'apt.conf'),'LC_ALL':'C'},text=True,capture_output=True,timeout=30)
   bad=simulate();self.assertEqual(bad.returncode,100);self.assertIn('Unable to fetch some archives',bad.stderr)
   for f in cache.glob('*.deb'):f.unlink()
   G.stage_runtime_packages(packages,source,cache)
   good=simulate();self.assertEqual(good.returncode,0,good.stdout+good.stderr)
   selected=set(re.findall(r'^Inst (\S+) \((\S+)',good.stdout,re.M));self.assertEqual(selected,allowed)
   self.assertIn('0 upgraded, 15 newly installed, 0 to remove',good.stdout)
   self.assertEqual(len(list(cache.glob('*%3a*.deb'))),6)
   self.assertEqual({f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in source.glob('*.deb')},before)
   next(cache.glob('*%3a*.deb')).unlink()
   missing=simulate();self.assertEqual(missing.returncode,100);self.assertIn('Unable to fetch some archives',missing.stderr)

if __name__=='__main__':unittest.main(verbosity=2)
