"""Prepare a fresh worker identity while preserving attempt 03 workload/media bytes."""
from pathlib import Path
import hashlib,json,shutil
B=Path(__file__).resolve().parent;old=B/'build-proof-inputs-v3';new=B/'build-proof-inputs-v4'
assert not new.exists() and not (B/'offline-build-proof-v4.py').exists()
prior=Path('/var/lib/eqemu-vm-proof/build-proof-03/suite-result.json')
assert hashlib.sha256(prior.read_bytes()).hexdigest()=='3dc79bb99749f6d202e37aa217e94b3e3eb27fe12d4418c70aa93b0e3da834d7'
r=json.loads(prior.read_text());assert r['suite_passed'] and r['cleanup']['complete'] and not r['cleanup']['rescued']
assert not json.loads((prior.parent/'leases.json').read_text())['active'] and not (prior.parent/'build/data').exists()
new.mkdir()
for name in ['guest.py','host-transport.py','seed.iso','user-data','meta-data']:
 shutil.copyfile(old/name,new/name)
worker=(old/'build-worker.py').read_text()
worker=worker.replace('build-proof-03','build-proof-04').replace('build-03','build-04').replace('build03','build04').replace('build-proof-inputs-v3','build-proof-inputs-v4')
compile(worker,str(new/'build-worker.py'),'exec');(new/'build-worker.py').write_text(worker)
worker_sha=hashlib.sha256(worker.encode()).hexdigest()
suite=(B/'offline-build-proof-v3.py').read_text()
suite=suite.replace('build-proof-03','build-proof-04').replace('build-03','build-04').replace('build03','build04').replace('build-proof-inputs-v3','build-proof-inputs-v4')
suite=suite.replace('7791233f965fc143d4a59b2f1af0f1ca597e7d093f1b0cfb065b7711b798ff17',worker_sha)
suite=suite.replace('build-proof-02','build-proof-03').replace('8d9f19ec8217b869ebe391b32648c11cde31476119a54e61ce01a0afbc758438','3dc79bb99749f6d202e37aa217e94b3e3eb27fe12d4418c70aa93b0e3da834d7')
suite=suite.replace("r.get('suite_passed') is not False", "r.get('suite_passed') is not True")
suite=suite.replace('Prior failed attempt cleanup/provenance changed','Prior successful attempt cleanup/provenance changed')
compile(suite,str(B/'offline-build-proof-v4.py'),'exec');(B/'offline-build-proof-v4.py').write_text(suite)
(new/'test-build-proof.py').write_text((old/'test-build-proof.py').read_text().replace('offline-build-proof-v3.py','offline-build-proof-v4.py'))
manifest={'worker_sha256':worker_sha,'launcher_sha256':hashlib.sha256(suite.encode()).hexdigest(),'seed_sha256':hashlib.sha256((new/'seed.iso').read_bytes()).hexdigest(),'seed_bytes':(new/'seed.iso').stat().st_size,'input_iso_sha256':'02e94c23126772a5ca81ac7974661c3010cbdbba8da7647b8ac6cedac6c3cca4','previous_suite_sha256':hashlib.sha256(prior.read_bytes()).hexdigest(),'unchanged_files':{n:hashlib.sha256((new/n).read_bytes()).hexdigest() for n in ['guest.py','host-transport.py','seed.iso','user-data','meta-data']}}
for n in manifest['unchanged_files']:assert (old/n).read_bytes()==(new/n).read_bytes()
normalized=worker.replace('build-proof-04','build-proof-03').replace('build-04','build-03').replace('build04','build03').replace('build-proof-inputs-v4','build-proof-inputs-v3')
assert normalized==(old/'build-worker.py').read_text()
manifest['worker_changes_only_run_identity']=True
(new/'generated-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');print(json.dumps(manifest,indent=2))
