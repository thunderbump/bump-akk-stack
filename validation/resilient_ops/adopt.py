"""Separately reviewed, fixed host adoption. Never called by the socket protocol.

Run only from a protected hash-verified package as root, with ingress held.
Interrupted adoption refuses a second apply; an administrator must reconcile it.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

CONTRACT_SHA = 'dbd6bc9bccd5acf9df40b60caef95f3c0c0c6568a451918a738111715a8f6698'


def contract():
    raw = (Path(__file__).resolve().parent/'enrollment-contract.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != CONTRACT_SHA:
        raise ValueError('reviewed external contract changed')
    return json.loads(raw)


def policy_for(packet):
    common = dict(root='/var/lib/eqemu-resilient-targets/validator-worker-code',
                  units=['eqemu-validator@.service'], service_uid=995, timeout=30,
                  max_bytes=4*1024*1024, max_files=256, host_contract=CONTRACT_SHA)
    return {'peers':[dict(uid=1000,gid=1000,methods=['prepare','execute','status'],
                         targets=['validator-worker-code','validator-integration-evidence'],
                         actions=['publish','revert','recover'])],
            'targets':{
                'validator-worker-code':dict(common,actions=['publish','revert','recover'],resources=['validator-worker-code'],files=packet['authority']['approved_release_paths']),
                'validator-integration-evidence':dict(common,root='/var/lib/eqemu-resilient-targets/validator-integration-evidence',actions=['recover'],resources=['validator-integration-evidence','validator-ordinary-state'],files=list(packet['migration']['observed_records']['files']))}}


def verified_files(root, entries):
    """Only the explicit public/migration manifest, never backups or other state."""
    result = {}
    for item in entries:
        path = root/item['path']
        for parent in (path.parent, *path.parent.parents):
            if parent.is_symlink():
                raise ValueError('manifest parent link rejected')
            if parent == root:
                break
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('manifest requires unlinked regular files')
            with os.fdopen(fd,'rb',closefd=False) as source:
                raw = source.read(item['bytes']+1)
            if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
                raise ValueError('current bytes differ from reviewed external facts')
            result[item['path']] = raw
        finally:
            os.close(fd)
    return result


def apply(expected_operator, confinement_reviewed):
    # Check ancestors and every dependency before importing privileged helpers.
    here = Path(__file__).resolve().parent
    for path in (here, *here.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('protected immutable adoption release required')
    info = (here/'manifest.json').lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('protected package manifest required')
    manifest = json.loads((here/'manifest.json').read_bytes())
    for name, expected in manifest['assets'].items():
        if '/' in name or name in ('.', '..'):
            raise ValueError('invalid adoption asset')
        info = (here/name).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or hashlib.sha256((here/name).read_bytes()).hexdigest() != expected:
            raise ValueError('adoption dependency integrity failure')
    from engine import Engine, atomic, canonical, digest, protected, sync_dir
    from host import HostManager
    here=Path(__file__).resolve().parent
    protected(here,0)
    if os.geteuid()!=0 or hashlib.sha256(Path(__file__).read_bytes()).hexdigest()!=expected_operator:
        raise ValueError('reviewed root adoption operator required')
    if not confinement_reviewed:
        raise ValueError('administrative requirement: separately review confinement and fixed launcher compatibility')
    packet=contract()
    policy=policy_for(packet)
    store=Path('/var/lib/eqemu-resilient-ops')
    protected(store,0)
    intent=store/'host-adoption-intent.json'
    if intent.exists():
        raise ValueError('prior adoption intent retained; reconcile explicitly, never replay')
    configuration=Path('/etc/eqemu-resilient-ops/policy.json')
    if configuration.exists() and json.loads(configuration.read_bytes()).get('targets'):
        raise ValueError('existing enrollment is outside initial adoption')
    # Revalidate all finite public privileged integration assets before mutation.
    for section in ('installed_unit_definitions','installed_configs'):
        for entry in packet[section]:
            path=Path(entry['definition'])
            protected(path.parent,0)
            info=path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or hashlib.sha256(path.read_bytes()).hexdigest()!=entry['sha256']:
                raise ValueError('privileged integration asset changed; separate review required')
    for entry in packet['installed_unit_definitions']:
        for prefix in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system'):
            if list((Path(prefix)/(entry['unit']+'.d')).glob('*.conf')):
                raise ValueError('new unit override requires separate review')
    atomic(intent,{'state':'intent','contract':CONTRACT_SHA,'original_outcome':packet['migration']['original_outcome']})
    manager=HostManager()
    code=policy['targets']['validator-worker-code']
    before=manager.observe(code)
    manager.stop(code)
    # guard is a fixed existing worker.lock. No force-unlock or inode replacement.
    with manager.guard(code):
        original=Path('/srv/eqemu-validator-code')
        if original.is_symlink() or not original.is_dir():
            raise ValueError('initial code binding must be original reviewed directory')
        release_bytes=verified_files(original,packet['current_code']['fresh_files'])
        workspace=Path(packet['migration']['workspace'])
        legacy_entries=[dict(info,path=name) for name,info in packet['migration']['observed_records']['files'].items()]
        legacy_bytes=verified_files(workspace,legacy_entries)
        # Historical metadata is revalidated; no inference from missing cleanup/ACK.
        for name,info in packet['migration']['observed_records']['files'].items():
            st=(workspace/name).lstat()
            if (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(info['uid'],info['gid'],info['mode']):
                raise ValueError('retained workspace ownership differs; preserve for review')
        for target in policy['targets'].values():
            root=Path(target['root'])
            if root.exists():
                raise ValueError('fresh managed roots required')
            root.parent.mkdir(mode=0o711,exist_ok=True)
            os.chmod(root.parent,0o711)
            protected(root.parent,0)
            root.mkdir(mode=0o711)
            os.chmod(root,0o711)
        engine=Engine(policy,store,manager)
        prepared=engine.handle(dict(method='prepare',request_id='host-adoption-initial-code',target='validator-worker-code',action='publish',generation=0,artifact={k:base64.b64encode(v).decode() for k,v in release_bytes.items()}),(1000,1000))
        code_root=Path(code['root'])
        initial=prepared['plan_id']
        atomic(code_root/'current.json',dict(generation=0,workspace_generation=0,release=initial),0o644)
        evidence_root=Path(policy['targets']['validator-integration-evidence']['root'])
        for name in ('evidence','quarantine','workspaces','releases'):
            (evidence_root/name).mkdir(mode=0o711 if name in ('workspaces','releases') else 0o700)
        old=dict(operation_id='legacy-02fee-retained',plan_id='root-adoption',target='validator-integration-evidence',resources=['validator-integration-evidence','validator-ordinary-state'],state='failed',step='retained-root-audit-revalidated',recovery_required=True,original_outcome=packet['migration']['original_outcome'],contract=CONTRACT_SHA)
        atomic(store/'operations/legacy-02fee-retained.json',old)
        atomic(evidence_root/'current.json',dict(generation=0,workspace_generation=0,release=None),0o644)
        sealed=evidence_root/'evidence/0'
        sealed.mkdir(mode=0o700)
        (sealed/'workspace').mkdir(mode=0o700)
        for name,raw in legacy_bytes.items():
            destination=sealed/'workspace'/name
            with destination.open('xb') as out:
                os.fchmod(out.fileno(),0o600)
                out.write(raw);out.flush();os.fsync(out.fileno())
        atomic(sealed/'original-operation.json',old)
        for path in (sealed/'workspace',sealed,sealed.parent): sync_dir(path)
        if workspace.stat().st_dev != (evidence_root/'quarantine').stat().st_dev:
            raise ValueError('workspace retirement requires same filesystem; original untouched')
        backup=Path('/srv/eqemu-resilient-adoption')
        backup.mkdir(mode=0o700,exist_ok=True)
        protected(backup,0)
        retained=backup/'original-code'
        if retained.exists(): raise ValueError('retained original code already exists')
        os.rename(original,retained)
        sync_dir(backup);sync_dir(original.parent)
        # Initial adoption alone creates the external link. Routine publication only
        # replaces an established managed link, never an existing directory.
        original.symlink_to(code_root/'releases'/initial)
        sync_dir(original.parent)
        configuration.parent.mkdir(mode=0o700,exist_ok=True)
        atomic(configuration,policy)
        atomic(store/'host-adoption-result.json',{'state':'succeeded','contract':CONTRACT_SHA,'code_release':initial,'legacy_operation':'legacy-02fee-retained','workload_started':False})
        # No workload/ingress is started by adoption. HOLD persists. The old broker
        # and old original tree are retained, with its ingress left fenced.
        return {'adopted':True,'activation_performed':False,'original_history_preserved':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-operator',required=True)
    parser.add_argument('--confinement-reviewed',action='store_true')
    args=parser.parse_args()
    print(json.dumps(apply(args.expected_operator,args.confinement_reviewed),sort_keys=True))


if __name__=='__main__':
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    main()
