"""Real scratch files and fake account/service calls; never modifies the host."""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('worker_setup',ROOT/'validation/worker/setup.py')
setup=importlib.util.module_from_spec(spec);spec.loader.exec_module(setup)


class FakeHost(setup.Host):
    def __init__(self,root):
        super().__init__(root)
        self.admin_uid=os.getuid();self.calls=[];self.owners={}
        self.users={'submitter':SimpleNamespace(pw_name='submitter',pw_uid=os.getuid()+1002,
                    pw_gid=4002,pw_dir='/home/submitter',pw_shell='/bin/bash')}
        self.groups_by_name={'submitter':SimpleNamespace(gr_name='submitter',gr_gid=4002,gr_mem=[]),
                             'kvm':SimpleNamespace(gr_name='kvm',gr_gid=3000,gr_mem=[])}

    def info(self,path):
        info=list(path.lstat())
        if str(path) in self.owners:info[4],info[5]=self.owners[str(path)]
        if path==self.path('/dev/kvm'):info[0]=stat.S_IFCHR|0o660;info[5]=3000
        return os.stat_result(info)

    def chown(self,path,uid,gid):self.owners[str(path)]=(uid,gid)
    def user(self,name):return self.users.get(name)
    def group(self,name):
        if isinstance(name,int):return next((g for g in self.groups_by_name.values() if g.gr_gid==name),None)
        return self.groups_by_name.get(name)
    def groups(self,name,gid):return [gid]
    def run(self,args):
        self.calls.append(args)
        if args[0]=='/usr/sbin/useradd':
            name=args[-1];gid=4001
            self.users[name]=SimpleNamespace(pw_name=name,pw_uid=os.getuid()+1001,pw_gid=gid,
                pw_dir=args[args.index('--home-dir')+1],pw_shell=args[args.index('--shell')+1])
            self.groups_by_name[name]=SimpleNamespace(gr_name=name,gr_gid=gid,gr_mem=[])
        if args[1:] == ['--version']:return 'systemd 259 (259.1)\n'
        if args[1:2]==['list-units']:return ''
        if args[0]=='/usr/sbin/apparmor_parser':
            self.path('/sys/kernel/security/apparmor/profiles').write_text('eqemu-validator (enforce)\n')
        if args[1:2]==['is-active']:return 'active\n'
        return ''


class WorkerSetup(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.host=FakeHost(Path(temp.name));self.host.root.chmod(0o755)
        for directory in ('/etc','/etc/systemd/system','/etc/apparmor.d','/var/lib','/srv','/dev',
                          '/run','/usr/bin','/usr/sbin','/sys/module/apparmor/parameters',
                          '/sys/fs/cgroup','/sys/kernel/security/apparmor'):
            self.host.path(directory).mkdir(parents=True,exist_ok=True)
        for directory in self.host.root.rglob('*'):
            if directory.is_dir():directory.chmod(0o755)
        self.host.path('/etc/os-release').write_text('ID=ubuntu\nVERSION_ID="26.04"\n')
        self.host.path('/sys/module/apparmor/parameters/enabled').write_text('Y\n')
        self.host.path('/sys/fs/cgroup/cgroup.controllers').write_text('cpu memory pids\n')
        self.host.path('/sys/kernel/security/apparmor/profiles').write_text('')
        self.host.path('/dev/kvm').touch()
        for name in (*setup.TOOLS,'/usr/sbin/nologin'):
            self.host.path(name).write_text('#!/bin/sh\n');self.host.path(name).chmod(0o755)
        self.args=argparse.Namespace(user='eqemu-validator',state_dir='/var/lib/eqemu-validator',
            code_dir='/srv/eqemu-validator-code',base_image='/var/lib/eqemu-validator-inputs/base.qcow2',
            submitter='submitter',apply=False,check=False,dry_run=True,account_only=True)

    def snapshot(self):
        return {str(p.relative_to(self.host.root)):(p.lstat().st_mode,p.read_bytes() if p.is_file() else None)
                for p in self.host.root.rglob('*')}

    def full_inputs(self):
        code=self.host.path(self.args.code_dir)
        (code/'validation/worker').mkdir(parents=True)
        (code/'scripts').mkdir()
        for name in ('validation/worker/runtime.py','validation/worker/guest.py',
                     'validation/worker/client.py','scripts/check-validation-worker'):
            (code/name).write_text('"""Synthetic reviewed runtime bytes, not executed."""\n')
        for path in (code,*code.rglob('*')):
            self.host.chown(path,self.host.users['submitter'].pw_uid,4002)
            path.chmod(0o755 if path.is_dir() else 0o644)
        (code/'scripts/check-validation-worker').chmod(0o755)
        base=self.host.path(self.args.base_image);base.parent.mkdir();base.parent.chmod(0o755)
        base.write_bytes(b'opaque public image');base.chmod(0o644)
        self.args.account_only=False

    def apply(self):
        self.args.apply=True;self.args.dry_run=False
        return setup.setup(self.host,self.args)

    def test_default_inspection_and_missing_check_never_mutate(self):
        before=self.snapshot()
        report=setup.setup(self.host,self.args)
        self.assertEqual(report['mode'],'dry-run');self.assertFalse(report['runtime_ready'])
        self.assertEqual(self.snapshot(),before);self.assertEqual(self.host.calls,[])
        self.args.check=True
        with self.assertRaisesRegex(ValueError,'not been set up'):setup.setup(self.host,self.args)
        self.assertEqual(self.snapshot(),before)

    def test_account_only_create_and_rerun_preserve_jobs_without_service(self):
        first=self.apply();self.assertTrue(first['account_configured']);self.assertFalse(first['runtime_ready'])
        state=self.host.path(self.args.state_dir);(state/'retained-job').write_bytes(b'preserve me')
        before=self.snapshot();calls=copy.deepcopy(self.host.calls)
        self.apply()
        self.assertEqual(self.snapshot(),before);self.assertEqual(self.host.calls,calls)
        self.assertEqual(stat.S_IMODE(state.stat().st_mode),0o700)
        self.assertFalse(self.host.path('/etc/systemd/system/eqemu-validator.socket').exists())
        marker=json.loads(self.host.path(setup.CONFIG).read_text())
        self.assertEqual(marker['worker_uid'],self.host.user(self.args.user).pw_uid)
        self.assertEqual(self.host.calls[0][-1],self.args.user)
        self.assertNotIn('sudo',str(self.host.calls));self.assertNotIn('usermod',str(self.host.calls))

    def test_restrictive_root_umask_keeps_config_readable_and_state_private(self):
        previous=os.umask(0o077)
        try:self.apply()
        finally:os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.host.path('/etc/eqemu-validator').stat().st_mode),0o755)
        self.assertEqual(stat.S_IMODE(self.host.path(setup.CONFIG).stat().st_mode),0o644)
        self.assertEqual(stat.S_IMODE(self.host.path(self.args.state_dir).stat().st_mode),0o700)
        before=self.snapshot();self.apply();self.assertEqual(self.snapshot(),before)

    def test_preexisting_account_without_exact_marker_refuses_without_mutation(self):
        self.host.users[self.args.user]=SimpleNamespace(pw_name=self.args.user,pw_uid=os.getuid()+1001,
            pw_gid=4001,pw_dir=self.args.state_dir,pw_shell='/usr/sbin/nologin')
        before=self.snapshot()
        with self.assertRaisesRegex(ValueError,'exact owned setup marker'):self.apply()
        self.assertEqual(self.snapshot(),before);self.assertEqual(self.host.calls,[])

    def test_symlink_conflicts_refuse_before_any_account_command(self):
        for name in (self.args.state_dir,'/etc/eqemu-validator',self.args.code_dir):
            with self.subTest(name=name):
                path=self.host.path(name);path.symlink_to(self.host.path('/absent'))
                before=self.snapshot()
                with self.assertRaises(ValueError):self.apply()
                self.assertEqual(self.snapshot(),before);self.assertEqual(self.host.calls,[])
                path.unlink()

    def test_wrong_owner_or_changed_marker_refuses_and_preserves_data(self):
        self.apply();state=self.host.path(self.args.state_dir);before=self.snapshot()
        self.host.chown(state,self.host.admin_uid,0)
        with self.assertRaisesRegex(ValueError,'ownership'):self.apply()
        self.assertEqual(self.snapshot(),before)
        worker=self.host.user(self.args.user);self.host.chown(state,worker.pw_uid,worker.pw_gid)
        config=self.host.path(setup.CONFIG);data=json.loads(config.read_text());data['worker_uid']+=1
        config.write_text(json.dumps(data));before=self.snapshot()
        with self.assertRaisesRegex(ValueError,'exact owned setup marker'):self.apply()
        self.assertEqual(self.snapshot(),before)

    def test_full_missing_input_refuses_before_account_creation(self):
        self.full_inputs();self.host.path(self.args.base_image).unlink();before=self.snapshot()
        with self.assertRaises(FileNotFoundError):self.apply()
        self.assertEqual(self.snapshot(),before);self.assertEqual(self.host.calls,[])

    def test_full_install_policy_and_plain_code_update_need_no_privileged_rerun(self):
        self.full_inputs();report=self.apply();self.assertFalse(report['runtime_ready'])
        socket=self.host.path('/etc/systemd/system/eqemu-validator.socket').read_text()
        service=self.host.path('/etc/systemd/system/eqemu-validator@.service').read_text()
        profile=self.host.path('/etc/apparmor.d/eqemu-validator').read_text()
        self.assertIn('SocketGroup=submitter',socket);self.assertIn('MaxConnections=1',socket)
        for text in ('User=eqemu-validator','StandardInput=socket','PrivateNetwork=yes',
                     'ProtectHome=yes','MemoryMax=2G','MemorySwapMax=0','KillMode=control-group',
                     'AppArmorProfile=eqemu-validator','ExecStopPost=','DeviceAllow=/dev/kvm rw'):
            self.assertIn(text,service)
        self.assertNotIn('PrivateDevices=yes',service)
        self.assertNotIn(' ux',profile);self.assertIn(self.args.base_image+' r,',profile)
        before=self.snapshot();calls=len(self.host.calls);self.apply()
        self.assertEqual(self.snapshot(),before)
        self.assertEqual(self.host.calls[calls:],[['/usr/bin/systemctl','--version']])
        self.host.path(self.args.code_dir+'/validation/worker/runtime.py').write_text('# reviewed code update\n')
        self.args.apply=False;self.args.check=True
        self.assertEqual(setup.setup(self.host,self.args)['mode'],'check')

    def test_conflicting_policy_and_weaker_confinement_refuse_without_mutation(self):
        self.full_inputs()
        policy=self.host.path('/etc/systemd/system/eqemu-validator@.service');policy.write_text('User=root\n');policy.chmod(0o644)
        before=self.snapshot()
        with self.assertRaisesRegex(ValueError,'Conflicting existing worker policy'):self.apply()
        self.assertEqual(self.snapshot(),before)
        self.assertFalse(any(args[0]=='/usr/sbin/useradd' for args in self.host.calls))
        policy.unlink();self.host.path('/sys/module/apparmor/parameters/enabled').write_text('N\n')
        before=self.snapshot()
        with self.assertRaisesRegex(ValueError,'AppArmor'):self.apply()
        self.assertEqual(self.snapshot(),before)

    def test_unknown_host_or_unsafe_names_and_paths_refuse_before_mutation(self):
        for field,value in (('user','root; command'),('state_dir','/var/lib/../etc'),
                            ('code_dir','/home/submitter/code'),('state_dir','/var/lib/with space')):
            with self.subTest(field=field,value=value):
                args=copy.copy(self.args);setattr(args,field,value);args.apply=True
                before=self.snapshot()
                with self.assertRaises(ValueError):setup.setup(self.host,args)
                self.assertEqual(self.snapshot(),before);self.assertEqual(self.host.calls,[])
        self.host.path('/etc/os-release').write_text('ID=other\nVERSION_ID=26.04\n');before=self.snapshot()
        with self.assertRaisesRegex(ValueError,'Ubuntu'):self.apply()
        self.assertEqual(self.snapshot(),before)

    def test_script_finds_its_assets_outside_checkout_and_help_has_no_side_effects(self):
        result=subprocess.run([sys.executable,'-I',str(ROOT/'scripts/setup-validation-worker'),'--help'],
            cwd='/tmp',capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('--account-only',result.stdout);self.assertIn('--dry-run',result.stdout)


if __name__=='__main__':unittest.main()
