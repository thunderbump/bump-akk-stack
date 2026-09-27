# Appended to the fixed suite. Only attempt 01's orphan slice file is eligible.
PREVIOUS_HASHES = {}  # @PREVIOUS_HASHES@
PREVIOUS_CTL_SHA = '@PREVIOUS_CTL_SHA@'


def reconcile_previous(apply=False):
    prior = BASE / 'artifact-handoff-01'
    m = module('producer', local=True)
    m.safe_dir(BASE)
    m.safe_dir(prior)
    for name, expected in PREVIOUS_HASHES.items():
        path = prior / name
        read(path)
        if digest(path) != expected:
            raise RuntimeError('Prior evidence changed: ' + name)
    if not quiescent(properties('eqemu-vm-handoff-01-suite.service')):
        raise RuntimeError('Prior suite is active')
    if read(prior / 'leases.json')['active']:
        raise RuntimeError('Prior reservations remain')
    if (prior / 'retained').exists() or (prior / 'retained').is_symlink():
        raise RuntimeError('Prior artifact remains')
    for case, short in [('producer', 'prod'), ('consumer', 'cons')]:
        s = read(prior / case / 'state.json')
        if not quiescent(properties('eqemu-vm-handoff-'+short+'01-worker.service')):
            raise RuntimeError('Prior controller active')
        if s['uuid'] in m.virsh('list','--all','--uuid').stdout.split() or m.owned_pids(s):
            raise RuntimeError('Prior VM remains')
        if s['profile'] in P('/sys/kernel/security/apparmor/profiles').read_text():
            raise RuntimeError('Prior profile remains')
        for path in [prior/case/'data', P('/run/systemd/system/eqemuvmhandoff'+short+'01worker.slice'),
                     P('/sys/fs/cgroup/eqemuvmhandoff'+short+'01worker.slice')]:
            if path.exists() or path.is_symlink(): raise RuntimeError('Prior resource remains')
    previous_ctl = P('/run/systemd/system/eqemuvmhandoff01ctl.slice')
    if P('/sys/fs/cgroup/eqemuvmhandoff01ctl.slice').exists():
        raise RuntimeError('Prior controller cgroup remains')
    props = properties('eqemuvmhandoff01ctl.slice')
    if props.get('ActiveState') != 'inactive' or props.get('DropInPaths'):
        raise RuntimeError('Prior controller slice is active or modified')
    if previous_ctl.exists() or previous_ctl.is_symlink():
        info = previous_ctl.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 4096 or digest(previous_ctl) != PREVIOUS_CTL_SHA:
            raise RuntimeError('Prior controller slice identity changed')
        if apply:
            previous_ctl.unlink()
    if apply:
        run(['systemctl', 'daemon-reload'])
        write(prior/'reconciliation-02.json', {'complete': True, 'slice_file_absent': not previous_ctl.exists(),
              'original_suite_passed': False, 'prior_evidence': PREVIOUS_HASHES, 'at': time.time()})
