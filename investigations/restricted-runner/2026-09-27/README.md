# Restricted validation runner preparation

This package is the first installation candidate for the restricted-runner plan.
It is **not installed or VM-proven** by the local tests. The central task is
**Prepare and prove the restricted validation runner installation**.

The authoritative design and operator worklog are in operations-webui. This file
explains the package and its local checks.

## What changes

- Root-owned versioned Python and templates under `/usr/local/lib/eqemu-test`.
- One fixed helper `/usr/local/sbin/eqemu-test-request`, invoked with no arguments.
- Normal-user client `/usr/local/bin/eqemu-test`.
- One `eqemu-test` group, with Brian and a locked `eqemu-test-proof` account.
- Root-owned inputs, run state and reports under `/var/lib/eqemu-test`.
- One sudoers fragment. It grants only this helper, no Python, shell, systemctl or
  libvirt command. Caller identity comes from sudo; the request has no UID field.

The exact proposed grant is:

```sudoers
%eqemu-test ALL=(root) NOPASSWD: NOSETENV: /usr/local/sbin/eqemu-test-request ""
```

The administrator installer validates the package manifest, checks pre-existing
paths, copies four fixed inputs with hashes, runs installed static preflight,
validates sudoers, then exercises authorization as the submit-only proof account.
It starts **no VM**. If a post-grant check fails, the grant is removed. Partial
installation data is retained for exact recovery. No package installation or
production/NAS access is part of this installer.

The initial input copy is about 1.18 GiB. The existing retained 4 GiB build is read
in place with its original qualification and expiry checks. No new compilation,
artifact promotion or expiry extension occurs. Copies and run state remain subject
to the existing worker admission and limits. Eight retained runs are the initial
cap; exceeding it refuses admission pending an exact retention review.

## Local checks

```sh
python3 -m unittest discover -s investigations/restricted-runner/2026-09-27 -p 'test_*.py' -v
python3 investigations/restricted-runner/2026-09-27/prepare.py
```

`prepare.py` seals only the explicit source file list. It does not regenerate old
experiments. `worker.py.in` and `suite.py.in` freeze the exercised runtime-reuse-06
controllers, with installed input paths, fresh host-generated run identity and
private evidence. `provenance.json` records their original hashes. The original
scenario seed is copied as identified opaque media during installation. Its
scenario and protocol have not been loosened.

The CLI takes `run startup-diagnostic`, `status RUN_ID`, or `cancel RUN_ID`.
`run` waits and returns nonzero because the profile remains diagnostic-only.
`run --detach` returns submission success only, never validation success.
The client prints the run ID immediately, then publishes bounded reports during
status checks. A killed client cannot remove the systemd lifetime limits.
The worker still cleans itself without a live client; a later `status` publishes
its retained receipts. Report JSON and bounded logs are readable to the report
group, not writable by it.

Normal requests accept one small JSON object on stdin, at most 4096 bytes within
two seconds. There are no caller-selected host paths, commands, policy overrides,
XML, source uploads or arbitrary unit names. Cancellation is limited to the
requesting UID. Root remains the administrator. The proof account gets only the
submit group and a nologin shell; Brian's existing broader privileges are not
changed by this package.

## Installation and reversal

The operator handoff must identify the reviewed package revision before invoking
`sudo python3 -I .../install.py`. Do not grant sudo to the checkout or run the client
as root. The source installer is the one-time reviewed administrative action;
subsequent requests use only installed code. A new login may be needed for Brian's
new group membership. The locked proof account can exercise requests via an
administrator's `runuser` without a login shell.

The installer prints its exact installed version and rollback command. The
installed `remove.py` disables the grant, refuses to remove active-run entry points,
and supports `--cancel-owned` to stop only recorded runs. It verifies cleanup
before removing the exact matching client/helper and Brian's added membership.
It retains versioned code, input copies, the locked proof identity, report group
and evidence for inspection. This is a privilege rollback, not broad disk pruning.
A separate exact audit may remove those retained files later. Shared libvirt,
backups and historical attempts are never deleted.

First-install only: an existing install is refused. There is no in-place upgrade
or automatic version switch. That avoids changing active cleanup code and keeps
upgrade handling out of this first proof.

## Remaining real proof

After the administrator installation and its no-VM authorization checks, run a
normal diagnostic and a cancellation as the submit-only identity. Verify terminal
results, unchanged artifacts, actual resource absence, readable reports and
rejection of another caller's run ID. Keep the task open until those real checks
are recorded. Whole-AFK tool isolation, candidate payload ingestion, independent
assertions and durable AFK publication remain separate work.
