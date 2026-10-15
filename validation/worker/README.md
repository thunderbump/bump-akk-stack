# Unprivileged validation worker POC

The first deliverable provisions the dedicated account. Full worker policy and
tiny-VM execution are separate qualification steps. This POC does not change
the installed EQEmu validator or AFK configuration.

Inspect the account setup without changing the host:

```sh
./scripts/setup-validation-worker --submitter bump --account-only --dry-run
```

Create the account with an explicit administrator invocation:

```sh
sudo ./scripts/setup-validation-worker --submitter bump --account-only --apply
```

The defaults create `eqemu-validator`, a private group, the non-login shell
`/usr/sbin/nologin`, private state at `/var/lib/eqemu-validator`, and an owned
configuration marker at `/etc/eqemu-validator/config.json`. Change `--submitter`
to the existing local user on another host. `--user` and `--state-dir` are also
configurable. The initial supported host is Ubuntu 26.04.

Account-only setup installs no worker service or AppArmor policy and starts no
VM. Its output deliberately reports `runtime_ready: false`. Repeating the same
command preserves the UID, configuration and existing state. Unowned accounts,
conflicting files, symlinks and changed ownership refuse rather than being reset.

Verify that account setup later with the same arguments and `--check` instead
of `--apply`. Keep the selected code/image paths consistent when progressing to
full setup; they are recorded in the marker. The current full-setup interface
expects reviewed submitter-owned code outside home directories and a separately
staged root-owned public base image. Those prerequisites are not provisioned by
the account-only command.

When full setup has been qualified, `scripts/check-validation-worker` inspects
worker readiness through the ordinary local socket. Its explicit `--smoke`
option requests a tiny disposable VM; a plain check starts no VM. A readiness
report is not a server build, actor test, or confinement qualification.

Run source regressions without sudo:

```sh
python3 -B -m unittest discover -s tests/worker -v
```
