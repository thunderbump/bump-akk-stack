# central-ng41 fixed maintenance broker

This directory contains the service source and package preparation tools. Brian
installed the reviewed `f62ce81` package on his validator host. Its authenticated
root-service health, status, and same-mount diagnostics passed installed read-only
qualification. Privileged source-binding publication and rollback remain unrun,
and installation does not qualify candidate workloads. Other hosts still require
their own installation and qualification.

The [authoritative Operations walkthrough on the LAN](http://192.168.1.230:8081/projects/bump-akk-stack/documentation/central-ng41-validator-maintenance.html)
records the installation evidence, commands, and remaining qualification limits.

`maintenance.py` contains the fixed protocol, source-object verifier and two-file
transaction. `service.py` is the systemd connected-socket entry point. It imports
only protected broker code and stdlib, never installed worker or candidate code.
`client.py` is unprivileged. `install.py` runs only once from a separately reviewed
normal root terminal, after the package/installer hashes have been checked.

Capabilities: health, status, diagnose, fixture-data read, source-binding publish,
and explicit bounded binding rollback. The proposed MVP additions below are
source only; the installed broker still has no retirement capability. No arbitrary
program, file path or Python capability exists. Existing HOLDs remain in place.

Prepare from clean committed source:

```
scripts/prepare-validator-maintenance --output /absolute/fresh-package --submitter bump
```

This prints the complete root install/uninstall argv and SHA256s as data. It does
not call systemd or run an installer. Installation enables only the new broker
socket. Source publication preserves the ordinary socket's observed state, so it
does not activate the held inactive worker socket. It never launches a workload.

Run harmless source tests:

```
python3 -B -m unittest discover -s tests/worker -p test_maintenance.py -v
```

One test uses a real Unix socket and a NoNewPrivs=1 child under the current UID.
Temporary transaction tests simulate privileged metadata. These host tests alone
do not qualify actual root/systemd, mount namespaces, privileged transactions,
worker execution, or candidate results. The installed read-only checks above are
separate evidence.

## Fixed unattended MVP, central-016p

The proposed source adds `socket-start` and `socket-stop`, accepting no unit or
options. They call only `/usr/bin/systemctl start|stop eqemu-validator.socket`
with a 15-second deadline and discarded command output, then confirm its state.
They never start accepted worker service instances. Status includes
`ordinary_socket_active`. An explicit start authorizes ingress; a later client
connection can then activate a worker. Keep the existing HOLD until separately
authorized.

`retire-failed-integration --expected-run HEX32` validates the fixed ordinary
`/var/lib/eqemu-validator/last-integration` receipt and moves the whole directory
to `.maintenance-v1/retired-integrations/HEX32`. VM cleanup must be exactly true.
Native and database cleanup retain their separate original values, including
`not-run` and `unknown`. A failed execution or an explicitly incomplete failed
transfer is required. The operation uses the common worker lock, refuses active
owned work, stops ordinary ingress, and leaves it stopped. It preserves all
artifact/pending/receipt bytes, writes no ACK, and creates no replacement slot.
Only a separately requested integration job creates the next slot. Root and file
symlinks, malformed metadata, wrong run, existing archive, and cross-filesystem
moves refuse. No diagnostic sockets or worker code change.

Both operations share the existing lock with publication. Requests have no
automatic retry or rollback. A command failure or timeout returns
`command-failed-or-uncertain`; disconnects and I/O failures can leave effects
uncertain. Consult status, which reports actual socket state, slot presence and
up to 16 archived run names with a truncation flag. Explicit repeated retirement
refuses without another move or overwriting an archive. This is ordinary rename
and directory synchronization, not power-loss recovery or exactly-once delivery.

Prepare an update for an EXISTING installation from clean committed source:

```
python3 -I -B validation/maintenance/prepare_mvp_update.py --output /absolute/fresh-update
```

Preparation reads only the public installed baseline, broker source and template.
It writes `manifest.json` with exact before/after SHA256 values, the three fixed
replacement files, an unprivileged client copy, and `UPDATE-REVIEW-ONLY.sh` /
`RESTORE-REVIEW-ONLY.sh`. Review those exact human root commands. Do not execute
preparation or package Python as root. The recipe stages checked bytes under a
fresh protected `/root/eqemu-maintenance-mvp-update`, stops only the maintenance
socket, refuses active maintenance requests, backs up the three files under a
fresh `/root/eqemu-maintenance-mvp-backup`, installs checked files, reloads systemd,
and starts only the maintenance socket. It never starts ordinary ingress.
Do not run it automatically; a partial update requires human inspection and the
explicit restore recipe. Existing backup/staging directories intentionally refuse
reuse. The original install manifest remains historical; use the backup recipe
for this update, not the original install/resume/uninstall commands.

The only service-policy change adds `/var/lib/eqemu-validator` to the existing
`ReadWritePaths`, required for the fixed rename. Existing identities, resource
limits, worker policy, profiles, code/input selection, and private state layout
remain intact. Normal broker API requests cannot change broker code or policy.
The newly prepared source is uninstalled and unqualified on the real host.
Source-only authorization excludes root commands, Docker redeployment, worker
runs, and probes of protected runtime state.
