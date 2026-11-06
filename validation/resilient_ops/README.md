# Resilient root operations

This additive source package is **not installed or runtime qualified**. Existing
`validator-maintenance` and its units remain unchanged. The authoritative
adoption plan and worklog are in Operations under `resilient-root-operations`.

Run harmless tests with:

```
python3 -B -m unittest discover -s tests/resilient_ops -v
```

The three methods are `prepare`, `execute`, and `status`. `health` and `diagnose`
are read-only aliases. Each connected Unix socket carries one newline-terminated
JSON object of at most 8 MiB and one response of at most 64 KiB. Linux peer
credentials select the enrolled UID/GID permissions. The new socket name is
`eqemu-resilient-ops.socket`; old protocol names are not replaced.

Prepare accepts an opaque request ID, target ID, exact expected generation and
`publish`, `revert`, or `recover`. Publish artifacts are a mapping of canonical
relative paths to strict base64 regular-file bytes. The exact file set comes
from root enrollment. Directories are implicit, privilege bits and links have
no wire representation. `revert` names a prior same-target publish plan in
`release`. `recover` names a failed or uncertain operation in `recovery_of`.
No uploaded command, script hook, environment or unit name is accepted.

Execute binds an explicit operation ID to a sealed plan ID. Identical completed
retries return the stored result. A simultaneous retry returns busy; query
status or retry the same IDs. Interrupted acceptance or an incomplete terminal
receipt returns uncertainty, never automatic execution. Recovery is explicit
and linked. Failed original records remain unchanged after successful recovery.
Fixture recovery leaves owned services stopped and allocates a fresh workspace.
Host workspace recovery seals evidence, quarantines the failed generation and
allocates a fresh empty workspace for subsequent separately authorized work.
Host code recovery restores the established prior sealed binding and does not
allocate a workspace. Host recovery durably carries the original ingress state
through linked interruptions and restores previously active diagnostic, profiling
and maintenance sockets after safe recovery. It never restarts accepted service
instances. The ordinary socket remains inactive under the maintenance HOLD.
Host deployment preserves other socket activation state with the same HOLD
exception; fixture deployment preserves unit activation state. Failed health compensation remains a failed deployment.

The fixture publication interface is atomic `current.json` under a dedicated
enrolled root. The fixed host adapter additionally replaces the adopted
`/srv/eqemu-validator-code` symlink with a sealed release. The supplied
`enrollment-contract.json` binds the exact 19 paths, UID/GID 995:980, units,
shared lock and legacy three-file workspace facts. `adopt.py` is a separate
reviewed root operator, never a protocol action. It revalidates current bytes,
retains the original code tree, seals legacy evidence, and establishes the
launcher link and initial failed history without starting anything. Existing
workspace bytes remain untouched until a subsequent explicit recovery. The
legacy failed record retains the ingress observation from before adoption
fencing, so that recovery can restore unrelated sockets while retaining the
ordinary HOLD. Lock
ancestor protection and AppArmor/launcher compatibility need root adoption
review. Ordinary package installation performs none of this migration.

Resource ownership is administrative policy: every relevant writer must be
confined to the listed owned unit cgroups, with no other writer to a managed
generation or binding. Same-UID callers cooperate. Root administrators, kernel,
and systemd are trusted. Unknown identity or populated stopped cgroups block
conflicting work. The module never scans or kills host processes by PID, name
or UID. Kernel-stuck work remains fenced.

The store admits at most 900 normal operations/preparations and reserves 100
slots for explicit recovery. Reading status is separate from admission. Private
failed evidence stages remain retained; partial evidence or exhausted recovery
capacity requires administrative preservation/expansion. There is no automatic
retention deletion. Each operation preallocates a 64 KiB receipt reserve; each
artifact/evidence tree has enrolled byte and entry limits. Raw application or
systemctl output never enters receipts.

Package preparation prints hashes and finite root operator argv. Installation,
upgrade, rollback and uninstall preserve state/releases and do not reload,
enable or start units. Enrollment is a separate hash-pinned root action for
fresh dedicated roots. Policy expansion and executor upgrades cannot be
requested through the automation protocol. No root action is authorized merely
by preparing the package.
