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
sockets after safe recovery. The old maintenance publisher stays retired. It never restarts accepted service
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

## Host compatibility successor

R3 accepted only commit 24a0fd6 and source-v4. This successor requires fresh
review. It packages the exact 19-file installed baseline and an explicit
ordinary-runtime.patch, rather than promoting the combined repository worker.
Only runtime.py and its integration-release.json data binding change.
The latter records root-owned mode0644 sealed files and the changed runtime
hash. Existing recipes/implementation identities do not match this release.

ordinary-config.json selects private UID995:GID980/mode0700
/var/lib/eqemu-validator/ordinary and the explicit existing common
/var/lib/eqemu-validator/worker.lock. The parent becomes root-owned0711 only
inside the fenced finite adoption transition; the leaf remains995:980/0600.
ASan and profiling roots/code/config/caps/profiles are unchanged. Ordinary
serve and ExecStopPost retain the existing launcher. The proposed ordinary
worker accepts only that root-owned symlink into a protected hash-named managed
release matching current.json and its own resolved entry point.

ordinary-unit changes only working directory and writable paths.
ordinary-apparmor grants read access to the physical managed code/current
binding and limits ordinary writes to its state child and common lock.
No unconfined execution or additional worker resource authority is introduced.
The exact profile still requires separate root loading and effective admission;
an acknowledgment flag is not proof of loaded confinement.

Adoption now requires a separately reviewed private selection JSON and its
SHA256. Its exact shape is {"version":1,"entries":[...],"records":{...}}.
Entries must enumerate the current parent exactly, at most16 names, restricted
to worker.lock, last-integration, three ASan children, last-result.json and
last-serial.log. Each present last-result/serial requires exact bytes and SHA256
in records, at most1MiB each, owned995:980/mode0600. Active markers, job
directories, unknown entries, existing ordinary child or changed protected
facts refuse and retain adoption intent. Current private data is not invented.

The transition archives selected bytes and original ordinary unit/config/profile
and publisher units in protected custody; copies only selected records and the
three verified legacy evidence files into the new state; leaves old data
in place; and converts only the parent directory custody. It masks the old
publisher socket AND service template after fencing and retains their bytes.
Subsequent operations never restore publisher ingress. No automatic rollback
reinstalls publisher authority into the adopted namespace.

Recovery seals old history and allocates a root-authored .rootops-fresh.json
marker. The actual proposed worker intake consumes only a valid otherwise-empty
marked slot. Unmarked empty, malformed, dirty or uncertain retained collections
refuse. No ACK or successful historical result is fabricated.

Preparation prints a bounded bootstrap recipe: a normal authorized root terminal
stages the hash-named bootstrap with /usr/bin/install, externally compares its
sha256sum, runs it to stage only manifest-pinned package.py, and externally
verifies that operator. NoNewPrivs callers use the installed protocol; they do
not execute this root bootstrap. Exact selected-package install/verify argv and
adoption executable/hash are printed. The private state-selection hash is an
external fact still required, never a guessed selected-package token.

Rollback/uninstall of executor packaging does not undo host custody/adoption.
Original assets are preserved evidence, not an authorized automatic rollback.
Effective systemd/cgroup ownership, loaded AppArmor and private selection remain
separate bounded root prerequisites. No installation, profile loading, service
activation or workload has been performed by source/package preparation.

Recovery validates the workspace ROOT with lstat before traversal or retirement,
even when sealed evidence already exists. It must be a directory owned by the
trusted root or enrolled service UID; links, dangling links, files and unknown
owners refuse. A missing root is reconcilable only through an explicitly linked
retirement record with established owned quarantine and sealed evidence.
Absence alone does not prove successful retirement or permit a fresh slot.
Adoption synchronizes both target roots, their common parent and that parent's
entry before publishing the external launcher binding, policy or success.
These are source-level durability requirements, not power-loss qualification.
