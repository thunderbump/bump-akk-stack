# AFK fixture command

Use `scripts/validate-worker-candidate` from a reviewed, fixed frontend copy as
AFK's foreground fixture command. It defaults to the current working directory
and `HEAD`; AFK supplies its clean fixture checkout. Pass `--websocketpp` pointing
to the initialized trusted dependency object store. The source packager verifies
the pinned dependency commit and native input hashes before sending opaque data
to the worker. Candidate Rust/native commands execute only inside the VM.

Configure the same command with `--identity` as `identity_command`, keeping
`timeout_seconds = 20400`, `termination_grace_seconds = 780` and
`repairable_exit_codes = [1]`. The identity invocation prints only
`{"schema_version":1,"identity":"eqemu-worker-v1:<sha256>"}` on success. It
hashes the frontend, installed worker implementation, root configuration,
systemd units, AppArmor policy, base image and offline input bytes. It neither
contacts the worker nor reads/executes candidate source. Missing/unreadable inputs
return infrastructure exit 2 without a usable identity. Normal validation keeps
its existing JSON report and exit 0/pass, 1/candidate failure, 2/infrastructure.
AFK retains stdout/stderr and publishes its normal checks and feedback.

The frontend needs these eight files in their original relative locations:
`scripts/validate-worker-candidate`, `validation/worker/identity.py`,
`validation/worker/prepare.py`, `validation/worker/client.py`,
`validation/inputs.py`, `validation/profile.json`, `validation/runtime-fixture.json`
and `validation/worker/normal_world.py`. Copy them to a fresh,
commit-named directory owned by the submitter; keep that directory fixed while
any AFK job is running. Source/client changes require a fresh copy and an AFK
configuration update while jobs are quiescent. Root account/service/policy/base
changes still use the existing reviewed setup script. Frontend/configuration
selection needs no sudo. Identity probes before/after execution detect observed
changes; they do not replace keeping trusted implementation fixed during a run.

This path uses one disposable VM for Rust checks, native compilation, final zone
symbol inspection, native utility tests and the
[normal disposable DB/world/zone baseline](NORMAL-WORLD.md). The pinned public
runtime ISO is now required by ordinary validation and identity probes. The worker owns scratch and VM
cleanup; do not attach the old validator's Docker/lease cleanup adapter. It does
not run a separate fresh consumer or claim actor gameplay qualification.


The cloud-init shell remains the parent of the guest Python command and owns
poweroff. If Python exits abruptly before normal completion, the shell emits an
infrastructure result with its exit status and requests shutdown. The host also
refuses immediately on cloud-init's user-script failure diagnostic, preserving
the console tail and cleaning its owned VM instead of waiting for the build
budget to expire. A failure result does not establish completed checks.

The disposable build guest masks/stops `serial-getty@ttyS0.service` before
opening its validation console. That login service resets/hangs up the same
terminal and can invalidate existing writers with EIO during boot. Failure to
stop it refuses guest launch; it changes no host service or root policy.

After a normal-world run, the frontend writes `normal-world-success.json` or
`normal-world-failure.json` into
AFK's supplied `VALIDATION_AFK_EVIDENCE_DIR`. The private artifact contains the
exact candidate SHA, worker run ID, structured observer result including source-owned bounded test diagnostics,
and separate VM cleanup outcome. Successful measurements use the existing suite
report; no new guest protocol or scenario knowledge is added to the validator. `diagnostic-files.json` admits that relative file through AFK's
existing exact-head responder contract. The manifest includes a SHA-256 digest
for consistency checking; this does not authenticate an advisory artifact or
replace AFK's authoritative execution evidence. `public-summary.json` contains bounded
identifiers only, so the PR receives a concise outcome summary instead of raw
native log tails. These files are advisory and cannot turn a failed run into a
pass. Responses receive manifested success measurements only for unchanged,
sealed exact-head validation; raw wrapper logs remain failure-only. A failed artifact export is infrastructure exit 2.

Outside AFK, the same private artifact is retained under
`~/.local/state/eqemu-rust-validator/runs/<worker-run-id>/`. Files are created
once with mode 0600. Existing files, symlink targets and directories writable by
other users are refused. The artifact is at most 16 KiB including JSON escaping
and its final newline; shortened console excerpts carry explicit truncation
flags. The guest completion frame is bounded at 32 KiB and the worker socket
report at 64 KiB. The read-only last-result command uses that same 64 KiB bound.

Deploy a fresh reviewed frontend before qualifying success handoff against a
real VM. This export change reuses the existing worker report and needs no
worker, guest observation, completion limit or privilege changes. Earlier failure
observation support still requires the corresponding reviewed worker baseline. No new host privileges,
artifact service or raw guest disk export are needed.

The source-port allocation repair in `normal_world.py` separately requires that
reviewed helper in both the fixed frontend and installed worker closure before a
new VM run. The existing worker copies it into the disposable guest. Its changed
bytes change validator identity, preventing reuse of an older fixture result.
No new host privilege, policy, input image or execution permission is required.
