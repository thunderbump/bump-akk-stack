# Disposable normal world/zone slice (not yet VM-qualified)

The ordinary `scripts/validate-worker-candidate` command now selects a clean
committed candidate, performs the existing Rust/native build, bridge-symbol and
utility checks, and then starts a normal world and one `poknowledge` zone in the
same offline VM. It never calls the old `tests:actor-lifecycle` CLI. There is no
loginserver, client, GM/account handoff, artifact platform or production database.
The build's exact world, zone and shared_memory SHA-256 values accompany the
normal-world result. Source/dependency contract checks remain mandatory.

## Inputs and activation prerequisites

Use the ordinary command, optionally specifying `--runtime-input <public-ISO>`.
By default the input is the path declared in `validation/runtime-fixture.json`
under `--input-store`. This is the retained public runtime/debugger bundle from
the prior server preparation, not an off-repository recipe. Its exact size and
SHA-256 are checked before packaging. The guest independently checks the bundle
manifest and every member before installing packages or importing SQL. Existing
native and Rust input hashes remain unchanged. Identity includes the runtime
media, fixture declaration and complete installed guest-helper closure.

The runtime manifest identifies the five PEQ SQL members/import order, quests,
maps, opcodes, offline package proof and public provenance. The helper checks the
actual package solver plan against the pinned closure, installs with
`--no-download --no-remove`, audits installed versions and probes Perl/debugger
tools in this current guest. It does not assume a previous guest's installed
packages still exist. Missing media, unavailable versions, solver changes,
missing `setpriv`, schema/content differences or missing required maps are
concrete infrastructure prerequisites, not candidate failures. No download,
host package installation, new sudo permission or root-policy change is made.

**Activation is separate:** review/select the changed trusted frontend and worker
assets using the existing deployment procedure while jobs are quiescent. This
source change neither installs nor selects them. An old build-only worker cannot
satisfy the new frontend's success gate. Available runtime media, compatibility
with the current worker base/packages, payload headroom and native invocation /
wire compatibility still require actual worker qualification. The existing
1 GiB payload, disk, service and supervisor limits are unchanged; an oversized
combined payload refuses rather than expanding host policy automatically.

## Fixture and independent readiness

Root performs only guest-local preparation: pinned package installation, a fresh
owned MariaDB datadir/database, verified public imports and derived fixture
configuration. It removes ambient PoK spawn2 entries, disables zone controller,
bots, state saving and external logging sinks, and explicitly sets and reads
back `Zone:IdleWhenEmpty=false`. No player/login records are added. Normal native
executables and the source-owned observer run as `nobody`, with empty supplementary
groups, no-new-privileges, no cores and bounded output files. Login attempts are
restricted to loopback; the VM still has no network interface.

The observer starts `world` and `zone poknowledge 7000`. It requires both ends of
an established loopback world connection to belong to those exact native PIDs,
**and** an EQ stream SessionResponse echoing a fresh random challenge from the
zone. Merely listening, sleeping for a fixed period, or printing a startup marker
cannot pass. The fixed legacy EQ stream handshake and native command arguments
must be confirmed against the selected native revision in VM qualification;
incompatible behavior refuses instead of falling back to startup log strings.

After readiness the observer repeatedly checks the connection and application
response for at least five seconds, retaining readiness latency, successful
samples, elapsed baseline time and world/zone CPU scheduler tick deltas plus
`SC_CLK_TCK`. Zone CPU ticks must advance. These are **scheduler/activity and
readiness measurements, not a count of native gameplay loop ticks**, NPC activity
or actor acceptance. If later tests require actual gameplay-loop tick counts,
that needs an independently reviewed native observation contract; this wrapper
does not invent a native completion marker or label CPU ticks as gameplay ticks.

## Non-pass controls, diagnostics and teardown

The same command accepts fixed `--world-control startup`, `assertion` or `cancel`
controls. Each builds the selected candidate and creates a fresh fixture:

* `startup`: world starts in an owned empty directory without configuration;
  unexpected exit/deadline is infrastructure non-pass 2, with console tails.
* `assertion`: after real readiness and baseline measurement, the observer
  deliberately fails its assertion. Complete cleanup yields candidate exit 1.
* `cancel`: after real readiness, the observer continues bounded responsiveness
  checks instead of passing. Wait for the `normal-world-ready` stage in the
  ordinary output, then interrupt/disconnect the foreground client. The existing
  worker cancellation path destroys its exact VM/scratch and returns non-pass.
  An un-interrupted cancel control also reaches a non-pass deadline, never pass.

The full runtime reserves 1800 seconds within the existing 17400-second guest
work budget; missing reserve refuses before fixture launch. Native readiness /
observation has a 120-second deadline plus bounded teardown. Native consoles
have 1 MiB file limits and bounded diagnostic tails. The root adapter scrubs
guest credentials (including split reads) before persistence/export. Failures
keep useful context in the ordinary guest diagnostic/final report; no raw DB,
config, quest state or credentials are exported.

The unprivileged observer and native children share one exact owned session, so
the root adapter also kills their group if the observer dies or is interrupted.
Orderly teardown observes descendant absence, including after leader exit;
forced rescue cannot establish success. The database has its own owned group
and is stopped on every adapter exit. The worker then terminates its owned VM
and removes the disposable overlay/input/seed scratch on success, failure and
client death. Whole-VM destruction also removes guest database and runtime state
on abrupt guest/controller failure. Existing cgroup recovery remains authoritative
for controller death. No unrelated VM, PID, socket or filesystem tree is pruned.

## Qualification limits

Trusted Python/fake controls in `tests/worker/test_normal_world.py` cover gates,
missing/wrong challenge replies, exact-PID connection ownership, positive and
assertion/startup/interruption paths, descendant cleanup, seed/staging closure
and old-worker rejection. They do not establish a real native startup, package
compatibility, gameplay ticks or GitHub delivery. Actual positive, startup,
assertion and foreground-cancellation evidence must be collected separately in
the current worker after reviewed asset activation. No such acceptance run was
performed as part of this source implementation.
