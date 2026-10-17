# Disposable normal world/zone slice

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
actual package solver plan against the pinned closure minus identical installed
packages. It uses isolated APT state with the verified runtime metadata and live
guest dpkg status, not the native bundle's indices or a retained simulation status.
Version changes to existing pins, removals and unpinned additions refuse. It installs with
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
bots, state saving and external logging sinks. Before native boot it sets
`zone.idle_when_empty=0` on the exact default PoK row (`zoneidnumber=202`,
`version=0`, `short_name='poknowledge'`) and reads back that row's identity and
value, refusing missing, duplicate or mismatched results. Native zone construction
loads `idle_when_empty` and `seconds_before_idle` from the zone table; with idling
disabled, the idle delay is irrelevant and is left unchanged. An arbitrary
`Zone:IdleWhenEmpty` rule row is not a native activity control or proof.
No player/login records are added. Normal native
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
does not label CPU ticks as gameplay ticks. The independent baseline remains
mandatory alongside the source-owned in-server suite below.

## EQEmu-owned in-server suite

The upgraded fixture requires the candidate's built-in `zone` test runner. There
is no historical-candidate bypass. Compile the runner through `EQEMU_BUILD_TESTS`.
Ordinary server starts do not enable it. The observer gives only its unprivileged
zone child `EQEMU_INSERVER_TEST_RUN`, a fresh 32-character lowercase hex run ID,
and `EQEMU_INSERVER_TEST_RESULT`, a fresh absolute guest-local file path. It
clears inherited `EQEMU_INSERVER_TEST_*` variables for both native children.
There is no network control endpoint or candidate command on the host.

EQEmu owns suite registration, scenario setup, native observations and assertions.
Its runner waits for the loaded zone and world connection, advances through the
normal server loop, and stays alive after reporting. Stack does not enumerate
cases or implement actor semantics. A new scenario using the existing environment
requires an EQEmu change only. New environment/package requirements still belong
in Stack.

The runner publishes one fresh regular JSON file atomically, without overwriting
an existing file. The version 1 report is at most 4096 bytes:

```json
{"version":1,"run_id":"0123456789abcdef0123456789abcdef","suite":"zone","selected":1,"started":1,"completed":1,"failed":0,"finalized":true,"passed":true,"tests":[{"name":"source-owned-case","passed":true,"diagnostic":""}]}
```

All keys shown are required and other keys are rejected. The fixture requires
`selected = started = completed = len(tests)`, between 1 and 32 tests, unique
nonempty names of at most 64 characters, Boolean per-case outcomes, and diagnostic
strings of at most 256 characters. `failed` must equal the number of failed tests;
`passed` must agree with that count. Counts are integers, never Booleans. The run
ID must match the observer's fresh invocation. Duplicate JSON keys, nonregular
files, symlinks, oversized files, zero tests and incomplete reports refuse. The
fixture rechecks the same result bytes and file identity after owned teardown;
a replacement or disappearing report cannot pass.

The existing independent readiness and five-second activity baseline must still
complete. The observer then waits for the report within the same 120-second
budget. A complete failed suite is candidate exit 1. Missing/malformed reports,
a native crash after readiness or missing completion at the deadline are also
candidate exit 1. Preparation/startup prerequisites, explicit cancellation and
incomplete cleanup remain infrastructure exit 2. Success includes the checked
per-test report in `normal_world.inserver_tests`, and the same gate is checked by
the host worker and frontend. Log markers and responsiveness alone cannot pass.

## Non-pass controls, diagnostics and teardown

The same command accepts fixed `--world-control startup`, `assertion` or `cancel`
controls. Each builds the selected candidate and creates a fresh fixture:

* `startup`: world starts in `server/missing-config/world`, with both its
  working directory and immediate parent empty. Native config discovery searches
  both locations; a direct child of `server` would rediscover the positive
  fixture's config. The positive config and zone working directory stay unchanged.
  Missing-config startup exit is infrastructure non-pass 2, with console tails,
  before readiness or baseline measurement. A deadline or the generic
  control-unexpectedly-completed guard is non-pass, but is not proof that the
  intended startup fault occurred.
* `assertion`: the observer passes `EQEMU_INSERVER_TEST_CONTROL=assertion` to
  the zone runner at launch and retains the independent readiness/baseline gate. The source
  must complete its real native scenario and report a deliberate failed assertion.
  Complete cleanup yields candidate exit 1. A passing suite is rejected as an
  ineffective qualification control, not accepted as evidence of the intended fault.
* `cancel`: after real readiness, the observer continues bounded responsiveness
  checks instead of passing. Wait for the `normal-world-ready` stage in the
  ordinary stderr (`EQEMU_STAGE normal-world-ready`), then interrupt/disconnect
  the foreground client. The worker sends at most one fixed, bounded progress
  frame; it never forwards raw guest output. This is an advisory synchronization
  notification, not a pass: the final identity/assertion/cleanup gates still apply. The existing
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
zone-row activity configuration/readback refusal before native launch (including
missing/schema-mismatched rows and failed writes), missing/wrong challenge replies,
exact-PID connection ownership, strict in-server report schema/identity/file
bounds, duplicate keys/names, incomplete/missing/malformed/replaced/disappearing
reports, source assertion outcomes, post-readiness crashes, positive and
assertion/startup/interruption paths (including current/parent config discovery
with a real positive config retained and startup refusal before readiness/baseline),
descendant cleanup, seed/staging closure
and old-worker rejection. Socket/process tests cover a split readiness frame,
foreground interruption upon its receipt, non-pass persistence and owned VM/scratch
cleanup. Shared installer tests in `tests/validation/test_runtime_packages.py`
cover runtime metadata selection, live installed pins, plan refusal and failure
restoration without executing apt. These source tests establish helper behavior,
not real native startup, package compatibility, gameplay ticks or GitHub delivery.
Actual installed/runtime acceptance is tracked separately in the authoritative
[Operations qualification worklog](http://localhost:8081/projects/bump-akk-stack/worklog/2026-10-16-normal-world-qualification.html).
Before acceptance, a deployment must collect current positive, intended
startup-failure, assertion-failure and readiness-cancellation evidence on the
current worker after reviewed asset activation. Operational run identities and
results belong in that worklog, not in this source document.
