# Headless Qeynos2 journey

`scripts/qeynos2-journey` runs the Rust server's Qeynos2 journey with the
headless EQOxide client in a disposable rootless container. The journey is
login, zone entry, move, stop, target, one hit, camp, server restart, and relog
at the saved position. It replaces the hand-copied `worker.py` and `capture.py`
directories under `~/.local/state/eqemu-rust-*`. Those directories remain
historical evidence.

Routine runs do not seal artifacts and do not run the native C++ comparison.
Those remain separate, explicit steps.

## Run

```sh
scripts/qeynos2-journey run \
  --server /abs/bump-eqemu-rust --server-revision FULL_SERVER_SHA \
  --client /abs/eqoxide-headless --client-revision FULL_CLIENT_SHA \
  --maps /abs/dir-with-qeynos2.map-and-qeynos2.wtr
```

The script hashes and copies every input and records those hashes. It never
compares against a hard-coded binary hash. `--server-revision` and
`--client-revision` are labels only. The script does not check that a binary
was built from the named revision. Use `build-server` to produce a binary
together with its commit receipt. `--label` adds free text. `--output-root`
chooses the parent of the run directory and must be outside this source tree.
Maps must match the pinned fixture hashes in `fixture.py` unless
`--allow-unpinned-maps` is given.

### Clients

Routine runs use headless EQOxide `64492b63f8fb7f6f2f33c835b7211328d79957ff`,
binary SHA-256 `af425c5748312f9d67a0a3c0fa94f04f2031f8d73383f1dfbb5ba7af72b65aa9`.
Also run the older client `d034b7eafae6a0c9cbd4461da6a09a847d61ba4a` (binary
`6271c614d1668d2966f68867e2cdab50df6b94f4c8339a37c1750c564c460505`) when a
server change touches wire or transport. `fixture.VALIDATION_CLIENTS` lists
both. It also lists the previous routine client
`9623e8a451b8794ec56649271b738eddb5ca1c20` (binary
`b8d56995fe2843bea1ccb6687e31f0b15783e393b47ba3cbe066fcda381a6c8b`) and the
historical `fea4596cd14e9b61883e58966ad7d26150715914` (binary
`de96afb5d6458fe9c0601cccb02b2d2430891ec98203943da5d68ec2fd14be50`), so that
older results still name their role. `identity.client.validation_pin` in
`result.json` names the matching role, or is null for any other client. Any
client still runs. The routine journey keeps the 200 ms move. In the
stop-timing probes, a longer move with client fea4596 stopped past the
fixture's accepted strip at X −934.1 (the strip is X −934 to −924).

At every pin move, run the routine journey and the kill-and-respawn variant
with `--census` for both the previous and the new routine client, and compare
the `transport-census.json` files. Do not take a "no wire change" claim on
trust. The census compares ACK, keepalive and session datagrams by count only;
it records opcode, first payload byte and length for every client packet.

Census record at the 64492b6 pin (2026-11-28), against Rust b395aee:

* 64492b6 sends **no** `OP_AutoAttack` (`0x109d`) attack-off after any zone
  entry. 9623e8a sent three after each zone entry, and fea4596 sent two.
* The other attack-offs remain. Both variants send one for the `hit`
  milestone's explicit `attack_off`. Kill-and-respawn also sends one at lease
  expiry, 5.0 s after the last renewal, after the death.
* Camp with attack already off now sends none (9623e8a sent one). Camp with
  attack on, which should send one, is not exercised by either journey.
* Every other outbound reliable packet is identical in order, opcode, first
  payload byte and length. Client keepalive and session datagram counts are
  equal. Client ACK counts follow the reliable-packet difference.
* Outbound unreliable traffic is all 46-byte `OP_ClientUpdate`, with exactly
  23 in the camp window in all four runs. The totals were 27 vs 26 (routine)
  and 43 vs 44 (kill-and-respawn), for 64492b6 vs 9623e8a. The difference is
  at the move-to-rest transition. Sometimes the rest update follows a
  separate moving update (two updates, two server samples). Sometimes it is
  the only update, at a new position, and the server logs `moved` and
  `stopped` for that one sample. Either client shows either form,
  depending on timing. The server's reliable packet count moves with it: 13
  vs 12 and 23 vs 24, one position reply per sample. A count change anywhere
  else would be a real difference.
* Census runs: `20261128T044933Z-2225fa` (64492b6 routine),
  `…045011Z-4debb1` (9623e8a routine), `…045050Z-21c252` (64492b6
  kill-respawn) and `…045151Z-a5885a` (9623e8a kill-respawn), all with
  `run --census` from Stack f5dc79e.

The earlier census that found the third attack-off (9623e8a vs fea4596) used
the pre-check-in probe, which `census.py` matches in what it records. It is
under `~/.local/state/eqemu-rust-journey/probes/transport-census-v3/`, runs
`20261128T023827Z-122427` (fea4596 routine), `…023906Z-c4dfaf` (9623e8a
routine), `…023944Z-1c44cc` (fea4596 kill-respawn) and `…024045Z-a72a25`
(9623e8a kill-respawn).

One-time preparation loads the runtime image into the harness data root:

```sh
scripts/qeynos2-journey prepare-image \
  --archive ~/.local/state/eqemu-map-translation/pr118-beb1068-20261121-v1/runtime-legacy-layout-v1.tar
```

To build one exact server commit offline and run its tests in the same image:

```sh
scripts/qeynos2-journey build-server --repo /abs/bump-eqemu-rust --commit FULL_SHA
```

This writes `build.json` with the commit, tree, source archive hash, test
summaries and binary hash, plus the binary itself, under
`~/.local/state/eqemu-rust-journey/builds/`.

## Environment

Each command starts its own `dockerd-rootless.sh` as a transient user systemd
unit, `eqemu-rust-journey-<id>.service`, on its own socket. The unit has
`RuntimeMaxSec=3600`, and a private RootlessKit state directory. If a killed
host process leaves a unit behind, later commands refuse to start until it
ends. Stop it with `systemctl --user stop 'eqemu-rust-journey-*'`. All commands share the data root
`~/.local/state/eqemu-rust-journey/docker-data`, which holds only the runtime
image. A non-blocking lock in that directory makes concurrent commands fail
instead of sharing it. The default image is the PR118 runtime image
`sha256:630e294d…`: Debian 12, Python 3.11 and OpenSSL 3 with the legacy
provider.

The container has no network, 2 GiB memory without swap, one CPU, 256 PIDs, a
read-only root filesystem, a private `/tmp`, all capabilities dropped except
`NET_RAW`, and `no-new-privileges`. Inputs and the harness copy are mounted
read-only, and the run's `output/` is the only writable mount. Credentials and
the control token are generated inside the container. Every JSON file the
guest writes (`guest-result.json`, `progress.json`, `evidence/`) is written
with those values replaced by `[REDACTED]`. After the processes exit, the same
replacement is applied to the logs, and `log_redactions` counts it. Nothing
else in the logs is changed. A guest killed by SIGKILL can leave raw logs.

The candidates run as the same container user as the guest, so a hostile
binary could rewrite `/output`. The host reads guest JSON only as a bounded
regular file. It accepts a PASS only when the container exits 0 without OOM
or timeout and the guest report agrees. This guards against accidents, not a
deliberately forged report.

The command removes its container and stops its daemon unit in all cases,
including SIGINT or SIGTERM. Signals that arrive during cleanup are recorded
and do not interrupt it. It records each step in `cleanup`. It does not
touch `bump-akk-stack-validation`, the system Docker daemon, or other
`eqemu-*` units and data roots.

## Milestones

In order: `inputs`, `environment`, `observer_self_check`, `server_start`,
`entry`, `move`, `stop`, `target`, `hit`, `camp`, `restart`, `relog`,
`cleanup`. The journey stops at the first failure. Each later milestone is
`not_run`, except `cleanup`, which always runs. `environment` covers the
daemon and the container from start to exit. A container that is OOM-killed,
times out, or exits with a status that disagrees with the guest report fails
`environment`. If the guest dies without a report, the milestone it had
checkpointed in `progress.json` fails instead.

| Milestone | Passes when |
| --- | --- |
| `observer_self_check` | Observer mode only (`not_applicable` with `--evidence client-api`): known loopback datagrams of all seven selected opcodes (eight replies), and their ACK, are captured and decoded exactly. This check found the real observer bug in the first movement run. |
| `server_start` | The endpoint line is first, with `zone_id=2`. The empty state directory reports `load outcome=seeded` at the seed pose. |
| `entry` | The client reports Ready in zone 2, with the pinned geometry digest and ready region data. The seven `entry` stages appear in order on one attempt, all `ok`. The ACKed self spawn is at the seed pose. |
| `move` | One 200 ms westward `move_for` runs and the client's lease ends on its own. The server reports at least one `moved` sample. |
| `stop` | After `stop`, the server reports exactly one `stopped`, within 8 s. All samples move strictly west on unchanged Y/Z, with sequences moving forward, and the stop equals the **final** accepted sample. Each sample has one ACKed `0x7dfc` reply with the same position. A rest sample at a new position (server PR 14) logs `moved` then `stopped` with one sequence and one reply, and counts as one sample. |
| `target` | The rat is selected from the roster by name. The server's `targeted` line matches its entity, incarnation, spawn and NPC type. The `0x58e2` reply is ACKed, and the client log shows the target applied. |
| `hit` | Exactly one attributed `melee_hit` occurs with 1–3 damage from 11 HP, followed by `attack_off`. The `0x6f15` and `0x37b1` replies match the trace and are ACKed. The client logs the hit. |
| `camp` | The client exits 0 on its own within 60 s. The server logs `camp_started`, `camp_completed` and one `save outcome=ok`. The save line, the pose file and the stop pose agree. |
| `restart` | `server1` stops on TERM. A new process on the same state directory reports `load outcome=ok` with the saved pose. |
| `relog` | A fresh client reaches Ready. All entry stages pass again. The ACKed self spawn has the saved pose and heading. The client reports its feet at Z − 3.125. The pose file is unchanged. |

The older client d034b7e reports its resting position only at a 1300 ms
keepalive, and its first stationary packet about 1300 ms after that. The
clients fea4596, 9623e8a and 64492b6 send a rest update on the first step at rest. The stop
check therefore waits for the server's `stopped` line and compares against the
last sample. It passes whether the stop arrives before the stop command, as a
client that reports rest itself may do, or after it. `stop.evidence` records
`stop_seconds` and `move.evidence.stopped_before_stop_command`.

The journey never uses command receipts or client events as evidence. Effects
are proven by the server trace, by ACKed wire replies, and by client log
lines. Server trace parsing lives only in `servertrace.py`. Its shapes are
closed and mirror the server's single emitter, `src/rof2/trace.rs`. A line in
the `entry`, `gameplay`, `persistence` or `zone` family with an unknown stage,
outcome, field set or field order fails the current milestone as a trace
contract violation. This includes the exact detail of successful entry
stages. A new server line therefore needs a matching parser change. Any
`entry ... stage=gameplay outcome=rejected` line fails the milestone during
which it appears, unless that milestone names the exact rejection it expects.
A correct run logs none.

## Wire evidence modes

`run --evidence observer` (the default) proves every reply with the external
raw-socket observer. A client ACK datagram covering the reply must be seen on
the wire, and the proof is labelled `wire_observed`. It is the only evidence
not reported by the client under test, and it keeps the known-traffic
self-check. Use it for Rust changes that touch wire or transport and at every
client pin move.

`run --evidence client-api` takes the same evidence from the running client's
`GET /v2/player/packets` (bump-eqoxide 9623e8a, docs/headless-player.md
"Packet trace") and starts no observer:

* Inbound reliable rows of the journey's opcodes are converted to the
  observer's row shapes (`wire.convert_api_row`) under the observer's own
  selection rules. Each body must have the observer's exact length. The
  delete spawn must end `00 00 01`, checked from `raw=1` payload bytes, which
  are held in memory only and never saved. The self spawn must carry the
  character's name and entity 1. A new spawn must be a named NPC. Delivery is
  the client's own `acked_at_ms`/`ack_seq` report, checked for wrap-aware
  coverage. Rows still waiting for an ACK are read again. Each proof is
  labelled `client_reported`, and respawn timing uses the client-reported
  socket arrival (`arrived_at_ms`).
* `observer_self_check` is `not_applicable`, and `result.json` records
  `evidence_mode: client-api` and `known_traffic_control: false`. This mode's
  controls are offline (`tests/journey/test_wire.py`). A deliberately wrong
  server reply fails both modes, and a hit reported twice under two sequences
  fails.
* The trace lives in the client process, so session 1 is read before the
  camp command. Any page with `gap: true` fails the run, and so does a
  client session change under one cursor. The client says a retransmit never
  adds a row, and the journey still deduplicates by reliable sequence. Damage
  and health replies are counted again just before camp in both modes, so a
  late duplicate fails. `--census` opens a raw socket and is refused with
  `--evidence client-api`.
* The milestones and every assertion are the same in both modes.

## Kill-and-respawn variant

`run --variant kill-respawn` starts the server in `qeynos2-hunting-fast`:
the same content as `qeynos2-hunting`, with a 10 s respawn. It inserts four
milestones between `hit` and `camp` and takes about 60 s. The routine run is
unchanged and remains the default.

| Milestone | Passes when |
| --- | --- |
| `kill` | After the routine hit's `attack_off`, the variant re-arms. It renews the attack lease 1.0, 2.0 and 3.0 s after each observed hit, clear of the next swing due at 3.5 s, until `npc_died`, within 60 s. Any refused renewal fails. Every `melee_hit`, including the routine first hit, is attributed to player→rat incarnation 1. HP falls from 11 to 0, each `hp_before` equals the previous `hp_after`, each hit does 1–3 damage, and only the last hit reaches 0. 4–11 hits are required in total. Each hit has one ACKed `0x6f15` and `0x37b1` matching the trace, and the last health is 0 %. The client logs every hit, in order, with the same damage. No swing is refused before the death. |
| `death` | Exactly one `npc_died` occurs for the rat's entity, incarnation, spawn and NPC type on the active attempt, after the final hit. One ACKed `OP_DeleteSpawn` `0x7280` names the rat, no `OP_NewSpawn` has arrived yet, and the client's ready, untruncated roster drops the rat's entry. |
| `no_swing_after_death` | For 4.5 s after the death was first seen (one 3.5 s swing interval plus margin), the client still reports `attack_on` after the full interval, and the server logs no `attack_armed`, `melee_hit` or `melee_refused`, including in the final snapshot. As an observation only, the variant also sends a `target` for the dead ID and records the client's answer and final receipt. Headless refuses it locally. If the client reports it as sent, the server must log exactly `rejected unpublished_target opcode=0x075d`: the kill removed the peer's binding, so the ID resolves to nothing. No `targeted` line may follow the death. |
| `respawn` | Exactly one `zone outcome=npc_respawned` occurs for the same entity, spawn and NPC type with a higher incarnation. One ACKed `OP_NewSpawn` `0x6097` arrives for that entity, an NPC named `a_large_rat` at 100 % HP, 5–20 s after the delete on the wire. The roster regains the rat, and re-targeting yields `targeted ... incarnation=<new>` with an ACKed `0x58e2` echo that the client applies. No swing or target is logged between the death and that re-target. As an observation only, the variant records `attack_on` at re-target and any swing lines in the following 1.5 s without a fresh attack-on. |

Server facts at bump-eqemu-rust `75e8ffdf8393be1e6a38697c4798e13d7818073c`:

* Swings repeat every 3.5 s (`src/rof2/melee.rs:10`). A repeated
  `OP_AutoAttack` while armed is ignored (`src/rof2/play.rs:177-179`), so
  lease renewals do not change the cadence.
* The fast mode is in `src/main.rs:22-29`, with a 10 s respawn
  (`src/rof2/content.rs:166`). The ordinary mode respawns after 640 s
  (`src/rof2/content.rs:137`).
* After the kill the peer's binding for the wire ID is removed
  (`src/rof2/front/zone.rs:437-439`). A later `OP_TargetMouse` for it
  resolves to nothing (`front/zone.rs:486-493`) and is rejected as
  `unpublished_target` (`src/rof2/play.rs:159-161`). An attack-on after the
  kill is rejected as `no_target` (`play.rs:180`), so the variant never renews
  the lease near a swing.
* Death sends `OP_DeleteSpawn` `0x7280`, 5 bytes `[id_lo, id_hi, 0, 0, 1]`
  (`src/rof2/wire.rs:37`, `wire.rs:252-255`). Respawn sends `OP_NewSpawn`
  `0x6097` built by the same `spawn_packet` as the zone-entry spawn, at hp 100
  (`wire.rs:38`, `wire.rs:152-189`, `src/rof2/front/zone.rs:436-444`).
* `zone outcome=npc_respawned ...` has no attempt field
  (`src/rof2/trace.rs:233-240`). `npc_died` is a gameplay line
  (`trace.rs:264-271`).
* `kill()` clears the target and cancels the auto-attack of every player who
  had the dead NPC targeted, without a trace line (`src/rof2/zone.rs:524-531`).
  A client therefore cannot reach the server's three `stale_target` paths
  after a kill: a due swing is never scheduled, and headless refuses a
  `target` or `attack` for an entity missing from its roster. The three server
  `stale_target` paths (`OP_TargetMouse`, `OP_AutoAttack` and a due swing) are
  covered by the server's own tests, not by this journey.
* The client's attack lease lasts at most 5000 ms, and headless refuses
  `attack` without a live target. At the 10 s respawn the client therefore
  normally reports `attack_on` false, so the re-target observation cannot
  show a client that still believes attack is on.

## Result

`<run-dir>/result.json`, schema `qeynos2-journey-result/v1`:

* `status` is `PASS` or `FAIL`, and `exit_code` is the process exit code.
* `first_failed_milestone` and `failure` (`milestone`, `type`, `message`)
  name the first failure. `guest_traceback` holds the guest traceback.
* `milestones` lists every milestone with its `status` (`pass`, `fail` or
  `not_run`) and `seconds`. Guest milestones also carry `evidence`.
* `identity` records the hashes, sizes and paths of the server and client,
  their revision labels, and the hash of each map with whether it matches the
  pin.
* `fixture` records the fixture constants used.
* `harness` records the Stack commit, whether the harness files were dirty,
  and the hash of each harness file that ran.
* `image`, `environment` (daemon record and container argv), `container`
  (exit, OOM, timeout), and `cleanup` (container and daemon) describe the
  environment.
* `guest` holds the process exits, redaction counts, trace contract
  violations and command receipts.
* `artifacts` gives the paths to the raw logs (`output/logs/server1.log`,
  `client1.log`, `server2.log`, `client2.log`), `guest.log`, observer evidence
  and the state directory.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every milestone passed, including cleanup. |
| 1 | A journey milestone failed. Cleanup completed. |
| 2 | Invalid arguments or inputs. Nothing was started. |
| 3 | The environment failed: daemon, image, container, guest crash, timeout, OOM or interruption. |
| 4 | Cleanup could not be confirmed, whatever the journey verdict. Check `cleanup`. |

## Tests

```sh
python3 -B -m unittest discover -s tests/journey -v
```

These tests cover the trace contract, the movement and wire checks (including
the old first-sample assertion as a red control), pose parsing, input identity
and the result table. Live observer tests run in `unshare -rn`, including a
negative control that reproduces the historical outgoing-only filter. No test
runs a candidate binary.
