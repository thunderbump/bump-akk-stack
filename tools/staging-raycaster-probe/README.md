# Private staging raycaster probe

Implementation for central-z9g4. Parent Stack owns review, installation, reservations,
monitor exclusion, deployment, credentials, live execution, and recovery. No live run
has qualified this helper. Host tests run only Python and mocks.

This is one fixed recipe: Qeynos2, then PoKnowledge, each in a fresh private root,
reserved nonzero instance and unused UDP port. It reuses NPC type 2011 without
changing that row. It inserts exactly one owned spawn2, spawngroup, spawnentry and
instance_list row per zone. Runtime quests set size 6, faction 0, aggro/assist 0,
speed 1.25, and process mobs while empty. Two GMMove calls place the fixed-query
and route fixtures; only ordinary MoveTo(...,0,1) moves the route. No membership is
created. Public instance zero, quests, actors, rules and spawn rows are untouched.

## Parent preparation

Run only inside the existing staging container, where the existing world TCP
endpoint is 127.0.0.1. Install Python 3.11+ and PyMySQL through the parent's reviewed
container procedure. This helper installs nothing. Do not run as part of host tests.

Parent must hold exclusive ownership of both reserved instance IDs, versions, spawn
IDs, group IDs and UDP ports throughout this invocation and cleanup. Select distinct
instance IDs inside the server's `Instances:ReservedInstances` range, versions 1..255
unused for each zone, and distinct unused ports. A named SQL lock excludes other
copies of this helper; it does not reserve resources against unrelated operators.
The parent must coordinate those operators. InnoDB SERIALIZABLE row/range locks
protect checks/inserts until commit. Nontransactional tables, triggers, and foreign
keys are refused. No fixture data is imported and no database is reset.

Prepare an owner-only contract JSON, outside version control. Required fields:

```json
{
  "monitor_window": "exclusive-between-public-samples",
  "operator_exclusive_reservations": true,
  "read_only_assets": true,
  "world_pid": 123,
  "ruleset_id": 0,
  "ruleset_name": "default",
  "assets": {
    "maps": "/READ_ONLY/maps",
    "patches": "/READ_ONLY/opcodes",
    "opcodes": "/READ_ONLY/opcodes",
    "shared_memory": "/READ_ONLY/shared"
  },
  "zones": {
    "qeynos2": {
      "instance": 30001, "version": 250, "port": 17901,
      "spawn": 1900000001, "group": 1900000001,
      "reference": "/PRIVATE/qualified-qeynos2.log",
      "reference_sha256": "REVIEWED_64_HEX_SHA256",
      "reference_backend": "OFF"
    },
    "poknowledge": {
      "instance": 30002, "version": 251, "port": 17902,
      "spawn": 1900000002, "group": 1900000002,
      "reference": "/PRIVATE/qualified-poknowledge.log",
      "reference_sha256": "REVIEWED_64_HEX_SHA256",
      "reference_backend": "OFF"
    }
  },
  "schemas": {"REPLACE_WITH_ALL_KEYS_BELOW": "REVIEWED_SHA256"}
}
```

Numbers above illustrate shape and are not reservations. Parent supplies actual
qualified baseline logs, pins their SHA256, and verifies their provenance. Each
baseline must pass the pinned comparator for that exact zone and its declared
backend. Missing references never produce a PASS. This compares exact fixed
queries, native callers/nodes/route admission, route floor samples and final pose.
Movement cadence may differ. Missing/nonfinite evidence, wrong entity/backend,
teleport dispatch, exhausted/malformed observation budget, or interpolation outside
the frozen corridor fails. Routes and comparator are exact vendored source files,
pinned in `vendor/pins.json`; modified quests are derived in memory at preparation.

For each schema key below, independently review `SHOW CREATE TABLE`, remove only
` AUTO_INCREMENT=<digits>`, then SHA256 the remaining UTF-8 DDL without a trailing
newline. Unknown or missing schemas refuse before fixture writes. The manifest
retains the exact normalized DDL plus digest and original fixture rows plus digest.
Do not accept schema pins from an unreviewed live dump automatically.

- Gameplay keys: `game.instance_list`, `game.respawn_times`,
  `game.spawn_condition_values`, `game.spawn2_disabled`, `game.data_buckets`,
  `game.zone_state_spawns`, `game.instance_list_player`, `game.character_corpses`,
  `game.dynamic_zones`, `game.character_data`, `game.rule_values`, `game.rule_sets`,
  `game.variables`.
- Content keys: `content.spawn2`, `content.spawngroup`, `content.spawnentry`,
  `content.npc_types`, `content.zone`.

Gameplay/content DB names may differ. This minimal recipe requires identical
server/port/credentials with permissions to both DBs so a single transaction owns
bootstrap and compensation. Separate connections are refused. Credentials come
only from the private server config, never CLI arguments or environment variables.
The parent must supply fully populated DB settings and a loopback world TCP address
and existing key. No config/raw native output/driver exception is copied to receipts.
Private generated `eqemu_config.json` files contain credentials: keep the entire
root owner-only and never publish those files. Publish only the scrubbed receipt,
evidence logs and ownership manifest after review.

Mount existing actual maps, navigation assets, opcodes and shared memory read-only
at the contract's absolute directories. The parent asserts and enforces those
mounts; this helper checks directories exist but does not change mount permissions.
All quest/plugin/module scalar paths AND override arrays are replaced. Each root
has empty private plugins, modules, mods and logs, and ONLY
`quests/ZONE/v<VERSION>/2011.pl`. No public/global quest fallback is installed.

Before any insert, all explicit Map:FindBestZHeightAdjust=1,
Map:FixZWhenPathing=true, Zone:UseZoneController=false, Bots:Enabled=false and
Zone:StateSavingOnShutdown=false values must already match. The active ruleset
name/ID and zone effective ruleset must agree; missing values refuse. Matching
version or -1 wildcard spawns, occupied row/instance/version reservations, existing
instance persistent state, memberships, corpses, characters or dynamic zones refuse.
The helper never changes a production rule to meet these requirements.

## Controlled invocation

After parent review and the monitor exclusion described below, run once:

```sh
python3 /APP/tools/staging-raycaster-probe/probe.py \
  --config /PRIVATE/existing-config.json \
  --contract /PRIVATE/reviewed-probe-contract.json \
  --root /PRIVATE/new-exclusive-run-root \
  --zone-binary /RELEASE/zone
```

The root must not exist. There is no import-time work or automatic retry. Zone and
world hashes are fixed in code to the authorized matched ON binaries. The source
commit is `6a037f008f9398df5967fa70ded0de32a9e83335`; retained 1bcb binaries have no
production delta to that source, per the parent brief. Each process gets only its
own `EQEMU_COLLISION_OBSERVE=server-collision-npc-2011`, with the native budget of
4096. Only one NPC in its private version can be observed. Existing world PID and
both ends of its established loopback TCP connection must match the private child.

Each route gets at most 120 seconds, then a 3-second stop-file interval, up to
5 seconds after TERM, KILL if needed, up to 5 seconds to reap, and a bounded final
pipe drain. Output is capped at 4 MiB per child. Child core dumps are disabled and each native
log file has a 4 MiB RLIMIT_FSIZE cap; parent must bound the private root disk
allocation as part of installation. Quest evidence prints directly to
stdout; no global Quest Debug setting is required. Every started child has PID,
exit, elapsed time, stop acknowledgement, TERM/KILL and reap results recorded.
Collision success and clean shutdown are both required. A failed initial zone
stops the sequence. No automatic retry or active hourly scheduler is installed.

Bootstrap inserts share one transaction. Partial insertion failure rolls it back.
The private ownership manifest is fsynced before COMMIT. After children are reaped,
cleanup checks player/dynamic state again, captures only the known instance-scoped
persistent rows, and deletes those exact row values. Fixture cleanup includes an
explicit exact `instance_list` deletion because Server DeleteInstance omits it.
Every conditional deletion requires one matching unchanged row and one affected
row. A conflict rolls cleanup back and leaves an operator-visible failure, never
an unqualified delete. No public row is restored from a snapshot or overwritten.

If the helper/container is forcibly lost, use the manifest and receipt under the
parent's live ownership procedure. Verify both child PIDs/process groups are gone,
check no membership/player state, compare every row to the manifest, then remove
only exactly matching created rows and reviewed instance-scoped persistent rows in
one transaction. Do not call broad DeleteInstance, delete by NPC type, delete public
spawns, or retry automatically. Short instance expiry is 600 seconds and is not a
substitute for confirmed content-row cleanup. An ambiguous COMMIT response requires
operator inspection if exact compensation cannot be proved.

## Monitor and remaining qualification

The five-minute monitor counts three public zones. Extra private processes must
never satisfy that count or enter its baseline. Parent must place this bounded
sequence wholly between completed public samples, hold an exclusive exclusion
window, and verify both private children are reaped before the next sample. With
120 seconds per zone plus shutdown bounds, budget at least 280 seconds plus DB
preflight/cleanup overhead. If the window is too short, skip the probe and report
it; do not suppress/skip a due public sample and claim continuous monitor coverage.
A parent-approved classification contract that identifies public PIDs separately
could replace that scheduling constraint, but this PR does not edit the monitor.
Hourly probes remain optional until the initial gate and window are qualified.

One finite Server gap remains: the existing map reload route queues all zones;
no targeted private-instance reload route was found. This helper issues no reload
and never writes invalid/empty assets. Fresh private processes test initial map
loading and native route behavior; they cannot qualify map reload during this soak.
Parent must carry that exact reload gap into the soak report.

Source assessment used common/file.cpp:55, common/path_manager.cpp:30,
common/eqemu_config.cpp:130, zone/main.cpp:203, common/database_instances.cpp:111,
:387 and :485, zone/spawn2.cpp:505, zone/npc.cpp:2272, zone/npc.h:319,
zone/questmgr.cpp:1160, zone/collision_observation.h, zone/worldserver.cpp:4591,
and tests/map_server_validation/runtime.py at the pinned commit. Unlike that fresh
DB test, this helper performs no reset/import/global edits or global reload.

## Harmless verification

```sh
python3 -m unittest discover -s tools/staging-raycaster-probe/tests -v
python3 -m py_compile tools/staging-raycaster-probe/probe.py tools/staging-raycaster-probe/vendor/evidence.py
```
