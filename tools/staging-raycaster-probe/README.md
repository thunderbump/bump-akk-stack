# Private staging raycaster probe

Implementation for central-z9g4. Parent Stack owns review, installation, reservations,
monitor exclusion, deployment, credentials, live execution, and recovery. No live run
has qualified this helper. Host tests run only Python and mocks.

This is one fixed recipe: Qeynos2 and PoKnowledge, each in a fresh private root,
reserved nonzero instance and unused UDP port. It reuses NPC type 2011 without
changing that row. It inserts exactly one owned spawn2, spawngroup, spawnentry and
instance_list row per zone. Runtime quests set size 6, faction 0, aggro/assist 0,
speed 1.25, and process mobs while empty. Two GMMove calls place the fixed-query
and route fixtures; only ordinary MoveTo(...,0,1) moves the route. No membership is
created. Helper-managed writes are confined to owned fixture rows. Player/inventory, public
spawn definitions, actor checkpoints, quests and rules are protected. Native zone
startup additionally runs ordinary global expired-NPC-respawn-timer and expired
quest-global cleanup, plus event-log setting initialization. Parent accepted these
unchanged production lifecycle calls for this staging test; it is not strict
confinement of every native DB write. Event-log initialization loads configured
settings, adds missing implemented entries and removes deprecated/unimplemented
entries; it does not generally reset configured active settings. The automatic
database-update flag does not disable these lifecycle calls. Expired quest values
are not exported; parent retains aggregate expiry counts only. No stale timer is restored and no shared
AUTO_INCREMENT counter is rewound.

## Parent preparation

Run only inside the existing staging container, where the existing world TCP
endpoint is 127.0.0.1. Python 3.11+ must already be present. The helper verifies and imports the task-local
PyMySQL 1.1.2 wheel by exact SHA256 and explicit path. It installs nothing and
requires no default dependencies for the existing mysql_native_password account.
Initial and switched authentication must be mysql_native_password. The helper blocks
optional cryptography/PyNaCl import during fresh driver loading and refuses an
already-imported optional module. Other authentication refuses; no package is
downloaded at runtime. `vendor/pymysql-provenance.json` records official PyPI URL,
metadata, wheel/member hashes, license and authentication limits. Do not run as part of host tests.

Parent must hold exclusive ownership of both reserved instance IDs, versions, spawn
IDs, group IDs and UDP ports throughout this invocation and cleanup. Select distinct
instance IDs inside the server's `Instances:ReservedInstances` range, versions 1..255
unused for each zone, and distinct unused ports. A named SQL lock excludes other
copies of this helper; it does not reserve resources against unrelated operators.
The parent must coordinate those operators. InnoDB SERIALIZABLE row/range locks
protect checks/inserts until commit. Nontransactional fixture tables, triggers on mutated tables, and foreign
keys referencing or originating from any mutated table are refused. Incoming
references match UNIQUE_CONSTRAINT_SCHEMA independently from the outgoing
CONSTRAINT_SCHEMA, including cross-database references. Unrelated
constraints on player-only tables are retained and never changed. No fixture data is imported and no database is reset.

Prepare an owner-only contract JSON, outside version control. Required fields:

```json
{
  "monitor_window": "exclusive-between-public-samples",
  "operator_exclusive_reservations": true,
  "read_only_assets": true,
  "allow_native_expired_timer_housekeeping": true,
  "world_pid": 123,
  "ruleset_id": 0,
  "ruleset_name": "default",
  "support_root": "/READ_ONLY/runtime-support",
  "support_manifest_sha256": "69e8d20fc25e3a0bfe8793762e765a7423956521b0d23b373c9bb629af24c381",
  "shared_blobs": {
    "items": {"bytes": 156747856, "sha256": "REVIEWED_64_HEX_SHA256"},
    "spells": {"bytes": 46352076, "sha256": "REVIEWED_64_HEX_SHA256"}
  },
  "default_rule_rows_sha256": "REVIEWED_64_HEX_SHA256",
  "assets": {
    "maps": "/READ_ONLY/maps",
    "patches": "/READ_ONLY/opcodes",
    "opcodes": "/READ_ONLY/opcodes",
    "shared_memory": "/READ_ONLY/shared"
  },
  "zones": {
    "qeynos2": {
      "instance": 90, "version": 250, "port": 17901,
      "ruleset_id": 1, "rule_rows_sha256": "REVIEWED_64_HEX_SHA256",
      "spawn": 1900000001, "group": 1900000001,
      "reference": "/PRIVATE/qualified-qeynos2.log",
      "reference_sha256": "REVIEWED_64_HEX_SHA256",
      "reference_backend": "OFF"
    },
    "poknowledge": {
      "instance": 91, "version": 251, "port": 17902,
      "ruleset_id": 2, "rule_rows_sha256": "REVIEWED_64_HEX_SHA256",
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
  `game.variables`, `game.spawn_events`.
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

Provide verified read-only maps/navigation/opcodes and frozen shared seed files at
the contract's absolute input directories. The actual native MemoryMappedFile
consumer requires O_RDWR, same-size ftruncate and MAP_SHARED even for loading
existing items/spells. It cannot consume the frozen shared seeds directly.

The helper verifies every input before DB connection/bootstrap, then creates a
fresh shared directory inside each private process root. It copies exactly items
and spells, verifies initial size/hash and the source again, modes copies 0600,
and creates private zero-byte items.lock/spells.lock files. The generated config
always points to this private shared directory. Total seed bytes are capped at
256MiB per process; two initial roots can use at most 512MiB plus bounded logs and
receipts. Each copy requires 64MiB additional free-disk reserve. This is a byte
budget, not an installed quota or a proven peak resource fit. Original shared
files/locks and frozen seeds are never opened for writing or removed.

Only after every started native child is confirmed reaped does cleanup verify the
known copy inode identities, retain post-use hashes, unlink exactly those copies
and locks, then remove the empty shared directory. Native changes to a private
copy are recorded, not attributed to the raycaster. Incomplete/replaced/unknown
files or cleanup faults are retained and force NONPASS; no recursive root/log
removal occurs. Support modules, quests, private configs and evidence remain.

The first native attempt exposed required CheckHandin compatibility utilities.
Use only the four already-deployed files named and hashed in
vendor/runtime-support-pins.json: plugins/check_handin.pl and plugins/globals.pl,
plus modules/items.lua and modules/string_ext.lua. The globals file is a plugin
utility, not a global NPC quest. The support manifest is fixed by source and must
match the contract; all payload file hashes/sizes are verified. At most 64KiB of
support data is accepted. No marker stubs, downloads, package installation or
public/global quest fallback are used. These modules provide the compatibility
closure; the collision fixture does not invoke or qualify item hand-in behavior.

All quest/plugin/module scalar paths AND override arrays point only to each fresh
private root. Plugins/modules contain only those four pinned utilities, mods and
logs begin empty, and the only NPC quest is quests/ZONE/v<VERSION>/2011.pl. No
public Rat quest, global_npc script or public plugin search path is installed.

Before any insert, all explicit Map:FindBestZHeightAdjust=1,
Map:FixZWhenPathing=true, Zone:UseZoneController=true, Bots:Enabled=false and
Zone:StateSavingOnShutdown=false values must already match. The named default ID and each zone ruleset ID are pinned. Missing RuleSet variable
uses the native named-default fallback. Default rows load first, then the selected
zone ruleset rows, as rulesys.cpp does. Complete ordered row hashes are pinned and
all five effective values must match; missing values refuse. A native zone controller
can exist off-map but has no quest in the private root and is not NPC 2011. No public
controller script or quest fallback is available. Any spawn_events row for either selected zone refuses before bootstrap, including
disabled rows. Nonzero instance/version does not isolate native event scheduling.
Matching version or -1 wildcard spawns, occupied row/instance/version reservations, existing
instance persistent state, memberships, corpses, characters or dynamic zones refuse.
The helper never changes a production rule to meet these requirements.

## Native housekeeping evidence

Before bootstrap and after cleanup, retain the complete respawn_times rows and DB
UNIX timestamps. Each snapshot is at most 256 rows and 65536 encoded bytes. A row
or byte overflow refuses the probe or invalidates its result; no clipping or
sampling. Native startup can delete globally expired rows. Concurrent world
activity can also change them, so a difference is not process attribution. Neither
timer snapshots nor fixture manifests authorize restoring stale public timers or
expired quest globals. The fixed acknowledgment field names the timer exception;
its documented parent scope also includes the unchanged lifecycle calls above.
It is not permission for arbitrary queries or changes to active player state.

Select unused content ID holes below current AUTO_INCREMENT counters where
possible, and prove group IDs have no existing spawn2/spawnentry references. Parent
retains exclusive reservations. Normal counter advancement from new owned instance
rows is preserved during cleanup; do not reset counters or erase old instance state.

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
allocation as part of installation. The generated private quest duplicates fixed
OS descriptor 1 using Perl `open(my $probe_output, '>&', 1)`. It does not alias
the descriptor with `>&=1`, untie global STDOUT/STDERR, or use their tied logging
path. Closing the lexical duplicate leaves original descriptor 1 usable. The
lexical handle remains in scope across that quest's events. Fixed ASCII records
use unbuffered `syswrite`, so there is no deferred flush. Open/mode errors fail
quest loading; oversized records, failed/short writes and broken pipes latch a
failure that rejects subsequent completion markers. SIGPIPE is ignored only
within that write so its error can be checked. Each record is at most 4096 bytes;
the existing combined child pipe and 4 MiB capture budget remain unchanged. No
public DB logging change or separate output channel is needed. The harmless
tied-Perl controls exercise both generated quests, descriptor close ownership and
error paths; they do not qualify native collision behavior or shutdown. The
lifecycle guard begins immediately after Popen. Stop-file, pipe, signaling and
selector faults are recorded independently and do not suppress kill/reap attempts.
Every started child has PID,
exit, elapsed time, stop acknowledgement, TERM/KILL and reap results recorded.
Collision success and clean shutdown are both required. A failed initial zone
stops the sequence. No automatic retry or active hourly scheduler is installed.

Bootstrap inserts share one transaction. Partial insertion failure rolls it back.
The private ownership manifest is fsynced before COMMIT. After children are reaped,
cleanup checks player/dynamic state again, captures only the known instance-scoped
persistent rows, and deletes those exact row values. Fixture cleanup includes an
explicit exact `instance_list` deletion because Server DeleteInstance omits it.
Every conditional deletion locks by the schema-pinned integer primary or unique
identity, compares the complete returned row to the retained canonical snapshot,
then deletes by that identity under the same transaction lock. The sole text key,
spawn-condition zone, uses explicit binary comparison. FLOAT coordinates are never
sent back as equality predicates; case/space-insensitive collation cannot establish
ownership. Each delete requires exactly one affected row. A conflict rolls cleanup back and leaves an operator-visible failure, never
an unqualified delete. No public row is restored from a snapshot or overwritten.

If the helper/container is forcibly lost, use the manifest and receipt under the
parent's live ownership procedure. Verify both child PIDs/process groups are gone,
check no membership/player state, compare every row to the manifest, then remove
only exactly matching created rows and reviewed instance-scoped persistent rows in
one transaction. Do not call broad DeleteInstance, delete by NPC type, delete public
spawns, or retry automatically. Short instance expiry is 600 seconds and is not a
substitute for confirmed content-row cleanup. An ambiguous COMMIT response requires
operator inspection if exact compensation cannot be proved. Rollback and close
failures are guarded independently so the failure receipt remains reachable even
on a dead connection; no ambiguous database outcome is called cleanup success.

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
For hourly work, `only_zone` must select `qeynos2` or `poknowledge` in the contract.
Run each in a separate five-minute window immediately after a completed public
sample, with at least 200 seconds remaining. Initial qualification may omit
`only_zone` to run both before the clock starts. No timer is installed here.
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
