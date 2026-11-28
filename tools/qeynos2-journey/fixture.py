"""Pinned Qeynos2 hunting fixture used by the headless journey.

These values describe the fixture, not a server build. Build identity is
always measured from the binaries passed in. Sources: the server README and
tests/qeynos2.rs at 3939f187af2c357b759ad10ae5fb2d6ff4801077 and the
2026-11-24 fixture worklog in Operations.
"""

SERVER_MODE = "qeynos2-hunting"
CHARACTER = "Clientab"
ZONE_ID = 2
ZONE_NAME = "qeynos2"
WORLD_NAME = "Rust Qeynos2"
WORLD_HOST = "127.0.0.1"

# Server model-origin seed pose on an empty state directory.
SEED_XYZ = (-925.0, 1194.0, 3.125)
SEED_HEADING = 0
# Headless subtracts this from wire Z to report its feet position.
CLIENT_FEET_OFFSET = 3.125

RAT_NAME_PREFIX = "a_large_rat"
RAT_SPAWN_ID = 10863
RAT_NPC_TYPE = 2011
RAT_MAX_HP = 11
RAT_INCARNATION = 1
DAMAGE_RANGE = (1, 3)

# The one movement command of the journey.
MOVE = {"kind": "move_for", "east": -1, "north": 0, "duration_ms": 200}
ATTACK_LEASE_MS = 2000

ENTRY_STAGES = (
    "login_accepted",
    "world_selected",
    "world_authenticated",
    "character_selected",
    "zone_endpoint",
    "zone_entered",
    "client_ready",
)

POSE_FORMAT = "qeynos2-pose-v1"
POSE_FILE = "clientab.pose"

# Headless clients coordination has selected, by executable SHA-256. Recorded
# in result.json as identity.client.validation_pin; never used as a gate.
VALIDATION_CLIENTS = {
    "b8d56995fe2843bea1ccb6687e31f0b15783e393b47ba3cbe066fcda381a6c8b": {
        "revision": "9623e8a451b8794ec56649271b738eddb5ca1c20", "role": "routine"},
    "de96afb5d6458fe9c0601cccb02b2d2430891ec98203943da5d68ec2fd14be50": {
        "revision": "fea4596cd14e9b61883e58966ad7d26150715914", "role": "previous_routine"},
    "6271c614d1668d2966f68867e2cdab50df6b94f4c8339a37c1750c564c460505": {
        "revision": "d034b7eafae6a0c9cbd4461da6a09a847d61ba4a", "role": "older_client_check"},
}

# Pinned map inputs. The client's geometry digest is the .map SHA-256.
PINNED_MAPS = {
    "qeynos2.map": "040343c54e3b02bfd1637ce8fca8839dd676e17c41fb24c042ccfa0bd649435c",
    "qeynos2.wtr": "237d114e3b60a839c9ee0b2cba23dc4221057afc7add8aabae55ee61e89c4bdc",
}

# Ordered journey milestones. The host owns inputs, environment and cleanup;
# the guest owns the rest.
HOST_PRE = ("inputs", "environment")
GUEST = (
    "observer_self_check",
    "server_start",
    "entry",
    "move",
    "stop",
    "target",
    "hit",
    "camp",
    "restart",
    "relog",
)
HOST_POST = ("cleanup",)
MILESTONES = HOST_PRE + GUEST + HOST_POST

# Journey variants. "routine" is the default ~40 s run. "kill-respawn" uses the
# server's fast-respawn mode (bump-eqemu-rust 75e8ffd src/main.rs:22-25,
# src/rof2/content.rs:166) and adds four milestones between hit and camp.
KILL_RESPAWN = GUEST[:GUEST.index("hit") + 1] + ("kill", "death", "no_swing_after_death", "respawn") \
    + GUEST[GUEST.index("hit") + 1:]
VARIANTS = {
    "routine": {"server_mode": SERVER_MODE, "milestones": GUEST},
    "kill-respawn": {"server_mode": "qeynos2-hunting-fast", "milestones": KILL_RESPAWN},
}


def milestones(variant: str) -> tuple:
    return HOST_PRE + VARIANTS[variant]["milestones"] + HOST_POST


# Kill-and-respawn timing. Swings repeat every 3.5 s (src/rof2/melee.rs:10);
# fast respawn is 10 s (src/main.rs:22-29, src/rof2/content.rs:166). Lease
# renewals go at fixed offsets after each observed hit, clear of the next due
# swing; the last one leaves the client's attack-on active long enough to
# observe that no swing follows the death (the server cancels it on a kill,
# src/rof2/zone.rs:524-531).
KILL_HITS = (4, 11)  # 11 HP at 1-3 per hit, counting the routine first hit
KILL_LEASE_MS = 5000
RENEW_AFTER_HIT = (1.0, 2.0, 3.0)  # seconds after each observed hit; the next swing is due at 3.5
KILL_TIMEOUT = 60.0
REPEAT_DELAY = 3.5  # server swing interval, src/rof2/melee.rs:10
STALE_OBSERVE = 4.5  # observe one swing interval plus margin after the death
ROSTER_TIMEOUT = 3.0
RESPAWN_TIMEOUT = 20.0  # after the death was first observed
RESPAWN_DELAY_RANGE = (5.0, 20.0)  # delete-to-new-spawn wire gap accepted
STALE_TARGET_WAIT = 2.0
FAST_RESPAWN = 10.0  # src/rof2/content.rs:166
RESPAWN_MARGIN = 1.0  # the dead-ID probe must finish this long before it
RETARGET_OBSERVE = 1.5  # > 150 ms windup plus margin

# Waits (seconds).
SERVER_START_TIMEOUT = 10.0
READY_TIMEOUT = 90.0
MOTION_EXPIRE_TIMEOUT = 2.0
# The older client d034b7e sends its resting position only at a 1300 ms
# keepalive and the first stationary packet about 1300 ms later, so the
# server's stopped sample can lag the stop command by ~2.6 s. Clients fea4596
# and 9623e8a (the verified revisions) send a rest update on the first step
# at rest.
STOP_TIMEOUT = 8.0
STOP_QUIET = 0.5
TARGET_TIMEOUT = 3.0
HIT_TIMEOUT = 2.0
ATTACK_OBSERVE = 2.3
WIRE_ACK_TIMEOUT = 3.0
CAMP_TIMEOUT = 60.0
SERVER_STOP_TIMEOUT = 10.0
CHILD_STOP_TIMEOUT = 20.0
LOG_LIMIT_BYTES = 64 * 1024 * 1024
