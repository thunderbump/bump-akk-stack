"""The Rust server's stdout trace contract, parsed in one place.

The startup endpoint line and the ``entry``, ``gameplay``, ``persistence`` and
``zone`` lines are a contract the server refactor must keep byte-identical.
Every other part of the journey reads server output only through this module.

The shapes are closed: they mirror the server's single emitter,
``src/rof2/trace.rs`` (``Trace`` and its ``Display``) at bump-eqemu-rust
75e8ffdf8393be1e6a38697c4798e13d7818073c. A line whose first word is a
contract family but whose stage, outcome, fields or field order is not one of
those shapes is ``malformed``, and the journey fails loudly on it. A new
server line therefore needs a matching change here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

ENDPOINT_RE = re.compile(
    r"login=127\.0\.0\.1:(\d+) world=127\.0\.0\.1:(\d+) zone=127\.0\.0\.1:(\d+) zone_id=(\d+)"
)
FAMILIES = ("entry", "gameplay", "persistence", "zone")
HEAD_RE = re.compile(
    r"(entry|gameplay|persistence) attempt=(none|\d+)(?: stage=([a-z_]+))? outcome=([a-z_]+)(?: (.*))?"
)
ZONE_RE = re.compile(r"zone outcome=([a-z_]+)(?: (.*))?")
# trace.rs Stage::label.
ENTRY_STAGES = {
    "login_session", "credentials", "login_accepted", "server_list", "world_selection",
    "world_selected", "world_login", "world_authenticated", "character_selection",
    "character_selected", "zone_endpoint", "zone_entry", "zone_entered", "request_spawn",
    "request_new_zone", "experience_echo", "client_ready", "complete", "gameplay",
}
# trace.rs Entry: ok | ok zone=N | rejected R | rejected R opcode=0xHHHH | ended R.
ENTRY_DETAIL_RE = {
    "ok": re.compile(r"(?:zone=\d+)?"),
    "rejected": re.compile(r"[a-z_]+(?: opcode=0x[0-9a-f]{4})?"),
    "ended": re.compile(r"[a-z_]+"),
}
NUMBER_RE = re.compile(r"-?\d+(?:\.\d+)?")
TOKEN_RE = re.compile(r"([a-z_]+)=(\S+)")

POSE_FIELDS = ("character", "zone", "x", "y", "z", "heading")
GAMEPLAY_FIELDS = {
    "moved": ("sequence", "x", "y", "z"),
    "stopped": ("sequence", "x", "y", "z"),
    "targeted": ("entity_id", "incarnation", "spawn_id", "npc_type"),
    "attack_armed": ("source_entity", "target_entity", "incarnation"),
    "attack_off": ("canceled",),
    "melee_hit": (
        "source_entity",
        "target_entity",
        "incarnation",
        "spawn_id",
        "npc_type",
        "damage",
        "hp_before",
        "hp_after",
    ),
    "melee_refused": ("source_entity", "target_entity", "incarnation", "reason"),
    "camp_started": (),
    "camp_canceled": (),
    "camp_incomplete": (),
    "logout_without_camp": (),
    "camp_completed": (),
    "camp_interrupted": ("reason",),
    "npc_died": ("entity_id", "incarnation", "spawn_id", "npc_type"),
}
ZONE_FIELDS = {
    "npc_respawned": ("entity_id", "incarnation", "spawn_id", "npc_type"),
}
PERSISTENCE_FIELDS = {
    ("save", "ok"): POSE_FIELDS,
    ("load", "ok"): POSE_FIELDS,
    ("load", "seeded"): POSE_FIELDS,
    ("save", "failed"): ("kind",),
    ("save", "uncertain"): ("kind",),
    ("load", "failed"): ("kind",),
    ("save", "disabled"): (),
}
# Successful entry stages and their exact detail text.
ENTRY_OK_DETAIL = {
    "login_accepted": "",
    "world_selected": "",
    "world_authenticated": "",
    "character_selected": "",
    "zone_endpoint": "",
    "zone_entered": "zone=2",
    "client_ready": "zone=2",
}
# Diagnostic stderr lines that share a contract prefix but carry no attempt.
DIAGNOSTIC_RE = re.compile(r"entry transport_send_error kind=\w+")

NUMERIC = {
    "sequence",
    "x",
    "y",
    "z",
    "heading",
    "zone",
    "entity_id",
    "incarnation",
    "spawn_id",
    "npc_type",
    "source_entity",
    "target_entity",
    "damage",
    "hp_before",
    "hp_after",
}


@dataclass(frozen=True)
class Endpoints:
    login: int
    world: int
    zone: int
    zone_id: int
    raw: str


@dataclass(frozen=True)
class Line:
    """One parsed trace line.

    ``kind`` is entry, gameplay, persistence, endpoints, malformed or other.
    ``fields`` holds ``key=value`` details in order; for entry lines ``detail``
    holds the free-form remainder.
    """

    kind: str
    raw: str
    index: int
    attempt: str | None = None
    stage: str | None = None
    outcome: str | None = None
    fields: dict = field(default_factory=dict)
    detail: str = ""
    endpoints: Endpoints | None = None
    problem: str | None = None

    def number(self, key: str) -> float:
        return float(self.fields[key])

    def xyz(self) -> list[float]:
        return [float(self.fields[k]) for k in ("x", "y", "z")]

    def as_dict(self) -> dict:
        out = {"kind": self.kind, "index": self.index, "raw": self.raw}
        for key in ("attempt", "stage", "outcome", "problem"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        if self.fields:
            out["fields"] = dict(self.fields)
        return out


def _fields(rest: str | None) -> list[tuple[str, str]] | None:
    if not rest:
        return []
    out = []
    for token in rest.split(" "):
        match = TOKEN_RE.fullmatch(token)
        if not match:
            return None
        out.append((match[1], match[2]))
    return out


def _check(expected: tuple, pairs: list[tuple[str, str]]) -> str | None:
    names = tuple(k for k, _ in pairs)
    if names != expected:
        return f"fields {names} != {expected}"
    for key, value in pairs:
        if key in NUMERIC and not NUMBER_RE.fullmatch(value):
            return f"non-numeric {key}={value}"
    return None


def parse_line(raw: str, index: int = 0) -> Line:
    """Parse one stdout/stderr line (without its newline)."""
    match = ENDPOINT_RE.fullmatch(raw)
    if match:
        ports = [int(match[i]) for i in range(1, 5)]
        endpoints = Endpoints(*ports, raw=raw)
        return Line("endpoints", raw, index, endpoints=endpoints)
    prefix = re.split(r"\s", raw, maxsplit=1)[0]
    if prefix not in FAMILIES or DIAGNOSTIC_RE.fullmatch(raw):
        return Line("other", raw, index)
    if prefix == "zone":
        match = ZONE_RE.fullmatch(raw)
        pairs = _fields(match[2]) if match else None
        expected = ZONE_FIELDS.get(match[1]) if match else None
        if pairs is None or expected is None:
            return Line("malformed", raw, index, problem="unknown zone line")
        problem = _check(expected, pairs)
        if problem:
            return Line("malformed", raw, index, outcome=match[1], problem=problem)
        return Line("zone", raw, index, outcome=match[1], fields=dict(pairs))
    match = HEAD_RE.fullmatch(raw)
    if not match:
        return Line("malformed", raw, index, problem="head does not match")
    kind, attempt, stage, outcome, rest = match.groups()
    if kind == "entry":
        if stage is None:
            return Line("malformed", raw, index, problem="entry without stage")
        if stage not in ENTRY_STAGES:
            return Line("malformed", raw, index, problem=f"unknown entry stage {stage}")
        detail_re = ENTRY_DETAIL_RE.get(outcome)
        if detail_re is None or not detail_re.fullmatch(rest or ""):
            return Line("malformed", raw, index, attempt, stage, outcome,
                        problem=f"unknown entry outcome shape {outcome} {rest!r}")
        pairs = _fields(rest) or []
        if outcome == "ok" and stage in ENTRY_OK_DETAIL:
            expected_detail = ENTRY_OK_DETAIL[stage]
            if (rest or "") != expected_detail:
                return Line("malformed", raw, index, attempt, stage, outcome,
                            problem=f"detail {rest!r} != {expected_detail!r}")
        return Line(
            kind, raw, index, attempt, stage, outcome, dict(pairs), detail=rest or ""
        )
    pairs = _fields(rest)
    if pairs is None:
        return Line("malformed", raw, index, attempt, stage, outcome, problem="bad fields")
    if kind == "gameplay":
        if stage is not None:
            return Line("malformed", raw, index, problem="gameplay with stage")
        expected = GAMEPLAY_FIELDS.get(outcome)
    else:
        if stage is None:
            return Line("malformed", raw, index, problem="persistence without stage")
        expected = PERSISTENCE_FIELDS.get((stage, outcome))
    if expected is None:
        return Line("malformed", raw, index, attempt, stage, outcome,
                    problem=f"unknown {kind} outcome {outcome}")
    problem = _check(expected, pairs)
    if problem:
        return Line("malformed", raw, index, attempt, stage, outcome, problem=problem)
    return Line(kind, raw, index, attempt, stage, outcome, dict(pairs))


def parse_log(text: str) -> list[Line]:
    """Parse complete lines only; a trailing partial line is ignored."""
    lines = text.split("\n")
    return [parse_line(raw, i) for i, raw in enumerate(lines[:-1])]


class Trace:
    """Convenience queries over one server process's parsed output."""

    def __init__(self, text: str):
        self.lines = parse_log(text)

    def endpoints(self) -> Endpoints | None:
        first = self.lines[0] if self.lines else None
        return first.endpoints if first and first.kind == "endpoints" else None

    def malformed(self) -> list[Line]:
        return [line for line in self.lines if line.kind == "malformed"]

    def of(self, kind: str, *, outcome: str | None = None, stage: str | None = None,
           attempt: str | None = None) -> list[Line]:
        return [
            line
            for line in self.lines
            if line.kind == kind
            and (outcome is None or line.outcome == outcome)
            and (stage is None or line.stage == stage)
            and (attempt is None or line.attempt == attempt)
        ]

    def entry(self) -> list[Line]:
        """Entry-protocol lines, excluding gameplay rejections reported as entry lines."""
        return [line for line in self.of("entry") if line.stage != "gameplay"]

    def zone(self, *outcomes: str) -> list[Line]:
        return [l for l in self.of("zone") if not outcomes or l.outcome in outcomes]

    def rejections(self) -> list[Line]:
        """``entry attempt=N stage=gameplay outcome=rejected <reason>`` lines."""
        return self.of("entry", stage="gameplay")

    def gameplay(self, *outcomes: str) -> list[Line]:
        return [l for l in self.of("gameplay") if not outcomes or l.outcome in outcomes]

    def persistence(self, stage: str | None = None, outcome: str | None = None) -> list[Line]:
        return self.of("persistence", stage=stage, outcome=outcome)
