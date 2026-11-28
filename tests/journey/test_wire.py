"""Offline controls for both wire evidence sources (central-c7sl).

A deliberately wrong server reply must fail the journey's wire checks whether
the evidence comes from the external observer's decode or from the client's
packet API, and a duplicated hit must not be counted twice.
"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "qeynos2-journey"))

import checks  # noqa: E402
import observer  # noqa: E402
import wire  # noqa: E402
from servertrace import Trace  # noqa: E402

ZONE = 7000
PEER = 40000
CHARACTER = "Clientab"


def api_row(n, name, fields, wire_seq, *, ack=None, direction="in", reliable=True, at_ms=1000):
    ack = wire_seq if ack is None else ack
    return {"n": n, "dir": direction, "opcode_name": name, "reliable": reliable, "wire_seq": wire_seq,
            "at_ms": at_ms + n, "fields": fields, "acked_at_ms": None if ack is False else at_ms + n,
            "ack_seq": None if ack is False else ack, "ack_exact": ack is not False and ack == wire_seq}


def observed(seq, opcode, body):
    """A server reply as the observer decodes it from real datagram bytes."""
    datagram = b"\0\x09" + seq.to_bytes(2, "big") + opcode.to_bytes(2, "little") + body
    row = observer.decode_datagram(datagram, ZONE, PEER, ZONE, CHARACTER)
    assert row is not None
    row.update(monotonic=float(seq), src_port=ZONE, dst_port=PEER, packet_type=0)
    return row


def damage_body(target, source, damage):
    return struct.pack("<HHBIi", target, source, 4, 0xFFFF, damage) + bytes(17)


def position_body(entity, x, y, z):
    def pack(v):
        return int(v * 8) & 0x7FFFF
    return struct.pack("<HH5I", entity, 0, pack(y) << 12, 0, pack(x), pack(z) << 10, 0)


HIT = Trace("gameplay attempt=1 outcome=melee_hit source_entity=1 target_entity=2 incarnation=1 "
            "spawn_id=10863 npc_type=2011 damage=2 hp_before=11 hp_after=9\n").gameplay("melee_hit")
SAMPLES = Trace("gameplay attempt=1 outcome=moved sequence=0 x=-931.25 y=1194 z=3.125\n"
                "gameplay attempt=1 outcome=stopped sequence=1 x=-931.25 y=1194 z=3.125\n").gameplay()


def proof(rows):
    return [{"reply": r} for r in rows]


class Convert(unittest.TestCase):
    def test_each_opcode(self):
        rows = [
            api_row(1, "OP_ZONE_ENTRY", {"entity": 1, "name": "Clientab", "position": [-925.0, 1194.0, 3.125],
                                         "heading": 0}, 0),
            api_row(2, "OP_ZONE_ENTRY", {"entity": 2, "name": "a_large_rat", "position": [-935.0, 1194.0, 9.125],
                                         "heading": 0}, 1),
            api_row(3, "OP_CLIENT_UPDATE", {"entity": 1, "position": [-931.25, 1194.0, 3.125], "heading": 1536}, 8),
            api_row(4, "OP_TARGET_COMMAND", {"target_id": 2}, 10),
            api_row(5, "OP_DAMAGE", {"target": 2, "source": 1, "type": 4, "spell": 65535, "damage": 2}, 11),
            api_row(6, "OP_MOB_HEALTH", {"entity": 2, "percent": 81}, 12),
            api_row(7, "OP_DELETE_SPAWN", {"entity": 2}, 20),
            api_row(8, "OP_NEW_SPAWN", {"entity": 2, "name": "a_large_rat", "npc": 1, "hp_percent": 100,
                                        "position": [-935.0, 1194.0, 9.125], "heading": 0}, 21),
            api_row(9, "OP_NEW_SPAWN", {"entity": 3, "name": "corpse", "npc": 3, "hp_percent": 0,
                                        "position": [0, 0, 0], "heading": 0}, 22),
            api_row(10, "OP_CLIENT_UPDATE", {"sequence": 0, "position": [0, 0, 0], "delta": [0, 0, 0],
                                             "animation": 0, "heading": 0}, None, direction="out", reliable=False),
            api_row(11, "OP_WEATHER", {}, 23),
        ]
        out = [wire.convert_api_row(r, CHARACTER) for r in rows]
        kept = [r for r in out if r]
        self.assertEqual([r["opcode"] for r in kept],
                         ["0x5089", "0x7dfc", "0x58e2", "0x6f15", "0x37b1", "0x7280", "0x6097"])
        self.assertEqual(kept[0]["position"], [-925.0, 1194.0, 3.125])
        self.assertEqual(kept[2]["entity"], 2)  # target echo target_id -> entity
        self.assertEqual((kept[3]["damage"], kept[4]["percent"]), (2, 81))
        self.assertTrue(kept[6]["npc"])
        self.assertTrue(all(r["evidence"] == "client_reported" and r["dst_port"] == wire.API_SESSION_PORT
                            for r in kept))

    def test_missing_fields_raise(self):
        with self.assertRaises(observer.ObserverError):
            wire.convert_api_row(api_row(1, "OP_DAMAGE", {"target": 2}, 11), CHARACTER)


class Correlate(unittest.TestCase):
    def convert(self, *rows):
        return [wire.convert_api_row(r, CHARACTER) for r in rows]

    def test_exact_cumulative_and_wrap(self):
        rows = self.convert(api_row(1, "OP_MOB_HEALTH", {"entity": 2, "percent": 81}, 12),
                            api_row(2, "OP_MOB_HEALTH", {"entity": 2, "percent": 63}, 13, ack=15),
                            api_row(3, "OP_MOB_HEALTH", {"entity": 2, "percent": 45}, 65535, ack=2))
        result = wire.api_correlate(rows)
        self.assertEqual([p["coverage"] for p in result], ["exact", "cumulative_high_water", "cumulative_high_water"])
        self.assertTrue(all(p["evidence"] == "client_reported" for p in result))

    def test_failures(self):
        for row in (api_row(1, "OP_MOB_HEALTH", {"entity": 2, "percent": 81}, 12, ack=False),
                    api_row(1, "OP_MOB_HEALTH", {"entity": 2, "percent": 81}, 12, ack=11)):
            with self.assertRaises(observer.ObserverError):
                wire.api_correlate(self.convert(row))
        bad = self.convert(api_row(1, "OP_MOB_HEALTH", {"entity": 2, "percent": 81}, 12))[0]
        bad["ack_exact"] = False
        with self.assertRaises(observer.ObserverError):
            wire.api_correlate([bad])


class FakeApi:
    def __init__(self, pages):
        self.pages = pages
        self.calls = []

    def call(self, path, timeout=2.0):
        self.calls.append(path)
        return self.pages.pop(0) if self.pages else {"packets": [], "next": 0, "gap": False, "counters": {}}


class Source(unittest.TestCase):
    def test_paging_and_gap(self):
        first = [api_row(n, "OP_MOB_HEALTH", {"entity": 2, "percent": 81}, n) for n in range(1, 2001)]
        api = FakeApi([{"packets": first, "next": 2000, "gap": False, "counters": {"resent": 0}},
                       {"packets": [api_row(2001, "OP_DELETE_SPAWN", {"entity": 2}, 2001)], "next": 2001,
                        "gap": True, "counters": {"resent": 1}}])
        source = wire.ApiSource(api, CHARACTER)
        rows = source.rows
        self.assertEqual(len(rows), 2001)
        self.assertEqual(api.calls[:2], ["packets?after=0&limit=2000", "packets?after=2000&limit=2000"])
        self.assertIsNotNone(source.error)
        snap = source.snapshot(refresh=False)
        self.assertEqual((snap["known_traffic_control"], snap["gap"]), (False, True))


class DuplicatedHit(unittest.TestCase):
    """The client claims retransmits never add rows; the journey still dedups."""

    def rows(self, *wire_seqs):
        return [wire.convert_api_row(api_row(i, name, fields, seq), CHARACTER)
                for i, seq in enumerate(wire_seqs)
                for name, fields in (("OP_DAMAGE", {"target": 2, "source": 1, "type": 4, "spell": 65535, "damage": 2}),)
                ] + [wire.convert_api_row(api_row(99, "OP_MOB_HEALTH", {"entity": 2, "percent": 81}, 40), CHARACTER)]

    def test_same_sequence_counts_once(self):
        checks.melee_wire(HIT, proof(self.rows(11, 11)), player=1, rat=2, max_hp=11)

    def test_double_count_under_two_sequences_fails(self):
        with self.assertRaises(checks.CheckFailed):
            checks.melee_wire(HIT, proof(self.rows(11, 12)), player=1, rat=2, max_hp=11)


class WrongServerReplyFailsBothModes(unittest.TestCase):
    """Each wrong reply is built once as observer-decoded bytes and once as an API row."""

    def both(self, observer_rows, api_rows):
        return {"observer": observer_rows,
                "client-api": [wire.convert_api_row(r, CHARACTER) for r in api_rows]}

    def test_correct_replies_pass_both(self):
        for mode, rows in self.both(
                [observed(11, 0x6F15, damage_body(2, 1, 2)), observed(12, 0x37B1, struct.pack("<HB", 2, 81))],
                [api_row(1, "OP_DAMAGE", {"target": 2, "source": 1, "type": 4, "spell": 65535, "damage": 2}, 11),
                 api_row(2, "OP_MOB_HEALTH", {"entity": 2, "percent": 81}, 12)]).items():
            checks.melee_wire(HIT, proof(rows), player=1, rat=2, max_hp=11)

    def test_wrong_damage(self):
        for mode, rows in self.both(
                [observed(11, 0x6F15, damage_body(2, 1, 3)), observed(12, 0x37B1, struct.pack("<HB", 2, 81))],
                [api_row(1, "OP_DAMAGE", {"target": 2, "source": 1, "type": 4, "spell": 65535, "damage": 3}, 11),
                 api_row(2, "OP_MOB_HEALTH", {"entity": 2, "percent": 81}, 12)]).items():
            with self.assertRaises(checks.CheckFailed, msg=mode):
                checks.melee_wire(HIT, proof(rows), player=1, rat=2, max_hp=11)

    def test_wrong_health(self):
        for mode, rows in self.both(
                [observed(11, 0x6F15, damage_body(2, 1, 2)), observed(12, 0x37B1, struct.pack("<HB", 2, 90))],
                [api_row(1, "OP_DAMAGE", {"target": 2, "source": 1, "type": 4, "spell": 65535, "damage": 2}, 11),
                 api_row(2, "OP_MOB_HEALTH", {"entity": 2, "percent": 90}, 12)]).items():
            with self.assertRaises(checks.CheckFailed, msg=mode):
                checks.melee_wire(HIT, proof(rows), player=1, rat=2, max_hp=11)

    def test_wrong_attribution(self):
        for mode, rows in self.both(
                [observed(11, 0x6F15, damage_body(3, 1, 2)), observed(12, 0x37B1, struct.pack("<HB", 2, 81))],
                [api_row(1, "OP_DAMAGE", {"target": 3, "source": 1, "type": 4, "spell": 65535, "damage": 2}, 11),
                 api_row(2, "OP_MOB_HEALTH", {"entity": 2, "percent": 81}, 12)]).items():
            with self.assertRaises(checks.CheckFailed, msg=mode):
                checks.melee_wire(HIT, proof(rows), player=1, rat=2, max_hp=11)

    def test_wrong_position_reply(self):
        for mode, rows in self.both(
                [observed(8, 0x7DFC, position_body(1, -931.25, 1194, 3.125)),
                 observed(9, 0x7DFC, position_body(1, -930.0, 1194, 3.125))],
                [api_row(1, "OP_CLIENT_UPDATE", {"entity": 1, "position": [-931.25, 1194.0, 3.125], "heading": 0}, 8),
                 api_row(2, "OP_CLIENT_UPDATE", {"entity": 1, "position": [-930.0, 1194.0, 3.125], "heading": 0}, 9)]
        ).items():
            with self.assertRaises(checks.CheckFailed, msg=mode):
                checks.wire_positions(checks.unique_replies(rows, "0x7dfc"), SAMPLES, 1)

    def test_missing_ack_fails_both(self):
        reply = observed(12, 0x37B1, struct.pack("<HB", 2, 81))
        with self.assertRaises(observer.ObserverError):  # observer: no client ACK datagram
            observer.correlate({"error": None, "rows": [reply]})
        with self.assertRaises(observer.ObserverError):  # client-api: client reports no ACK
            wire.api_correlate([wire.convert_api_row(
                api_row(1, "OP_MOB_HEALTH", {"entity": 2, "percent": 81}, 12, ack=False), CHARACTER)])


if __name__ == "__main__":
    unittest.main()
