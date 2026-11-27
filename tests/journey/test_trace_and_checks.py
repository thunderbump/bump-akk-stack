"""Offline controls for the trace contract parser and the pure journey checks."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "qeynos2-journey"))

import checks  # noqa: E402
import fixture as F  # noqa: E402
from servertrace import Trace, parse_line  # noqa: E402

# Lines as printed by the server at 3939f187 (recovery-v2 run, credentials absent).
SERVER1 = """login=127.0.0.1:40001 world=127.0.0.1:40002 zone=127.0.0.1:40003 zone_id=2
persistence attempt=none stage=load outcome=seeded character=Clientab zone=2 x=-925 y=1194 z=3.125 heading=0
entry attempt=1 stage=login_accepted outcome=ok
entry attempt=1 stage=world_selected outcome=ok
entry attempt=1 stage=world_authenticated outcome=ok
entry attempt=1 stage=character_selected outcome=ok
entry attempt=1 stage=zone_endpoint outcome=ok
entry attempt=1 stage=zone_entered outcome=ok zone=2
entry attempt=1 stage=client_ready outcome=ok zone=2
gameplay attempt=1 outcome=moved sequence=8 x=-931.25 y=1194 z=3.125
gameplay attempt=1 outcome=moved sequence=9 x=-931.875 y=1194 z=3.125
gameplay attempt=1 outcome=stopped sequence=10 x=-931.875 y=1194 z=3.125
gameplay attempt=1 outcome=targeted entity_id=2 incarnation=1 spawn_id=10863 npc_type=2011
gameplay attempt=1 outcome=attack_armed source_entity=1 target_entity=2 incarnation=1
gameplay attempt=1 outcome=melee_hit source_entity=1 target_entity=2 incarnation=1 spawn_id=10863 npc_type=2011 damage=2 hp_before=11 hp_after=9
gameplay attempt=1 outcome=attack_off canceled=false
gameplay attempt=1 outcome=camp_started
gameplay attempt=1 outcome=camp_completed
persistence attempt=1 stage=save outcome=ok character=Clientab zone=2 x=-931.875 y=1194 z=3.125 heading=1536
entry transport_send_error kind=WouldBlock
"""


def samples(*rows):
    text = "".join(
        f"gameplay attempt=1 outcome={o} sequence={s} x={x} y={y} z={z}\n" for o, s, x, y, z in rows
    )
    return Trace(text).gameplay("moved", "stopped")


class TraceContract(unittest.TestCase):
    def test_recorded_lines_parse(self):
        trace = Trace(SERVER1)
        self.assertEqual(trace.malformed(), [])
        self.assertEqual(trace.endpoints().zone, 40003)
        self.assertEqual([l.stage for l in trace.entry()], list(F.ENTRY_STAGES))
        hit = trace.gameplay("melee_hit")[0]
        self.assertEqual(hit.fields["damage"], "2")
        save = trace.persistence("save", "ok")[0]
        self.assertEqual(save.xyz(), [-931.875, 1194.0, 3.125])
        self.assertEqual(trace.lines[-1].kind, "other")

    def test_partial_last_line_ignored(self):
        trace = Trace("login=127.0.0.1:1 world=127.0.0.1:2 zone=127.0.0.1:3 zone_id=2\nentry attempt=1 st")
        self.assertEqual(len(trace.lines), 1)

    def test_field_order_is_contract(self):
        line = parse_line("gameplay attempt=1 outcome=moved x=-931.25 sequence=8 y=1194 z=3.125")
        self.assertEqual(line.kind, "malformed")

    def test_missing_field_is_malformed(self):
        self.assertEqual(parse_line("gameplay attempt=1 outcome=attack_off").kind, "malformed")

    def test_non_numeric_is_malformed(self):
        self.assertEqual(parse_line("gameplay attempt=1 outcome=moved sequence=8 x=NaN y=1 z=1").kind, "malformed")

    def test_unknown_outcomes_fail_loudly(self):
        for raw in ("gameplay attempt=1 outcome=npc_revived entity_id=2",
                    "persistence attempt=1 stage=save outcome=maybe",
                    "zone outcome=npc_despawned entity_id=2 incarnation=1 spawn_id=10863 npc_type=2011",
                    "zone attempt=1 outcome=npc_respawned entity_id=2 incarnation=2 spawn_id=10863 npc_type=2011",
                    "entry attempt=1 stage=new_stage outcome=ok",
                    "entry attempt=1 stage=zone_entry outcome=paused",
                    "entry attempt=1 stage=zone_entry outcome=rejected Bad Reason",
                    "entry attempt=1 stage=gameplay outcome=rejected stale_target opcode=75d"):
            self.assertEqual(parse_line(raw).kind, "malformed", raw)

    def test_lifecycle_shapes(self):
        died = parse_line("gameplay attempt=1 outcome=npc_died entity_id=2 incarnation=1 spawn_id=10863 npc_type=2011")
        self.assertEqual((died.kind, died.fields["incarnation"]), ("gameplay", "1"))
        self.assertEqual(parse_line("gameplay attempt=1 outcome=npc_died incarnation=1 entity_id=2 "
                                    "spawn_id=10863 npc_type=2011").kind, "malformed")
        born = parse_line("zone outcome=npc_respawned entity_id=2 incarnation=2 spawn_id=10863 npc_type=2011")
        self.assertEqual((born.kind, born.outcome, born.attempt, born.fields["incarnation"]),
                         ("zone", "npc_respawned", None, "2"))
        self.assertEqual(len(Trace(born.raw + "\n").zone("npc_respawned")), 1)
        refused = parse_line("gameplay attempt=1 outcome=melee_refused source_entity=1 target_entity=2 "
                             "incarnation=1 reason=stale_target")
        self.assertEqual(refused.fields["reason"], "stale_target")

    def test_entry_reject_and_end_shapes(self):
        for raw in ("entry attempt=1 stage=gameplay outcome=rejected stale_target opcode=0x075d",
                    "entry attempt=none stage=zone_entry outcome=rejected no_zone_handoff",
                    "entry attempt=3 stage=world_login outcome=ended handoff_expired"):
            self.assertEqual(parse_line(raw).kind, "entry", raw)

    def test_entry_free_detail(self):
        line = parse_line("entry attempt=1 stage=world_login outcome=ended handoff_expired")
        self.assertEqual((line.kind, line.detail), ("entry", "handoff_expired"))
        self.assertEqual(parse_line("entry attempt=none stage=zone_entry outcome=ended handoff_expired").attempt, "none")

    def test_entry_ok_detail_is_contract(self):
        self.assertEqual(parse_line("entry attempt=1 stage=zone_entered outcome=ok zone=9").kind, "malformed")
        self.assertEqual(parse_line("entry attempt=1 stage=zone_entered outcome=ok").kind, "malformed")
        self.assertEqual(parse_line("entry attempt=1 stage=login_accepted outcome=ok x=1").kind, "malformed")

    def test_prefix_shape_changes_are_malformed(self):
        self.assertEqual(parse_line("gameplay  attempt=1 outcome=camp_started").kind, "malformed")
        self.assertEqual(parse_line("gameplay outcome=camp_started").kind, "malformed")
        self.assertEqual(parse_line("entry transport_send_error kind=WouldBlock").kind, "other")
        self.assertEqual(parse_line("entryway").kind, "other")

    def test_gameplay_rejections_are_separate_from_entry(self):
        trace = Trace(SERVER1 + "entry attempt=1 stage=gameplay outcome=rejected movement_too_fast\n")
        self.assertEqual([l.stage for l in trace.entry()], list(F.ENTRY_STAGES))
        self.assertEqual([l.detail for l in trace.rejections()], ["movement_too_fast"])

    def test_endpoint_line_exact(self):
        self.assertEqual(parse_line("login=127.0.0.1:1 world=127.0.0.1:2 zone=127.0.0.1:3 zone_id=2 ").kind, "other")
        self.assertEqual(parse_line("login=0.0.0.0:1 world=127.0.0.1:2 zone=127.0.0.1:3 zone_id=2").kind, "other")


class Movement(unittest.TestCase):
    seed = F.SEED_XYZ

    def test_old_first_sample_assertion_red(self):
        # The inherited check compared stop with the FIRST sample and failed a good run.
        moves, stop = checks.ordered_movement(
            samples(("moved", 8, -931.25, 1194, 3.125), ("moved", 9, -931.875, 1194, 3.125),
                    ("stopped", 10, -931.875, 1194, 3.125)), "1", self.seed)
        self.assertNotEqual(stop.xyz(), moves[0].xyz())
        self.assertEqual(stop.xyz(), moves[-1].xyz())

    def test_single_sample(self):
        checks.ordered_movement(samples(("moved", 8, -931.25, 1194, 3.125),
                                        ("stopped", 9, -931.25, 1194, 3.125)), "1", self.seed)

    def test_wraparound(self):
        checks.ordered_movement(samples(("moved", 65535, -931.25, 1194, 3.125),
                                        ("stopped", 0, -931.25, 1194, 3.125)), "1", self.seed)

    def test_rest_sample_at_new_position_moved_then_stopped(self):
        # 4be36c2 (PR 14): one rest sample yields moved then stopped, same sequence and position.
        moves, stop = checks.ordered_movement(samples(("moved", 0, -931.875, 1194, 3.125),
                                                      ("stopped", 0, -931.875, 1194, 3.125)), "1", self.seed)
        self.assertEqual(stop.xyz(), [-931.875, 1194.0, 3.125])
        checks.ordered_movement(samples(("moved", 0, -931.25, 1194, 3.125), ("moved", 1, -931.875, 1194, 3.125),
                                        ("stopped", 1, -931.875, 1194, 3.125)), "1", self.seed)

    def test_same_sequence_stop_elsewhere_rejected(self):
        self.bad(("moved", 0, -931.875, 1194, 3.125), ("stopped", 0, -931.25, 1194, 3.125))
        self.bad(("moved", 1, -931.25, 1194, 3.125), ("stopped", 0, -931.25, 1194, 3.125))
        self.bad(("moved", 0, -931.25, 1194, 3.125), ("moved", 0, -931.875, 1194, 3.125),
                 ("stopped", 1, -931.875, 1194, 3.125))  # repeated sequence between moves

    def bad(self, *rows, attempt="1"):
        with self.assertRaises(checks.CheckFailed):
            checks.ordered_movement(samples(*rows), attempt, self.seed)

    def test_rejections(self):
        self.bad(("moved", 8, -931.25, 1194, 3.125), ("stopped", 9, -930, 1194, 3.125))  # stop differs
        self.bad(("moved", 8, -920, 1194, 3.125), ("stopped", 9, -920, 1194, 3.125))  # eastward
        self.bad(("moved", 8, -931, 1194, 3.125), ("moved", 9, -930, 1194, 3.125),
                 ("stopped", 10, -930, 1194, 3.125))  # reversal
        self.bad(("moved", 8, -931, 1195, 3.125), ("stopped", 9, -931, 1195, 3.125))  # wrong y
        self.bad(("moved", 9, -931, 1194, 3.125), ("stopped", 8, -931, 1194, 3.125))  # sequence back
        self.bad(("stopped", 8, -925, 1194, 3.125))  # no move
        self.bad(("moved", 8, -931, 1194, 3.125))  # no stop
        self.bad(("moved", 8, -931, 1194, 3.125), ("stopped", 9, -931, 1194, 3.125),
                 ("moved", 10, -932, 1194, 3.125))  # sample after stop
        self.bad(("moved", 8, -931, 1194, 3.125), ("stopped", 9, -931, 1194, 3.125), attempt="2")


def reply(seq, entity, xyz, port=50000):
    return {"direction": "server_to_client", "opcode": "0x7dfc", "sequence": seq, "entity": entity,
            "position": list(xyz), "dst_port": port}


class Wire(unittest.TestCase):
    lines = samples(("moved", 8, -931.25, 1194, 3.125), ("stopped", 9, -931.25, 1194, 3.125))

    def test_all_positions_green(self):
        checks.wire_positions([reply(8, 1, (-931.25, 1194, 3.125)), reply(9, 1, (-931.25, 1194, 3.125))],
                              self.lines, 1)

    def test_missing_and_wrong(self):
        with self.assertRaises(checks.CheckFailed):
            checks.wire_positions([reply(8, 1, (-931.25, 1194, 3.125))], self.lines, 1)
        with self.assertRaises(checks.CheckFailed):
            checks.wire_positions([reply(8, 1, (-931.25, 1194, 3.125)), reply(9, 1, (-931.0, 1194, 3.125))],
                                  self.lines, 1)
        with self.assertRaises(checks.CheckFailed):
            checks.wire_positions([reply(8, 1, (-931.25, 1194, 3.125)), reply(9, 2, (-931.25, 1194, 3.125))],
                                  self.lines, 1)

    def test_rest_pair_has_one_reply(self):
        pair = samples(("moved", 0, -931.875, 1194, 3.125), ("stopped", 0, -931.875, 1194, 3.125))
        checks.wire_positions([reply(8, 1, (-931.875, 1194, 3.125))], pair, 1)
        with self.assertRaises(checks.CheckFailed):
            checks.wire_positions([reply(8, 1, (-931.875, 1194, 3.125)), reply(9, 1, (-931.875, 1194, 3.125))],
                                  pair, 1)

    def test_retransmission_deduplicated(self):
        rows = [reply(8, 1, (0, 0, 0)), reply(8, 1, (0, 0, 0)), reply(8, 1, (0, 0, 0), port=50001)]
        self.assertEqual(len(checks.unique_replies(rows, "0x7dfc")), 2)


def hit_lines(*rows, incarnation=1, attempt=1):
    text = "".join(f"gameplay attempt={attempt} outcome=melee_hit source_entity=1 target_entity=2 "
                   f"incarnation={incarnation} spawn_id=10863 npc_type=2011 damage={d} hp_before={b} hp_after={a}\n"
                   for d, b, a in rows)
    text += "gameplay attempt=1 outcome=npc_died entity_id=2 incarnation=1 spawn_id=10863 npc_type=2011\n"
    trace = Trace(text)
    return trace.gameplay("melee_hit"), trace.gameplay("npc_died")[0]


class Kill(unittest.TestCase):
    def chain(self, hits, died):
        return checks.hit_chain(hits, died, attempt="1", player=1, rat=2, incarnation=1, spawn_id=10863,
                                npc_type=2011, max_hp=11, damage_range=(1, 3), hit_range=(4, 11))

    def test_seeded_fresh_server_sequence(self):
        # Rust thread: a fresh server rolls 2, 2, 2, 3, 2 and the rat dies on the fifth hit.
        self.assertEqual(self.chain(*hit_lines((2, 11, 9), (2, 9, 7), (2, 7, 5), (3, 5, 2), (2, 2, 0))),
                         [2, 2, 2, 3, 2])

    def test_overkill_clamps_to_zero(self):
        self.chain(*hit_lines((3, 11, 8), (3, 8, 5), (3, 5, 2), (3, 2, 0)))

    def test_rejections(self):
        for rows in (((2, 11, 9), (2, 9, 7), (2, 7, 5)),  # alive at the end / too few
                     ((2, 11, 9), (2, 8, 6), (3, 6, 3), (3, 3, 0)),  # chain gap
                     ((4, 11, 7), (3, 7, 4), (3, 4, 1), (1, 1, 0)),  # damage over 3
                     ((2, 10, 8), (3, 8, 5), (3, 5, 2), (2, 2, 0)),  # does not start at 11
                     ((2, 11, 9), (2, 9, 7), (2, 7, 5), (3, 5, 1), (1, 1, 0))):  # wrong hp_after
            with self.assertRaises(checks.CheckFailed, msg=rows):
                self.chain(*hit_lines(*rows))
        with self.assertRaises(checks.CheckFailed):
            self.chain(*hit_lines((3, 11, 8), (3, 8, 5), (3, 5, 2), (2, 2, 0), incarnation=2))
        hits, died = hit_lines((3, 11, 8), (3, 8, 5), (3, 5, 2), (2, 2, 0))
        late = Trace("\n".join([died.raw] + [h.raw for h in hits]) + "\n")
        with self.assertRaises(checks.CheckFailed):  # hits after the death line
            self.chain(late.gameplay("melee_hit"), late.gameplay("npc_died")[0])


class Pose(unittest.TestCase):
    def test_round_trip(self):
        pose = checks.parse_pose(b"qeynos2-pose-v1 Clientab 2 -931.25 1194 3.125 1536\n")
        self.assertEqual(pose["xyz"], [-931.25, 1194.0, 3.125])
        line = parse_line("persistence attempt=1 stage=save outcome=ok character=Clientab zone=2 "
                          "x=-931.25 y=1194 z=3.125 heading=1536")
        self.assertTrue(checks.pose_line_matches(line, pose))
        pose["heading"] = 0
        self.assertFalse(checks.pose_line_matches(line, pose))

    def test_shape(self):
        with self.assertRaises(checks.CheckFailed):
            checks.parse_pose(b"qeynos2-pose-v1 Clientab 2 -931.25 1194 3.125\n")
        with self.assertRaises(checks.CheckFailed):
            checks.parse_pose(b"qeynos2-pose-v1 Clientab 2 -931.25 1194 3.125 1536")

    def test_hp_percent(self):
        self.assertEqual(checks.hp_percent(9, 11), 81)


if __name__ == "__main__":
    unittest.main()
