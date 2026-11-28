"""Headless Qeynos2 journey, run inside the disposable container.

Invoked by the host as ``python3 -B -s -E /journey/guest.py ...``. The script
directory (the read-only harness copy) is the only import location used.
Writes ``guest-result.json`` and raw logs under ``--output``; never exits
without attempting to stop every process it started.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import secrets
import signal
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

import checks
import fixture as F
import observer as obs
import wire as W
from checks import CheckFailed, require
from servertrace import Trace

API_PORT = 18766


def utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Child:
    def __init__(self, name: str, argv: list[str], log: Path):
        self.name = name
        self.log = log
        self.handle = log.open("xb", buffering=0)
        self.started = time.monotonic()
        self.process = subprocess.Popen(
            argv, stdout=self.handle, stderr=subprocess.STDOUT, start_new_session=True
        )
        self.exit = None
        self.signal_sent = None

    def alive(self) -> bool:
        return self.process.poll() is None

    def text(self) -> str:
        return self.log.read_bytes().decode("utf-8", "replace")

    def stop(self, timeout: float) -> dict:
        was_live = self.alive()
        at = time.monotonic()
        if was_live:
            self.signal_sent = "SIGTERM"
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.signal_sent = "SIGKILL"
            os.killpg(self.process.pid, signal.SIGKILL)
            code = self.process.wait(timeout=5)
        try:
            os.killpg(self.process.pid, 0)
            group_absent = False
        except ProcessLookupError:
            group_absent = True
        except PermissionError:
            group_absent = False
        self.handle.close()
        return {
            "pid": self.process.pid,
            "exit": code,
            "signal_sent": self.signal_sent,
            "was_running": was_live,
            "stop_seconds": round(time.monotonic() - at, 3),
            "group_absent": group_absent,
        }


class Api:
    def __init__(self, token: str):
        self.token = token
        self.fence = None
        self.receipts = []

    def call(self, path: str, body=None, timeout=2.0):
        request = urllib.request.Request(
            f"http://127.0.0.1:{API_PORT}/v2/player/{path}",
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"},
            data=None if body is None else json.dumps(body).encode(),
            method="GET" if body is None else "PUT",
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)

    def state(self) -> dict:
        data = self.call("state")
        self.fence = data
        return data.get("state", data)

    def command(self, name: str, operation: dict) -> dict:
        require(self.fence is not None, "no state fence before command")
        payload = {
            "session": self.fence["session"],
            "zone_epoch": self.fence["zone_epoch"],
            "operation": operation,
        }
        at = time.monotonic()
        response = self.call("commands/" + name, payload)
        self.receipts.append({"id": name, "operation": operation, "monotonic": at, "response": response})
        return response

    def receipt(self, name: str) -> dict:
        return self.call("commands/" + name)


class Journey:
    def __init__(self, args):
        self.out = Path(args.output)
        self.logs = self.out / "logs"
        self.evidence_dir = self.out / "evidence"
        self.server_bin = args.server
        self.client_bin = args.client
        self.maps = Path(args.maps)
        self.variant = getattr(args, "variant", "routine")
        self.server_mode = F.VARIANTS[self.variant]["server_mode"]
        self.milestones = F.VARIANTS[self.variant]["milestones"]
        # Exact `entry ... stage=gameplay outcome=rejected <detail>` texts a
        # milestone currently expects; any other rejection still fails.
        self.allowed_rejections: set[str] = set()
        self.result = {
            "schema": "qeynos2-journey-guest/v1",
            "variant": getattr(args, "variant", "routine"),
            "evidence_mode": getattr(args, "evidence", "observer"),
            "known_traffic_control": getattr(args, "evidence", "observer") == "observer",
            "started_utc": utc(),
            "milestones": [],
            "first_failed_milestone": None,
            "failure": None,
            "processes": {},
            "trace_contract_violations": [],
        }
        self.children: list[Child] = []
        self.wire_source = None
        self.evidence_mode = getattr(args, "evidence", "observer")
        self.secrets: list[str] = []
        self.api = None
        self.facts = {}

    # ---- plumbing -------------------------------------------------------
    def scrub(self, text: str) -> str:
        for secret in self.secrets:
            text = text.replace(secret, "[REDACTED]")
        return text

    def write_json(self, path: Path, data) -> None:
        path.write_text(self.scrub(json.dumps(data, indent=2, default=str)))

    def checkpoint(self) -> None:
        """Progress for the host if the guest dies before writing its result."""
        rows = [{"name": m["name"], "status": m["status"]} for m in self.result["milestones"]]
        self.write_json(self.out / "progress.json", {"milestones": rows})

    def save_evidence(self, name: str, data) -> str:
        path = self.evidence_dir / (name + ".json")
        self.write_json(path, data)
        return str(path.relative_to(self.out))

    def wait(self, predicate, timeout: float, message: str, interval=0.05, watch=()):
        deadline = time.monotonic() + timeout
        while True:
            for child in watch:
                require(child.alive(), f"{child.name} exited (code {child.process.poll()}) while waiting: {message}")
                require(child.log.stat().st_size < F.LOG_LIMIT_BYTES, f"{child.name} log over budget")
            value = predicate()
            if value:
                return value
            require(time.monotonic() < deadline, f"timed out after {timeout}s: {message}")
            time.sleep(interval)

    def trace(self, server: Child) -> Trace:
        trace = Trace(server.text())
        bad = trace.malformed()
        if bad:
            self.result["trace_contract_violations"] = [l.as_dict() for l in bad]
            raise CheckFailed(f"server trace contract violation: {bad[0].raw!r} ({bad[0].problem})")
        rejected = [l for l in trace.rejections() if l.detail not in self.allowed_rejections]
        if rejected:
            self.result["server_rejections"] = [l.raw for l in rejected]
            raise CheckFailed(f"server rejected gameplay input: {rejected[0].raw!r}")
        return trace

    def wire(self, predicate, message: str) -> list[dict]:
        """Wait until the selected rows are all ACKed by the client peer."""
        source = self.wire_source
        require(source is not None, "no wire evidence source is running")

        def attempt():
            error = source.error
            if error:
                raise obs.ObserverError(f"{source.mode} evidence error: {error}")
            selected = predicate(source.rows)
            if not selected:
                return None
            try:
                return source.correlate(selected)
            except obs.ObserverError:
                return None
        return self.wait(attempt, F.WIRE_ACK_TIMEOUT, message)

    def run(self):
        steps = [getattr(self, "m_" + name) for name in self.milestones]
        try:
            for name, step in zip(self.milestones, steps):
                record = {"name": name, "status": "running", "evidence": {}}
                self.result["milestones"].append(record)
                self.checkpoint()
                at = time.monotonic()
                try:
                    outcome = step(record["evidence"])
                    record["status"] = outcome or "pass"
                except BaseException as error:
                    record["status"] = "fail"
                    self.result["first_failed_milestone"] = name
                    self.result["failure"] = {
                        "milestone": name,
                        "type": type(error).__name__,
                        "message": str(error),
                        "traceback": traceback.format_exc(),
                        "last_command_receipt": self.api.receipts[-1] if self.api and self.api.receipts else None,
                    }
                    if not isinstance(error, Exception):
                        raise
                    break
                finally:
                    record["seconds"] = round(time.monotonic() - at, 3)
        finally:
            try:
                self.cleanup()
            except Exception as error:  # never lose the result
                self.result["cleanup_error"] = repr(error)
                self.result["guest_processes_reaped"] = False
            done = {m["name"] for m in self.result["milestones"]}
            for name in self.milestones:
                if name not in done:
                    self.result["milestones"].append({"name": name, "status": "not_run"})
            self.result["finished_utc"] = utc()
            self.result["status"] = (
                "PASS" if all(m["status"] in F.PASSING for m in self.result["milestones"]) else "FAIL"
            )
            self.result["command_receipts"] = self.api.receipts if self.api else []
            self.write_json(self.out / "guest-result.json", self.result)
        return self.result

    def cleanup(self):
        if self.wire_source:
            try:
                self.save_evidence("wire-final", self.wire_source.snapshot())
            except Exception as error:  # evidence only
                self.result["wire_snapshot_error"] = repr(error)
            self.wire_source = None
        for child in reversed(self.children):
            if child.exit is None:
                try:
                    child.exit = child.stop(F.CHILD_STOP_TIMEOUT)
                except Exception as error:  # keep going: other children and the result
                    child.exit = {"pid": child.process.pid, "error": repr(error), "group_absent": False}
            self.result["processes"][child.name] = child.exit
        self.result["guest_processes_reaped"] = all(
            c.exit and c.exit["group_absent"] for c in self.children
        )
        redactions = {}
        for path in sorted(self.logs.glob("*.log")) if self.logs.is_dir() else []:
            raw = path.read_bytes()
            count = 0
            for secret in self.secrets:
                count += raw.count(secret.encode())
                raw = raw.replace(secret.encode(), b"[REDACTED]")
            if count:
                path.write_bytes(raw)
            redactions[path.name] = count
        self.result["log_redactions"] = redactions

    # ---- helpers for journey steps --------------------------------------
    def start_server(self, name: str) -> tuple[Child, object]:
        server = Child(name, [self.server_bin, self.server_mode, str(self.credentials), str(self.state_dir)],
                       self.logs / f"{name}.log")
        self.children.append(server)

        def ready():
            trace = self.trace(server)
            return trace if trace.endpoints() and len(trace.lines) >= 2 else None

        trace = self.wait(ready, F.SERVER_START_TIMEOUT, f"{name} endpoint and load lines", watch=[server])
        return server, trace

    def start_client(self, name: str, endpoints) -> Child:
        self.profile["login"]["login_port"] = endpoints.login
        self.profile["login"]["world_port"] = endpoints.world
        self.profile_path.write_text(json.dumps(self.profile))
        self.profile_path.chmod(0o600)
        client = Child(name, [self.client_bin, "--profile", str(self.profile_path)], self.logs / f"{name}.log")
        self.children.append(client)
        return client

    def await_ready(self, server: Child, client: Child) -> dict:
        def ready():
            try:
                state = self.api.state()
            except (OSError, ValueError):
                return None
            require(state.get("phase") != "failed", f"headless phase failed: {state.get('failure') or state.get('error')}")
            return state if state.get("phase") == "ready" else None

        state = self.wait(ready, F.READY_TIMEOUT, "client Ready", interval=0.1, watch=[server, client])
        require(state["zone"]["id"] == F.ZONE_ID and state["zone"]["name"] == F.ZONE_NAME, f"zone {state['zone']}")
        require(state["geometry"]["digest"] == self.geometry_digest, f"geometry {state['geometry']['digest']}")
        require(state["geometry"]["region"]["status"] == "ready", "client region data not ready")
        return state

    def entry_stages(self, server: Child, evidence: dict) -> str:
        # Client Ready can precede the server's final entry line by a tick.
        def complete():
            trace = self.trace(server)
            return trace if trace.of("entry", stage="client_ready") else None

        trace = self.wait(complete, 2.0, "server entry stage client_ready", watch=[server])
        entries = trace.entry()
        evidence["server_entry"] = [l.raw for l in entries]
        require([l.stage for l in entries] == list(F.ENTRY_STAGES), f"entry stages {[l.stage for l in entries]}")
        require(len({l.attempt for l in entries}) == 1, "entry stages span attempts")
        require(all(l.outcome == "ok" for l in entries), "entry stage not ok")
        return entries[0].attempt

    def self_spawn(self, message: str) -> dict:
        def spawn(rows):
            return checks.unique_replies(rows, "0x5089")
        proof = self.wire(spawn, message)
        require(len(proof) == 1, f"{len(proof)} self spawns")
        return proof[0]

    # ---- milestones ------------------------------------------------------
    def m_observer_self_check(self, ev):
        self.logs.mkdir(mode=0o700)
        self.evidence_dir.mkdir(mode=0o700)
        if self.evidence_mode == "client-api":
            ev["evidence_mode"] = "client-api"
            ev["known_traffic_control"] = False
            ev["note"] = ("client-api mode takes wire evidence from the client's packet trace; "
                          "it has no known-traffic control (offline controls only)")
            return "not_applicable"
        result = obs.self_check(F.CHARACTER)
        ev["status"] = result["status"]
        ev["file"] = self.save_evidence("observer-self-check", result)

    def m_server_start(self, ev):
        user = "jrny" + secrets.token_hex(8)
        password = secrets.token_hex(24)
        token = secrets.token_hex(32)
        self.secrets = [user, password, token]
        private = Path("/tmp/journey")
        private.mkdir(mode=0o700)
        self.credentials = private / "credentials"
        self.credentials.write_text(user + "\n" + password + "\n")
        self.credentials.chmod(0o600)
        self.state_dir = self.out / "state"
        self.state_dir.mkdir(mode=0o700)
        map_bytes = (self.maps / "qeynos2.map").read_bytes()
        self.geometry_digest = "sha256:" + hashlib.sha256(map_bytes).hexdigest()
        self.profile_path = private / "client-profile.json"
        self.profile = {
            "login": {"login_host": "127.0.0.1", "login_port": 0, "world_port": 0,
                      "username": user, "password": password, "character_name": F.CHARACTER},
            "expected_world": {"name": F.WORLD_NAME, "host": F.WORLD_HOST},
            "api_port": API_PORT,
            "control_token": token,
            "maps_dir": str(self.maps),
        }
        self.api = Api(token)
        server, trace = self.start_server("server1")
        self.server = server
        endpoints = trace.endpoints()
        ev["endpoints"] = endpoints.raw
        require(endpoints.zone_id == F.ZONE_ID, f"zone_id {endpoints.zone_id}")
        load = trace.lines[1]
        ev["load"] = load.raw
        require(load.kind == "persistence" and load.stage == "load" and load.outcome == "seeded",
                "empty state directory did not report load seeded")
        require(load.fields["character"] == F.CHARACTER and int(load.fields["zone"]) == F.ZONE_ID
                and load.xyz() == list(F.SEED_XYZ) and int(load.fields["heading"]) == F.SEED_HEADING,
                f"seed pose {load.raw}")
        self.endpoints = endpoints
        self.start_observer()

    def start_observer(self):
        if self.evidence_mode == "observer":
            self.wire_source = W.ObserverSource(self.endpoints.zone, F.CHARACTER)
            require(self.wire_source.error is None, f"observer: {self.wire_source.error}")

    def start_client_evidence(self):
        if self.evidence_mode == "client-api":
            self.wire_source = W.ApiSource(self.api, F.CHARACTER)

    def m_entry(self, ev):
        self.client = self.start_client("client1", self.endpoints)
        self.start_client_evidence()
        state = self.await_ready(self.server, self.client)
        ev["client_ready"] = {k: state.get(k) for k in ("phase", "zone", "geometry", "self")}
        self.attempt = self.entry_stages(self.server, ev)
        ev["attempt"] = self.attempt
        self.player = state["self"]["id"]
        spawn = self.self_spawn("first self spawn ACKed")
        ev["self_spawn"] = spawn
        require(spawn["reply"]["position"] == list(F.SEED_XYZ), f"spawn {spawn['reply']['position']}")
        require(spawn["reply"]["heading"] == F.SEED_HEADING, "spawn heading")
        self.start_state = state

    def m_move(self, ev):
        require(self.start_state["self"]["position"][:2] == list(F.SEED_XYZ[:2]),
                f"client start {self.start_state['self']['position']}")
        self.api.command("journey-move-1", F.MOVE)
        moved_at = time.monotonic()
        seen_active = False

        # Never truncate the lease: wait for the client to start and then end
        # the movement on its own before the explicit stop.
        def expired():
            nonlocal seen_active
            active = self.api.state()["self"]["motion_active"]
            seen_active = seen_active or active
            lease_over = time.monotonic() - moved_at >= F.MOVE["duration_ms"] / 1000
            return lease_over and not active

        self.wait(expired, F.MOTION_EXPIRE_TIMEOUT + F.MOVE["duration_ms"] / 1000,
                  "client movement lease expiry", interval=0.02, watch=[self.server, self.client])
        ev["lease_seconds"] = round(time.monotonic() - moved_at, 3)
        ev["client_motion_observed_active"] = seen_active
        require(seen_active, "client never reported the movement active")
        trace = self.wait(lambda: (t := self.trace(self.server)).gameplay("moved") and t,
                          F.STOP_TIMEOUT, "server moved sample", watch=[self.server, self.client])
        ev["first_moved"] = trace.gameplay("moved")[0].raw
        # A client that reports its resting position itself can make the
        # server report stop before the explicit stop command.
        ev["stopped_before_stop_command"] = bool(self.trace(self.server).gameplay("stopped"))

    def m_stop(self, ev):
        self.api.command("journey-stop-1", {"kind": "stop"})
        stop_at = time.monotonic()
        self.wait(lambda: self.trace(self.server).gameplay("stopped"), F.STOP_TIMEOUT,
                  "server stopped sample", watch=[self.server, self.client])
        ev["stop_seconds"] = round(time.monotonic() - stop_at, 3)
        time.sleep(F.STOP_QUIET)
        trace = self.trace(self.server)
        lines = trace.gameplay("moved", "stopped")
        ev["server_samples"] = [l.raw for l in lines]
        moves, stop = checks.ordered_movement(lines, self.attempt, F.SEED_XYZ)
        self.stop_line = stop
        self.stop_samples = [l.raw for l in lines]
        player = self.player
        count = len(checks.distinct_samples(lines))

        def updates(rows):
            found = [r for r in checks.unique_replies(rows, "0x7dfc") if r["entity"] == player]
            return found if len(found) >= count else None

        proof = self.wire(updates, "movement and stop replies ACKed")
        checks.wire_positions([p["reply"] for p in proof], lines, player)
        ev["wire"] = proof
        state = self.api.state()
        ev["client_prediction"] = state["self"]
        require(not state["self"]["motion_active"], "client still moving after stop")
        self.stopped_state = state

    def m_target(self, ev):
        rats = [e for e in self.stopped_state["nearby"]["entities"]
                if e["name"].startswith(F.RAT_NAME_PREFIX) and e["npc"] and not e["dead"]]
        require(len(rats) == 1, f"{len(rats)} live rats in received roster")
        rat = rats[0]
        self.rat = rat["id"]
        ev["roster_target"] = rat
        self.api.command("journey-target-1", {"kind": "target", "entity_id": rat["id"]})
        line = self.wait(lambda: self.trace(self.server).gameplay("targeted"), F.TARGET_TIMEOUT,
                         "server targeted line", watch=[self.server, self.client])[0]
        ev["server"] = line.raw
        require(line.attempt == self.attempt and int(line.fields["entity_id"]) == rat["id"]
                and int(line.fields["incarnation"]) == F.RAT_INCARNATION
                and int(line.fields["spawn_id"]) == F.RAT_SPAWN_ID
                and int(line.fields["npc_type"]) == F.RAT_NPC_TYPE, f"target identity {line.raw}")
        rat_id = rat["id"]
        proof = self.wire(lambda rows: checks.unique_replies(rows, "0x58e2"), "target reply ACKed")
        require(all(p["reply"]["entity"] == rat_id for p in proof), "target reply for another entity")
        ev["wire"] = proof
        needle = f"server forced target to spawn {rat_id}"
        applied = self.wait(lambda: [l for l in self.client.text().splitlines() if needle in l],
                            F.TARGET_TIMEOUT, "client target application log")
        ev["client_application"] = applied

    def m_hit(self, ev):
        attack_at = time.monotonic()
        self.api.command("journey-attack-1", {"kind": "attack", "lease_ms": F.ATTACK_LEASE_MS})
        try:
            try:
                self.wait(lambda: self.trace(self.server).gameplay("melee_hit"), F.HIT_TIMEOUT,
                          "server melee_hit", interval=0.02, watch=[self.server, self.client])
            except CheckFailed:
                pass  # verdict below; attack_off is still sent
        finally:
            self.api.command("journey-attack-off-1", {"kind": "attack_off"})
        time.sleep(max(0.0, attack_at + F.ATTACK_OBSERVE - time.monotonic()))
        ev["observation_seconds"] = round(time.monotonic() - attack_at, 3)
        trace = self.trace(self.server)
        melee = trace.gameplay("attack_armed", "melee_hit", "melee_refused", "attack_off")
        ev["server"] = [l.raw for l in melee]
        hits = trace.gameplay("melee_hit")
        require(len(hits) == 1, f"{len(hits)} melee hits (refused: {[l.raw for l in trace.gameplay('melee_refused')]})")
        hit = hits[0]
        damage = int(hit.fields["damage"])
        before, after = int(hit.fields["hp_before"]), int(hit.fields["hp_after"])
        require(hit.attempt == self.attempt and int(hit.fields["source_entity"]) == self.player
                and int(hit.fields["target_entity"]) == self.rat
                and int(hit.fields["incarnation"]) == F.RAT_INCARNATION
                and int(hit.fields["spawn_id"]) == F.RAT_SPAWN_ID
                and int(hit.fields["npc_type"]) == F.RAT_NPC_TYPE, f"hit attribution {hit.raw}")
        low, high = F.DAMAGE_RANGE
        require(low <= damage <= high and before == F.RAT_MAX_HP and after == before - damage,
                f"hit arithmetic {hit.raw}")
        require([l for l in trace.gameplay("attack_off") if l.index > hit.index],
                "server logged no attack_off after the hit")
        state = self.api.state()
        require(not state["self"]["attack_on"], "client attack still on")
        def effects(rows):
            damage_rows = checks.unique_replies(rows, "0x6f15")
            health_rows = checks.unique_replies(rows, "0x37b1")
            return damage_rows + health_rows if damage_rows and health_rows else None

        proof = self.wire(effects, "damage and health replies ACKed")
        checks.melee_wire(hits, proof, player=self.player, rat=self.rat, max_hp=F.RAT_MAX_HP)
        ev["wire"] = proof
        needle = f"EQ: combat: {F.CHARACTER} hits "
        applied = self.wait(lambda: [l for l in self.client.text().splitlines()
                                     if needle in l and f"for {damage} damage" in l],
                            F.TARGET_TIMEOUT, "client combat log hit")
        ev["client_application"] = applied

    # ---- kill-respawn variant ---------------------------------------------
    def try_command(self, name: str, operation: dict) -> dict:
        """Send a command; return the client's answer, including an admission refusal."""
        try:
            return {"accepted_by_client": True, "response": self.api.command(name, operation)}
        except urllib.error.HTTPError as error:
            # Keep only structured, bounded fields; never arbitrary response text.
            out = {"accepted_by_client": False, "http_status": error.code}
            try:
                body = json.loads(error.read(65536))
                for key in ("reason", "journaled", "status"):
                    if isinstance(body.get(key), (str, bool, int)) and len(str(body[key])) <= 80:
                        out[key] = body[key]
            except (ValueError, AttributeError):
                pass
            return out

    def live_rat(self, state: dict):
        return [e for e in state["nearby"]["entities"]
                if e["id"] == self.rat and e["npc"] and not e["dead"]]

    def m_kill(self, ev):
        """Re-arm after the routine hit and keep the lease alive until the rat dies."""
        renewals = []
        attack_at = time.monotonic()
        deadline = attack_at + F.KILL_TIMEOUT

        def renew():
            answer = self.try_command(f"journey-attack-k{len(renewals) + 1}",
                                      {"kind": "attack", "lease_ms": F.KILL_LEASE_MS})
            renewals.append({"t": round(time.monotonic() - attack_at, 3), **answer})
            if not answer["accepted_by_client"]:
                raise CheckFailed(f"client refused an attack command while the rat lived: {answer}")

        # Re-arm, then renew only at fixed offsets after each observed hit, so a
        # renewal never races the next due swing (repeat 3.5 s, melee.rs:10).
        renew()
        seen_hits, due = 0, []
        while True:
            trace = self.trace(self.server)
            if trace.gameplay("npc_died"):
                self.died_seen_at = time.monotonic()
                break
            require(time.monotonic() < deadline, f"rat not dead {F.KILL_TIMEOUT}s after re-arm")
            require(self.server.alive() and self.client.alive(), "a process exited during the kill")
            hits = len(trace.gameplay("melee_hit"))
            if hits > seen_hits:
                seen_hits = hits
                now = time.monotonic()
                due = [now + offset for offset in F.RENEW_AFTER_HIT]
            if due and time.monotonic() >= due[0]:
                due.pop(0)
                renew()
            time.sleep(0.02)
        ev["kill_seconds_after_rearm"] = round(time.monotonic() - attack_at, 3)
        ev["attack_renewals"] = len(renewals)
        ev["attack_renewals_refused"] = [r for r in renewals if not r["accepted_by_client"]]
        trace = self.trace(self.server)
        died = trace.gameplay("npc_died")[0]
        hits = trace.gameplay("melee_hit")
        ev["server_hits"] = [l.raw for l in hits]
        ev["damages"] = checks.hit_chain(
            hits, died, attempt=self.attempt, player=self.player, rat=self.rat,
            incarnation=F.RAT_INCARNATION, spawn_id=F.RAT_SPAWN_ID, npc_type=F.RAT_NPC_TYPE,
            max_hp=F.RAT_MAX_HP, damage_range=F.DAMAGE_RANGE, hit_range=F.KILL_HITS)
        refused = [l for l in trace.gameplay("melee_refused") if l.index < died.index]
        require(not refused, f"swing refused before death: {[l.raw for l in refused]}")
        count = len(hits)

        def effects(rows):
            damage_rows = checks.unique_replies(rows, "0x6f15")
            health_rows = checks.unique_replies(rows, "0x37b1")
            if len(damage_rows) >= count and len(health_rows) >= count:
                return damage_rows + health_rows
            return None

        proof = self.wire(effects, f"{count} damage and health replies ACKed")
        damage_rows, health_rows = checks.melee_wire(hits, proof, player=self.player, rat=self.rat,
                                                     max_hp=F.RAT_MAX_HP)
        ev["wire_health_percents"] = [h["percent"] for h in health_rows]
        pattern = re.compile(rf"EQ: combat: {F.CHARACTER} hits (\S+) for (\d+) damage")

        def client_hits():
            found = [m.groups() for m in map(pattern.search, self.client.text().splitlines()) if m]
            return found if len(found) >= count else None

        applied = self.wait(client_hits, F.TARGET_TIMEOUT, "client combat log hits")
        expected = [(F.RAT_NAME_PREFIX, l.fields["damage"]) for l in hits]
        require([(name.startswith(F.RAT_NAME_PREFIX) and F.RAT_NAME_PREFIX, dmg) for name, dmg in applied]
                == expected, f"client combat log {applied} != trace {expected}")
        ev["client_hits"] = applied
        self.died = died

    def m_death(self, ev):
        trace = self.trace(self.server)
        deaths = trace.gameplay("npc_died")
        ev["server"] = [l.raw for l in deaths]
        require(len(deaths) == 1, f"{len(deaths)} npc_died lines")
        died = deaths[0]
        require(died.attempt == self.attempt and int(died.fields["entity_id"]) == self.rat
                and int(died.fields["incarnation"]) == F.RAT_INCARNATION
                and int(died.fields["spawn_id"]) == F.RAT_SPAWN_ID
                and int(died.fields["npc_type"]) == F.RAT_NPC_TYPE, f"death identity {died.raw}")
        rat = self.rat
        proof = self.wire(lambda rows: [r for r in checks.unique_replies(rows, "0x7280")], "delete spawn ACKed")
        require(len(proof) == 1 and proof[0]["reply"]["entity"] == rat, f"delete spawn replies {proof}")
        ev["wire_delete"] = proof
        self.delete_row = proof[0]["reply"]
        require(not checks.unique_replies(self.wire_source.rows, "0x6097"), "new spawn before respawn")
        def roster_without_rat():
            st = self.api.state()
            nearby = st["nearby"]
            if st.get("phase") != "ready" or not nearby.get("available") or nearby.get("truncated"):
                return None
            return None if any(e["id"] == rat for e in nearby["entities"]) else st

        gone = self.wait(roster_without_rat, F.ROSTER_TIMEOUT, "client roster drops the rat's entry")
        ev["client_target_after_death"] = gone["self"].get("target_id")

    def m_no_swing_after_death(self, ev):
        """No action resolves against the dead incarnation.

        At 75e8ffd the server's kill path clears every attacker's target and
        cancels its auto-attack silently (src/rof2/zone.rs:524-531), so no due
        swing reaches the dead incarnation and `melee_refused reason=stale_target`
        is unreachable from the client. The black-box check is therefore: while
        the client still holds auto-attack on for one full swing interval after
        the death, the server resolves no swing (no attack_armed, melee_hit or
        melee_refused). The server-side stale_target paths stay with the
        server's own tests.
        """
        died = self.died
        start = self.died_seen_at  # the server's death, not this milestone's start
        attack_on_samples = []
        swings = ("attack_armed", "melee_hit", "melee_refused")

        def check_after_death():
            trace = self.trace(self.server)
            require(not trace.zone("npc_respawned"), "respawned inside the no-swing window")
            lines = [l for l in trace.lines if l.index > died.index and l.kind == "gameplay"]
            bad = [l.raw for l in lines if l.outcome in swings]
            require(not bad, f"swing resolved after death: {bad}")
            return lines

        while time.monotonic() - start < F.STALE_OBSERVE:
            check_after_death()
            attack_on_samples.append((round(time.monotonic() - start, 3), self.api.state()["self"]["attack_on"]))
            require(self.server.alive() and self.client.alive(), "a process exited in the no-swing window")
            time.sleep(0.1)
        ev["server_after_death"] = [l.raw for l in check_after_death()]  # final snapshot is checked too
        ev["client_attack_on_samples"] = attack_on_samples[::5]
        held = [t for t, on in attack_on_samples if on and t >= F.REPEAT_DELAY]
        require(held, "client released auto-attack before one swing interval passed; the window proves nothing")
        ev["client_attack_on_through_s"] = max(held)
        # Observation: a target for the dead ID. Headless is expected to refuse it
        # locally (recorded, not a pass condition). If the client reports it sent,
        # the server must reject it. After the kill the peer's binding is gone
        # (front/zone.rs:437-439), so the wire ID resolves to nothing
        # (front/zone.rs:486-493) and the exact correct rejection is
        # `unpublished_target` (play.rs:159-161).
        expected = "unpublished_target opcode=0x075d"
        if time.monotonic() - start + F.STALE_TARGET_WAIT > F.FAST_RESPAWN - F.RESPAWN_MARGIN:
            ev["observation_dead_id_target"] = {"skipped": "too close to the respawn"}
            return
        self.allowed_rejections.add(expected)
        try:
            answer = self.try_command("journey-target-stale", {"kind": "target", "entity_id": self.rat})
            time.sleep(F.STALE_TARGET_WAIT)
            if answer["accepted_by_client"]:
                answer["final_receipt"] = self.api.receipt("journey-target-stale")
            trace = self.trace(self.server)
            rejected = [l for l in trace.rejections() if l.index > died.index]
            targeted = [l.raw for l in trace.gameplay("targeted") if l.index > died.index]
            require(not targeted, f"a target succeeded for the dead ID: {targeted}")
            sent = answer["accepted_by_client"] and answer["final_receipt"].get("status") != "refused"
            if sent:
                require([(l.detail, l.attempt) for l in rejected] == [(expected, self.attempt)],
                        f"client reports the dead-ID target sent; server answered {[l.raw for l in rejected]}")
            else:
                require(not rejected, f"client refused the dead-ID target; server logged {[l.raw for l in rejected]}")
            ev["observation_dead_id_target"] = {"client": answer, "client_sent": sent,
                                                "server_rejections": [l.raw for l in rejected]}
        finally:
            self.allowed_rejections.discard(expected)

    def m_respawn(self, ev):
        died = self.died
        swings = ("attack_armed", "melee_hit", "melee_refused")

        def respawned():
            lines = self.trace(self.server).zone("npc_respawned")
            return lines or None

        remaining = max(0.0, self.died_seen_at + F.RESPAWN_TIMEOUT - time.monotonic())
        lines = self.wait(respawned, remaining, "server npc_respawned", watch=[self.server, self.client])
        ev["server"] = [l.raw for l in lines]
        require(len(lines) == 1, f"{len(lines)} respawn lines")
        line = lines[0]
        incarnation = int(line.fields["incarnation"])
        require(line.index > died.index and int(line.fields["entity_id"]) == self.rat
                and incarnation > F.RAT_INCARNATION and int(line.fields["spawn_id"]) == F.RAT_SPAWN_ID
                and int(line.fields["npc_type"]) == F.RAT_NPC_TYPE, f"respawn identity {line.raw}")
        ev["incarnation"] = incarnation
        rat = self.rat
        proof = self.wire(lambda rows: checks.unique_replies(rows, "0x6097"), "new spawn ACKed")
        require(len(proof) == 1, f"{len(proof)} new spawn replies")
        spawn = proof[0]["reply"]
        require(spawn["entity"] == rat and spawn["npc"] and spawn["hp_percent"] == 100
                and spawn["name"].startswith(F.RAT_NAME_PREFIX), f"new spawn {spawn}")
        require(checks.forward(self.delete_row["sequence"], spawn["sequence"]), "new spawn before delete")
        gap = spawn["monotonic"] - self.delete_row["monotonic"]
        ev["respawn_seconds_on_wire"] = round(gap, 3)
        low, high = F.RESPAWN_DELAY_RANGE
        require(low <= gap <= high, f"respawn {gap:.1f}s after delete")
        ev["wire_new_spawn"] = {k: spawn[k] for k in ("sequence", "entity", "name", "hp_percent", "position")}
        self.wait(lambda: self.live_rat(self.api.state()), F.ROSTER_TIMEOUT, "client roster regains the rat")
        before = len([l for l in self.client.text().splitlines() if f"server forced target to spawn {rat}" in l])
        attack_on_at_retarget = self.api.state()["self"]["attack_on"]
        self.api.command("journey-target-respawned", {"kind": "target", "entity_id": rat})
        targeted = self.wait(lambda: [l for l in self.trace(self.server).gameplay("targeted")
                                      if int(l.fields["incarnation"]) == incarnation],
                             F.TARGET_TIMEOUT, "server targets the new incarnation", watch=[self.server, self.client])
        ev["server_target"] = targeted[0].raw
        require(len(targeted) == 1 and targeted[0].attempt == self.attempt
                and int(targeted[0].fields["entity_id"]) == rat, f"retarget {targeted[0].raw}")
        trace = self.trace(self.server)
        early = [l.raw for l in trace.lines if died.index < l.index < targeted[0].index
                 and l.kind == "gameplay" and l.outcome in swings + ("targeted",)]
        require(not early, f"swing or target after the death and before the re-target: {early}")
        after_spawn = spawn["sequence"]
        echo = self.wire(lambda rows: [r for r in checks.unique_replies(rows, "0x58e2")
                                       if checks.forward(after_spawn, r["sequence"])], "retarget echo ACKed")
        require(len(echo) == 1 and echo[0]["reply"]["entity"] == rat, f"retarget echo {echo}")
        self.wait(lambda: len([l for l in self.client.text().splitlines()
                               if f"server forced target to spawn {rat}" in l]) > before,
                  F.TARGET_TIMEOUT, "client applies the retarget")
        # Observation only: does the server arm a swing on the new incarnation
        # after a retarget with no fresh attack-on? The client's lease (at most
        # 5 s) ends before the 10 s respawn and it cannot renew without a live
        # target, so attack_on is normally false here.
        time.sleep(F.RETARGET_OBSERVE)
        trace = self.trace(self.server)
        after = [l.raw for l in trace.lines if l.index > targeted[0].index
                 and l.kind == "gameplay" and l.outcome in swings]
        ev["observation_retarget_without_attack_on"] = {
            "client_attack_on_at_retarget": attack_on_at_retarget,
            "observed_seconds": F.RETARGET_OBSERVE, "server_swing_lines": after}

    def m_camp(self, ev):
        camp_at = time.monotonic()
        if self.evidence_mode == "client-api":
            # The client's packet history ends with its process: read session 1 now.
            self.wire_source.refresh()
            require(not self.wire_source.gap, "packet trace reported gap:true before camp")
            ev["session1_trace_rows_before_camp"] = len(self.wire_source.raw)
        self.api.command("journey-camp-1", {"kind": "camp"})
        try:
            code = self.client.process.wait(timeout=F.CAMP_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise CheckFailed(f"client did not exit within {F.CAMP_TIMEOUT}s of camp")
        self.client.exit = self.client.stop(F.CHILD_STOP_TIMEOUT)
        ev["client_exit"] = {"exit": code, "seconds": round(time.monotonic() - camp_at, 3), "signal_sent": None}
        require(code == 0, f"client exited {code} after camp")
        require(self.server.alive(), "server exited during camp")
        trace = self.wait(lambda: (t := self.trace(self.server)).persistence("save") and t, 2.0,
                          "server save line", watch=[self.server])
        ev["server"] = [l.raw for l in trace.lines if l.kind == "persistence" or (l.outcome or "").startswith("camp")]
        camp = trace.gameplay("camp_started", "camp_completed", "camp_canceled", "camp_incomplete",
                              "camp_interrupted", "logout_without_camp")
        saves = trace.persistence("save")
        require([l.outcome for l in camp] == ["camp_started", "camp_completed"],
                f"camp sequence {[l.raw for l in camp]}")
        require(len(saves) == 1 and saves[0].outcome == "ok", f"save {[l.raw for l in saves]}")
        require(camp[0].index < camp[1].index < saves[0].index, "camp/save lines out of order")
        require(all(l.attempt == self.attempt for l in camp + saves), "camp/save on another attempt")
        # The movement record must be unchanged since stop (no late duplicate stop or move).
        samples = [l.raw for l in trace.gameplay("moved", "stopped")]
        require(samples == self.stop_samples, f"server samples changed after stop: {samples}")
        pose_file = self.state_dir / F.POSE_FILE
        raw = pose_file.read_bytes()
        pose = checks.parse_pose(raw)
        ev["saved_pose"] = {"raw_ascii": raw.decode(), "sha256": hashlib.sha256(raw).hexdigest(),
                            "mode": oct(pose_file.stat().st_mode & 0o777)}
        require(pose["format"] == F.POSE_FORMAT and pose["character"] == F.CHARACTER and pose["zone"] == F.ZONE_ID,
                "pose record identity")
        require(checks.pose_line_matches(saves[0], pose), "save line differs from pose file")
        require(pose["xyz"] == self.stop_line.xyz(), f"saved {pose['xyz']} != stop {self.stop_line.xyz()}")
        require(pose["xyz"] != list(F.SEED_XYZ), "saved pose equals seed")
        self.pose, self.pose_raw = pose, raw

    def m_restart(self, ev):
        snapshot = (self.wire_source.snapshot() if self.evidence_mode == "observer"
                    else self.wire_source.snapshot(refresh=False))
        ev["first_observation"] = self.save_evidence("wire-session1", snapshot)
        self.wire_source = None
        self.server.exit = self.server.stop(F.SERVER_STOP_TIMEOUT)
        ev["server1_exit"] = self.server.exit
        require(self.server.exit["exit"] in (0, -signal.SIGTERM), f"server1 exit {self.server.exit['exit']}")
        require(self.server.exit["group_absent"] and self.client.exit["group_absent"], "first processes remain")
        server, trace = self.start_server("server2")
        self.server = server
        endpoints = trace.endpoints()
        ev["endpoints"] = endpoints.raw
        load = trace.lines[1]
        ev["load"] = load.raw
        require(load.kind == "persistence" and load.stage == "load" and load.outcome == "ok", f"load {load.raw}")
        require(checks.pose_line_matches(load, self.pose), "loaded pose differs from saved pose")
        self.endpoints = endpoints
        self.start_observer()

    def m_relog(self, ev):
        self.client = self.start_client("client2", self.endpoints)
        self.start_client_evidence()
        state = self.await_ready(self.server, self.client)
        ev["client_ready"] = {k: state.get(k) for k in ("phase", "zone", "geometry", "self")}
        ev["attempt"] = self.entry_stages(self.server, ev)
        spawn = self.self_spawn("relog self spawn ACKed")
        ev["self_spawn"] = spawn
        require(spawn["reply"]["position"] == self.pose["xyz"] and spawn["reply"]["heading"] == self.pose["heading"],
                f"relog spawn {spawn['reply']['position']} heading {spawn['reply']['heading']}")
        x, y, z = self.pose["xyz"]
        require(state["self"]["position"] == [x, y, z - F.CLIENT_FEET_OFFSET],
                f"client feet {state['self']['position']}")
        require((self.state_dir / F.POSE_FILE).read_bytes() == self.pose_raw, "pose file changed after reload")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--maps", required=True)
    parser.add_argument("--variant", choices=sorted(F.VARIANTS), default="routine")
    parser.add_argument("--evidence", choices=("observer", "client-api"), default="observer")
    args = parser.parse_args(argv)
    os.umask(0o077)

    def terminate(signum, frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, terminate)
    result = Journey(args).run()
    print(json.dumps({"status": result["status"], "first_failed_milestone": result["first_failed_milestone"]}))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
