"""Wire evidence sources for the journey: the external observer or the client's packet API.

Both sources expose the same interface to guest.py:

* ``rows``: server-to-client reply rows in the observer's row shapes
  (``observer.py``), plus, for the observer, client ACK rows;
* ``error``: a reason the evidence cannot be trusted, or None;
* ``correlate(selected)``: pair each selected reply with delivery evidence,
  raising ``observer.ObserverError`` if any lacks it;
* ``snapshot()``: evidence to retain.

``ObserverSource`` is the independent mode. Delivery is a client ACK
datagram seen on the wire (``evidence: wire_observed``). It has a
known-traffic control (``observer.self_check``).

``ApiSource`` reads ``GET /v2/player/packets`` from the running headless
client (bump-eqoxide 9623e8a, docs/headless-player.md "Packet trace").
Delivery is the client's own report that its socket sent a covering ACK
(``acked_at_ms``/``ack_seq``), labelled ``evidence: client_reported``.
There is no known-traffic control in this mode. Rows exist only while the
client process runs, so a session's trace must be read before the client
exits (before camp for session 1). Any page with ``gap: true`` makes the
source untrustworthy. Retransmits never add rows (client claim), and the
journey still dedups by reliable sequence.
"""

from __future__ import annotations

import observer as obs

# API opcode names to the observer's opcode labels.
API_OPCODES = {
    "OP_CLIENT_UPDATE": "0x7dfc",
    "OP_TARGET_COMMAND": "0x58e2",
    "OP_DAMAGE": "0x6f15",
    "OP_MOB_HEALTH": "0x37b1",
    "OP_ZONE_ENTRY": "0x5089",
    "OP_DELETE_SPAWN": "0x7280",
    "OP_NEW_SPAWN": "0x6097",
}
API_SESSION_PORT = 0  # API rows carry no ports: one zone stream per client session
PAGE_LIMIT = 2000


def convert_api_row(row: dict, character: str) -> dict | None:
    """One API packet-trace row -> an observer-shaped server reply row, or None.

    Only inbound reliable rows of the journey's opcodes are kept. Zone entry
    keeps only the character's own spawn (the observer's 0x5089 selection);
    new spawns keep only NPCs (npc == 1), as the observer's 0x6097 decoder.
    """
    label = API_OPCODES.get(row.get("opcode_name"))
    if label is None or row.get("dir") != "in" or not row.get("reliable") or row.get("wire_seq") is None:
        return None
    f = row.get("fields") or {}
    base = {
        "direction": "server_to_client",
        "sequence": int(row["wire_seq"]),
        "opcode": label,
        "src_port": API_SESSION_PORT,
        "dst_port": API_SESSION_PORT,
        "monotonic": row["at_ms"] / 1000.0,
        "api_n": row["n"],
        "acked_at_ms": row.get("acked_at_ms"),
        "ack_seq": row.get("ack_seq"),
        "ack_exact": row.get("ack_exact"),
        "evidence": "client_reported",
    }
    try:
        if label == "0x7dfc":
            extra = {"entity": int(f["entity"]), "position": [float(v) for v in f["position"]]}
        elif label == "0x58e2":
            extra = {"entity": int(f["target_id"])}
        elif label == "0x6f15":
            extra = {k: int(f[k]) for k in ("target", "source", "type", "spell", "damage")}
        elif label == "0x37b1":
            extra = {"entity": int(f["entity"]), "percent": int(f["percent"])}
        elif label == "0x5089":
            if f.get("name") != character:
                return None
            extra = {"entity": int(f["entity"]), "name": f["name"],
                     "position": [float(v) for v in f["position"]], "heading": int(f["heading"])}
        elif label == "0x7280":
            extra = {"entity": int(f["entity"])}
        else:  # 0x6097
            if f.get("npc") != 1:
                return None
            extra = {"entity": int(f["entity"]), "name": f["name"], "npc": True,
                     "hp_percent": int(f["hp_percent"]),
                     "position": [float(v) for v in f["position"]], "heading": int(f["heading"])}
    except (KeyError, TypeError, ValueError) as error:
        raise obs.ObserverError(f"packet API row {row.get('n')} lacks {label} fields: {error!r}")
    return {**base, **extra}


def api_correlate(selected: list[dict]) -> list[dict]:
    """Pair each converted reply with the client's reported covering ACK."""
    proof = []
    for reply in selected:
        ack = reply.get("ack_seq")
        if reply.get("acked_at_ms") is None or ack is None:
            raise obs.ObserverError(f"client reports no ACK for {reply['opcode']} sequence {reply['sequence']}")
        if ((int(ack) - reply["sequence"]) & 0xFFFF) >= 0x8000:
            raise obs.ObserverError(f"client ACK {ack} does not cover sequence {reply['sequence']}")
        coverage = "exact" if int(ack) == reply["sequence"] else "cumulative_high_water"
        if reply.get("ack_exact") is not None and bool(reply["ack_exact"]) != (coverage == "exact"):
            raise obs.ObserverError(f"inconsistent ack_exact for sequence {reply['sequence']}")
        proof.append({"reply": reply, "ack": {"ACK": int(ack), "acked_at_ms": reply["acked_at_ms"]},
                      "coverage": coverage, "evidence": "client_reported"})
    return proof


class ObserverSource:
    mode = "observer"

    def __init__(self, zone_port: int, character: str):
        self.observer = obs.Observer(zone_port, character)

    @property
    def error(self):
        return self.observer.error

    @property
    def rows(self) -> list[dict]:
        return self.observer.rows

    def correlate(self, selected: list[dict]) -> list[dict]:
        acks = [r for r in self.observer.rows if r["direction"] == "client_to_server" and "ACK" in r]
        proof = obs.correlate({"error": None, "rows": selected + acks})
        for item in proof:
            item["evidence"] = "wire_observed"
        return proof

    def snapshot(self) -> dict:
        return self.observer.stop()


class ApiSource:
    """Packet-trace reader for one client process (one session)."""

    mode = "client-api"

    def __init__(self, api, character: str):
        self.api = api
        self.character = character
        self.raw: list[dict] = []
        self.after = 0
        self.gap = False
        self.counters = None
        self.session = None

    @property
    def error(self):
        return "packet trace reported gap:true (rows evicted)" if self.gap else None

    def refresh(self) -> None:
        while True:
            page = self.api.call(f"packets?after={self.after}&limit={PAGE_LIMIT}", timeout=5)
            self.gap = self.gap or bool(page.get("gap"))
            self.counters = page.get("counters")
            rows = page.get("packets") or []
            self.raw.extend(rows)
            nxt = int(page.get("next", self.after))
            if not rows or nxt <= self.after:
                return
            self.after = nxt
            if len(rows) < PAGE_LIMIT:
                return

    @property
    def rows(self) -> list[dict]:
        self.refresh()
        out = []
        for row in self.raw:
            converted = convert_api_row(row, self.character)
            if converted is not None:
                out.append(converted)
        return out

    def correlate(self, selected: list[dict]) -> list[dict]:
        return api_correlate(selected)

    def snapshot(self, refresh: bool = True) -> dict:
        refresh_error = None
        if refresh:
            try:
                self.refresh()
            except OSError as error:  # the client may already have exited
                refresh_error = repr(error)
        return {"evidence_mode": self.mode, "known_traffic_control": False, "gap": self.gap,
                "counters": self.counters, "rows_read": len(self.raw), "refresh_error": refresh_error,
                "rows": self.raw}
