"""Loopback packet observer for the headless Qeynos2 journey.

Ported from the historical ``capture.py`` used by the 2026-11-25 camp
recovery run.

The observer runs inside the disposable container's private network namespace.
It opens one ``AF_PACKET``/``SOCK_RAW`` socket for IPv4 bound to ``lo`` and keeps
only packets whose ``sll_pkttype`` is ``PACKET_HOST`` (0). On loopback every
datagram is seen once as outgoing and once as host-received; keeping only the
received copy avoids duplicates. (The first movement run kept only
``PACKET_OUTGOING`` while registered for IPv4 and saw nothing; the self check
exists to catch that class of bug.)

Selected rows (everything else is discarded and never retained):

Server-to-client reliable packets from ``zone_port`` whose UDP payload starts
with ``00 09``, then a big-endian u16 sequence, then a little-endian u16
opcode, then the application payload:

* ``0x7dfc`` position update, payload exactly 24 bytes::

    {"direction": "server_to_client", "sequence": int, "opcode": "0x7dfc",
     "payload_bytes": 24, "entity": u16le(payload[0:2]),
     "position": [x, y, z], "payload_hex": str}

  with ``w = struct.unpack_from('<5I', payload, 4)`` and
  ``signed(v) = (v - (1 << 19) if v & (1 << 18) else v) / 8``:
  ``x = signed(w[2] & 0x7ffff)``, ``y = signed((w[0] >> 12) & 0x7ffff)``,
  ``z = signed((w[3] >> 10) & 0x7ffff)``.

* ``0x58e2`` target command, payload exactly 4 bytes::

    {"direction", "sequence", "opcode": "0x58e2", "entity": u32le, "payload_hex"}

* ``0x6f15`` melee damage, payload exactly 30 bytes::

    {"direction", "sequence", "opcode": "0x6f15", "target": u16le[0:2],
     "source": u16le[2:4], "type": payload[4], "spell": u32le[5:9],
     "damage": i32le[9:13], "payload_hex"}

* ``0x37b1`` mob health, payload exactly 3 bytes::

    {"direction", "sequence", "opcode": "0x37b1", "entity": u16le[0:2],
     "percent": payload[2], "payload_hex"}

* ``0x5089`` self spawn, payload exactly 430 bytes, starting with
  ``character + b"\\0"`` and with ``u32le(payload[len(character)+1:+4]) == 1``
  (the historical decoder hard-coded offset 9 for ``Clientab``)::

    {"direction", "sequence", "opcode": "0x5089", "entity": 1,
     "name": character, "position": [x, y, z], "heading": (w[2] >> 19) & 0xfff,
     "position_words_hex": payload[347:367].hex(), "payload_bytes": 430,
     "payload_hex"}

  with ``w = struct.unpack_from('<5I', payload, 347)`` and the same position
  decoding as ``0x7dfc``.

* ``0x7280`` delete spawn, payload exactly 5 bytes ending in ``00 00 01``::

    {"direction", "sequence", "opcode": "0x7280", "entity": u16le[0:2],
     "payload_hex"}

* ``0x6097`` new NPC spawn, with a NUL-terminated printable ASCII name of
  1..64 bytes and exactly 266 bytes after the name (including its NUL)::

    {"direction", "sequence", "opcode": "0x6097", "entity": u32le,
     "name": str, "npc": True, "hp_percent": int, "position": [x, y, z],
     "heading": int, "payload_bytes": int, "payload_hex"}

  Position and heading use the same decoding as ``0x5089``.

Client-to-server packets to ``zone_port`` whose UDP payload is exactly 4 bytes
starting with ``00 15`` (session ACK)::

    {"direction": "client_to_server", "ACK": u16be(payload[2:4])}

Every retained row additionally gets ``monotonic`` (``time.monotonic()`` at
capture), ``src_port``, ``dst_port`` and ``packet_type``.
"""

from __future__ import annotations

from copy import deepcopy
import socket
import struct
import threading
import time

OPCODE_POSITION = 0x7DFC
OPCODE_TARGET = 0x58E2
OPCODE_DAMAGE = 0x6F15
OPCODE_HEALTH = 0x37B1
OPCODE_SELF_SPAWN = 0x5089
OPCODE_DELETE_SPAWN = 0x7280
OPCODE_NEW_SPAWN = 0x6097

DEFAULT_MAX_ROWS = 4096
_PACKET_HOST = 0


class ObserverError(RuntimeError):
    """The observer could not produce trustworthy evidence."""


def _signed_coordinate(value: int) -> float:
    value &= 0x7ffff
    return (value - (1 << 19) if value & (1 << 18) else value) / 8


def _position(words: tuple[int, ...]) -> list[float]:
    return [
        _signed_coordinate(words[2]),
        _signed_coordinate(words[0] >> 12),
        _signed_coordinate(words[3] >> 10),
    ]


def decode_datagram(
    udp_payload: bytes, src_port: int, dst_port: int, zone_port: int, character: str
) -> dict | None:
    """Return the selected row for one UDP payload, or None if not selected.

    Pure function: no clock, no socket. ``monotonic``/ports/``packet_type`` are
    added by the caller. Wrong lengths, other opcodes or ports, non-matching
    self spawns, malformed deletions and new spawns outside the NPC layout
    return None.
    """
    if dst_port == zone_port and len(udp_payload) == 4 and udp_payload[:2] == b"\x00\x15":
        return {
            "direction": "client_to_server",
            "ACK": int.from_bytes(udp_payload[2:4], "big"),
        }
    if src_port != zone_port or len(udp_payload) < 6 or udp_payload[:2] != b"\x00\x09":
        return None

    sequence, = struct.unpack_from("!H", udp_payload, 2)
    opcode, = struct.unpack_from("<H", udp_payload, 4)
    payload = udp_payload[6:]

    kind = opcode, len(payload)
    if kind == (OPCODE_POSITION, 24):
        entity, = struct.unpack_from("<H", payload)
        fields = {
            "entity": entity,
            "position": _position(struct.unpack_from("<5I", payload, 4)),
            "payload_bytes": 24,
        }
    elif kind == (OPCODE_TARGET, 4):
        entity, = struct.unpack("<I", payload)
        fields = {"entity": entity}
    elif kind == (OPCODE_DAMAGE, 30):
        target, source, damage_type, spell, damage = struct.unpack_from("<HHBIi", payload)
        fields = {
            "target": target,
            "source": source,
            "type": damage_type,
            "spell": spell,
            "damage": damage,
        }
    elif kind == (OPCODE_HEALTH, 3):
        entity, percent = struct.unpack("<HB", payload)
        fields = {"entity": entity, "percent": percent}
    elif kind == (OPCODE_SELF_SPAWN, 430):
        name = character.encode("utf-8") + b"\x00"
        if not payload.startswith(name + struct.pack("<I", 1)):
            return None
        words = struct.unpack_from("<5I", payload, 347)
        fields = {
            "entity": 1,
            "name": character,
            "position": _position(words),
            "heading": (words[2] >> 19) & 0xfff,
            "position_words_hex": payload[347:367].hex(),
            "payload_bytes": 430,
        }
    elif kind == (OPCODE_DELETE_SPAWN, 5):
        if payload[2:] != b"\x00\x00\x01":
            return None
        entity, = struct.unpack_from("<H", payload)
        fields = {"entity": entity}
    elif opcode == OPCODE_NEW_SPAWN:
        name_length = payload.find(b"\x00", 0, 65)
        # wire.rs at 75e8ffd, lines 54–57 and 152–188, defines offsets from the name.
        if name_length < 1 or len(payload) != name_length + 266:
            return None
        name = payload[:name_length]
        npc = payload[name_length + 10] == 1
        if not npc or any(byte < 0x20 or byte > 0x7e for byte in name):
            return None
        entity, = struct.unpack_from("<I", payload, name_length + 1)
        words = struct.unpack_from("<5I", payload, name_length + 183)
        fields = {
            "entity": entity,
            "name": name.decode("ascii"),
            "npc": npc,
            "hp_percent": payload[name_length + 29],
            "position": _position(words),
            "heading": (words[2] >> 19) & 0xfff,
            "payload_bytes": len(payload),
        }
    else:
        return None

    return {
        "direction": "server_to_client",
        "sequence": sequence,
        "opcode": hex(opcode),
        "payload_hex": payload.hex(),
        **fields,
    }


def decode_ipv4_udp(frame: bytes) -> tuple[int, int, bytes] | None:
    """Parse one Ethernet-framed loopback IPv4/UDP frame from ``AF_PACKET``.

    Returns ``(src_port, dst_port, udp_payload)`` when the frame is IPv4, UDP,
    from 127.0.0.1 to 127.0.0.1 and long enough for its IP header length and
    UDP length field; None otherwise. The UDP payload length comes from the UDP
    header, not from the frame length.
    """
    ethernet_length = 14
    if len(frame) < ethernet_length + 20 or frame[12:14] != b"\x08\x00":
        return None
    version_and_length = frame[ethernet_length]
    ip_length = (version_and_length & 0xf) * 4
    if version_and_length >> 4 != 4 or ip_length < 20 or frame[23] != socket.IPPROTO_UDP:
        return None
    if frame[26:34] != b"\x7f\x00\x00\x01" * 2:
        return None

    udp_start = ethernet_length + ip_length
    if len(frame) < udp_start + 8:
        return None
    src_port, dst_port, udp_length = struct.unpack_from("!HHH", frame, udp_start)
    udp_end = udp_start + udp_length
    if udp_length < 8 or udp_end > len(frame):
        return None
    return src_port, dst_port, frame[udp_start + 8:udp_end]


class Observer:
    """Background capture of selected rows for one zone port.

    Construction opens and binds the socket and starts a daemon thread. On
    ``OSError`` it does not raise; it sets ``error`` to ``"<Type>:<message>"``
    and ``stop()`` reports it. If more than ``max_rows`` rows are selected the
    thread stops capturing and sets ``error`` (``"selected capture budget"``).
    Any other exception in the thread sets ``error`` to its ``repr``.
    """

    def __init__(self, zone_port: int, character: str, max_rows: int = DEFAULT_MAX_ROWS):
        self._zone_port = zone_port
        self._character = character
        self._max_rows = max_rows
        self._rows: list[dict] = []
        self._error: str | None = None
        self._lock = threading.Lock()
        self._done = threading.Event()
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None

        try:
            self._socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
            self._socket.bind(("lo", 0))
            self._socket.settimeout(0.05)
            thread = threading.Thread(target=self._capture, args=(self._socket,), daemon=True)
            thread.start()
            self._thread = thread
        except OSError as exc:
            with self._lock:
                self._error = f"{type(exc).__name__}:{exc}"
                self._close_socket()

    def _close_socket(self) -> None:
        """Close the capture socket while holding the state lock."""
        if self._socket is None:
            return
        try:
            self._socket.close()
        except OSError as exc:
            if self._error is None:
                self._error = repr(exc)
        finally:
            self._socket = None

    def _capture(self, capture_socket: socket.socket) -> None:
        try:
            while not self._done.is_set():
                try:
                    frame, address = capture_socket.recvfrom(65536)
                except socket.timeout:
                    continue
                if address[2] != _PACKET_HOST:
                    continue
                datagram = decode_ipv4_udp(frame)
                if datagram is None:
                    continue
                src_port, dst_port, payload = datagram
                row = decode_datagram(payload, src_port, dst_port, self._zone_port, self._character)
                if row is None:
                    continue
                row.update(
                    monotonic=time.monotonic(),
                    src_port=src_port,
                    dst_port=dst_port,
                    packet_type=address[2],
                )
                with self._lock:
                    if self._done.is_set():
                        return
                    if len(self._rows) >= self._max_rows:
                        self._error = "selected capture budget"
                        return
                    self._rows.append(row)
        except BaseException as exc:
            with self._lock:
                if self._error is None:
                    self._error = repr(exc)

    @property
    def rows(self) -> list[dict]:
        """A snapshot copy of rows captured so far."""
        with self._lock:
            return deepcopy(self._rows)

    @property
    def error(self) -> str | None:
        with self._lock:
            return self._error

    def stop(self) -> dict:
        """Stop capture (idempotent) and return the observation::

            {"selected_zone_port": int, "error": str | None, "rows": [...],
             "scope": str}

        If the thread does not stop within 1 second, ``error`` becomes
        ``"capture thread not stopped"``. The socket is always closed.
        """
        self._done.set()
        try:
            if self._thread is not None:
                self._thread.join(timeout=1)
                if self._thread.is_alive():
                    with self._lock:
                        self._error = "capture thread not stopped"
        finally:
            with self._lock:
                self._close_socket()
        with self._lock:
            return {
                "selected_zone_port": self._zone_port,
                "error": self._error,
                "rows": deepcopy(self._rows),
                "scope": "Selected zone reliable replies and peer session ACKs only",
            }


def correlate(observation: dict) -> list[dict]:
    """Pair each server-to-client row with the first later peer ACK covering it.

    Raises ``ObserverError`` if ``observation["error"]`` is set, or if any
    server-to-client row has no client-to-server row with
    ``src_port == reply.dst_port``, ``dst_port == reply.src_port``,
    ``monotonic >= reply.monotonic`` and
    ``((ack.ACK - reply.sequence) & 0xffff) < 0x8000``.

    Returns, in reply order, ``{"reply": row, "ack": ack_row, "coverage":
    "exact" | "cumulative_high_water"}``.
    """
    if observation["error"]:
        raise ObserverError(f"observer error: {observation['error']}")

    rows = observation["rows"]
    acks = [row for row in rows if row["direction"] == "client_to_server"]
    correlations = []
    for reply in rows:
        if reply["direction"] != "server_to_client":
            continue
        ack = next((
            row for row in acks
            if row["src_port"] == reply["dst_port"]
            and row["dst_port"] == reply["src_port"]
            and row["monotonic"] >= reply["monotonic"]
            and ((row["ACK"] - reply["sequence"]) & 0xffff) < 0x8000
        ), None)
        if ack is None:
            raise ObserverError(f"no matching peer cumulative ACK for reply {reply['sequence']}")
        correlations.append({
            "reply": reply,
            "ack": ack,
            "coverage": "exact" if ack["ACK"] == reply["sequence"] else "cumulative_high_water",
        })
    return correlations


def self_check(character: str) -> dict:
    """Known-traffic control run before the journey starts.

    Binds two loopback UDP sockets, starts an ``Observer`` on the "server"
    port, sends two ``0x7dfc`` datagrams followed by ``0x58e2``, ``0x6f15``,
    ``0x37b1``, ``0x5089``, ``0x7280`` and ``0x6097`` with sequences 5..12,
    confirms each was received by the "client" socket, sends one ACK for 12
    back, waits briefly, stops the observer and correlates. It requires exactly
    eight correlated replies in order, every ACK equal to 12, and decoded values
    equal to what was sent. Raises ``ObserverError`` on any mismatch, including
    an observer that captured nothing. Returns::

        {"status": "PASS", "scope": str, "observation": {...},
         "correlations": [...]}
    """
    x, y, z = -931.25, 1194, 3.125
    encoded_x, encoded_y, encoded_z = (int(value * 8) & 0x7ffff for value in (x, y, z))
    position_words = struct.pack("<5I", encoded_y << 12, 0, encoded_x, encoded_z << 10, 0)
    position_payload = struct.pack("<HH", 1, 0) + position_words
    position_fields = {"entity": 1, "position": [x, y, z], "payload_bytes": 24}
    name = character.encode("utf-8") + b"\x00"
    spawn = bytearray(430)
    if len(name) + 4 > 347:
        raise ObserverError("character name overlaps self-spawn position")
    spawn[:len(name)] = name
    struct.pack_into("<I", spawn, len(name), 1)
    spawn[347:367] = position_words

    rat_x = -935
    rat_words = struct.pack("<5I", encoded_y << 12, 0, (rat_x * 8) & 0x7ffff, encoded_z << 10, 0)
    # wire.rs at 75e8ffd, lines 152–188, with the rat's appearance from content.rs.
    rat_spawn = (
        b"a_large_rat\x00"
        + struct.pack("<IBfBI", 2, 1, 5.0, 1, 2)  # entity, level, radius, NPC, gender
        + bytes(9)
        + struct.pack("<BIB", 1, 21, 100)  # property count, body type, HP
        + bytes(22)
        + struct.pack("<fBffIBIII", 7.0, 0, 0.46, 0.7, 36, 0, 0, 0xffffffff, 0)
        + bytes([1, 0, 100, 0, 0, 0])  # class, PvP, standing, light, gravity, surname
        + bytes(27) + b"\xff" * 8 + bytes(60)
        + rat_words
        + bytes(9) + b"0000000000000000\x00" + bytes(37)
    )

    replies = [
        (OPCODE_POSITION, position_payload, position_fields),
        (OPCODE_POSITION, position_payload, position_fields),
        (OPCODE_TARGET, struct.pack("<I", 2), {"entity": 2}),
        (OPCODE_DAMAGE, struct.pack("<HHBIi", 2, 1, 4, 65535, 2) + bytes(17),
         {"target": 2, "source": 1, "type": 4, "spell": 65535, "damage": 2}),
        (OPCODE_HEALTH, struct.pack("<HB", 2, 81), {"entity": 2, "percent": 81}),
        (OPCODE_SELF_SPAWN, bytes(spawn), {
            **position_fields, "name": character, "heading": 0,
            "position_words_hex": position_words.hex(), "payload_bytes": 430,
        }),
        (OPCODE_DELETE_SPAWN, b"\x02\x00\x00\x00\x01", {"entity": 2}),
        (OPCODE_NEW_SPAWN, rat_spawn, {
            "entity": 2, "name": "a_large_rat", "npc": True, "hp_percent": 100,
            "position": [rat_x, y, z], "heading": 0, "payload_bytes": len(rat_spawn),
        }),
    ]
    ack_payload = b"\x00\x15\x00\x0c"
    expected = []
    try:
        with (
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client,
        ):
            for endpoint in (server, client):
                endpoint.bind(("127.0.0.1", 0))
                endpoint.settimeout(1)
            server_address = server.getsockname()
            client_address = client.getsockname()
            observer = Observer(server_address[1], character)
            try:
                if observer.error:
                    raise ObserverError(observer.error)
                for sequence, (opcode, payload, fields) in enumerate(replies, start=5):
                    datagram = b"\x00\x09" + struct.pack("!H", sequence) + struct.pack("<H", opcode) + payload
                    server.sendto(datagram, client_address)
                    if client.recvfrom(1024) != (datagram, server_address):
                        raise ObserverError(f"self-check client received an unexpected reply for {sequence}")
                    expected.append({
                        "direction": "server_to_client", "sequence": sequence,
                        "opcode": hex(opcode), "payload_hex": payload.hex(),
                        "src_port": server_address[1], "dst_port": client_address[1],
                        **fields,
                    })
                client.sendto(ack_payload, server_address)
                if server.recvfrom(1024) != (ack_payload, client_address):
                    raise ObserverError("self-check server received an unexpected ACK")
                time.sleep(0.1)
            finally:
                observation = observer.stop()
    except OSError as exc:
        raise ObserverError(f"self-check UDP exchange failed: {exc}") from exc

    correlations = correlate(observation)
    if len(correlations) != len(replies):
        raise ObserverError(f"self-check expected eight captured replies, got {len(correlations)}")
    for pair, expected_reply in zip(correlations, expected):
        reply = pair["reply"]
        if any(reply.get(key) != value for key, value in expected_reply.items()):
            raise ObserverError(f"self-check decoded an unexpected reply for {expected_reply['sequence']}")
        if pair["ack"]["ACK"] != 12:
            raise ObserverError(f"self-check captured an unexpected ACK for {reply['sequence']}")
    return {
        "status": "PASS",
        "scope": "Known loopback UDP traffic only",
        "observation": observation,
        "correlations": correlations,
    }
