"""Outbound/inbound datagram census for client pin moves (`run --census`).

Runs the ordinary journey unchanged (it subclasses guest.Journey and adds no
assertion) plus one passive AF_PACKET capture of every UDP datagram to or from
the current zone port(s), both directions, PACKET_HOST copies only, as the
observer. It writes output/evidence/transport-census.json with:

* counts by direction and transport opcode (first two bytes when the first is
  0x00, otherwise "app_unreliable");
* every server reliable/fragment sequence with capture times (retransmissions);
* every client reliable packet: sequence, opcode, first payload byte, length;
* every client unreliable packet: opcode and length;
* the host time each server gameplay/zone line first appeared (5 ms tail).

Compare two clients' census files at every pin move instead of trusting a
"no wire change" claim. Counts are compared for ACK, keepalive and session
datagrams; their contents are not recorded.
"""
import collections
import socket
import sys
import threading
import time

import guest
import observer

NAMES = {0x01: "session_request", 0x02: "session_response", 0x03: "combined", 0x05: "session_disconnect",
         0x06: "keepalive", 0x07: "session_stats_request", 0x08: "session_stats_response",
         0x09: "packet", 0x0d: "fragment", 0x11: "out_of_order_ack", 0x15: "ack", 0x19: "app_combined"}


class Census(guest.Journey):
    def census_start(self):
        if getattr(self, "census_thread", None):
            return
        self.zone_ports, self.census_stop = set(), threading.Event()
        self.counts = collections.Counter()
        self.reliable = collections.defaultdict(list)
        self.client_reliable = []
        self.client_unreliable = []
        self.lines_seen = {}
        raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        raw.bind(("lo", 0))
        raw.settimeout(0.05)

        def run():
            try:
                while not self.census_stop.is_set():
                    try:
                        frame, address = raw.recvfrom(65536)
                    except socket.timeout:
                        continue
                    if address[2] != 0:
                        continue
                    at = time.monotonic()
                    parsed = observer.decode_ipv4_udp(frame)
                    if not parsed:
                        continue
                    src, dst, data = parsed
                    if src in self.zone_ports:
                        direction, port = "server_to_client", src
                    elif dst in self.zone_ports:
                        direction, port = "client_to_server", dst
                    else:
                        continue
                    kind = NAMES.get(data[1], f"0x{data[1]:02x}") if len(data) >= 2 and data[0] == 0 else "app_unreliable"
                    self.counts[(direction, kind)] += 1
                    if direction == "client_to_server" and kind == "app_unreliable" and len(data) >= 2:
                        self.client_unreliable.append({"t": at, "opcode": f"0x{int.from_bytes(data[0:2], 'little'):04x}",
                                                       "payload_bytes": len(data) - 2})
                    if direction == "client_to_server" and kind == "packet" and len(data) >= 6:
                        self.client_reliable.append({"t": at, "sequence": int.from_bytes(data[2:4], "big"),
                                                     "opcode": f"0x{int.from_bytes(data[4:6], 'little'):04x}",
                                                     "first_payload_byte": data[6] if len(data) > 6 else None,
                                                     "payload_bytes": len(data) - 6})
                    if direction == "server_to_client" and kind in ("packet", "fragment") and len(data) >= 4:
                        self.reliable[(port, kind, int.from_bytes(data[2:4], "big"))].append(at)
            finally:
                raw.close()

        def tail():
            while not self.census_stop.is_set():
                at = time.monotonic()
                server = getattr(self, "server", None)
                if server:
                    for raw in server.text().split("\n")[:-1]:
                        if raw.startswith(("gameplay ", "zone ")) and (server.name, raw) not in self.lines_seen:
                            self.lines_seen[(server.name, raw)] = at
                time.sleep(0.005)

        self.census_thread = threading.Thread(target=run, daemon=True)
        self.census_thread.start()
        self.tail_thread = threading.Thread(target=tail, daemon=True)
        self.tail_thread.start()

    def m_server_start(self, ev):
        super().m_server_start(ev)
        self.census_start()
        self.zone_ports.add(self.endpoints.zone)

    def m_restart(self, ev):
        super().m_restart(ev)
        self.zone_ports.add(self.endpoints.zone)

    def cleanup(self):
        try:
            super().cleanup()
        finally:
            if getattr(self, "census_thread", None):
                self.census_stop.set()
                self.census_thread.join(timeout=2)
                self.tail_thread.join(timeout=2)
                retx = {f"{p}/{k}/{s}": [round(b - a, 3) for a, b in zip(t, t[1:])]
                        for (p, k, s), t in self.reliable.items() if len(t) > 1}
                self.save_evidence("transport-census", {
                    "zone_ports": sorted(self.zone_ports),
                    "counts": {f"{d} {k}": n for (d, k), n in sorted(self.counts.items())},
                    "server_reliable_sequences": len(self.reliable),
                    "server_retransmissions_spacing_s": retx,
                    "client_reliable": self.client_reliable,
                    "client_unreliable": self.client_unreliable,
                    "server_lines_first_seen": [{"server": k[0], "raw": k[1], "t": t}
                                                for k, t in sorted(self.lines_seen.items(), key=lambda kv: kv[1])]})


if __name__ == "__main__":
    guest.Journey = Census
    sys.exit(guest.main())
