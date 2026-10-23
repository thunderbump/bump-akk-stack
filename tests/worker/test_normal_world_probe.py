"""Trusted observer/socket fakes only; no native candidate or VM execution."""
import itertools
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'validation/worker'))
import normal_world as normal


class RetainedSessions:
    """Model EQ's endpoint lookup and refusal of a different session challenge."""
    def __init__(self, ports, response='echo'):
        self.ports = iter(ports)
        self.response = response
        self.sessions = {}
        self.sockets = []
        self.active = 0

    def socket(self, *_):
        peer = self
        port = next(self.ports)

        class Stream:
            def __enter__(self):
                peer.active += 1
                assert peer.active == 1
                self.sent = []
                self.receives = 0
                peer.sockets.append(self)
                return self

            def __exit__(self, *_):
                peer.active -= 1

            def connect(self, endpoint):
                self.endpoint = ('127.0.0.1', port)

            def getsockname(self):
                return self.endpoint

            def settimeout(self, seconds):
                assert seconds == .25

            def send(self, data):
                self.sent.append(data)
                self.challenge = data[6:10]
                peer.sessions.setdefault(self.endpoint, self.challenge)

            def recv(self, _):
                self.receives += 1
                if peer.response == 'refused':
                    raise ConnectionRefusedError()
                if peer.response == 'drop' or peer.sessions[self.endpoint] != self.challenge:
                    raise TimeoutError()
                if peer.response == 'malformed':
                    return b'wrong'
                if peer.response == 'wrong-challenge':
                    return b'\x00\x02xxxx'
                return b'\x00\x02' + self.challenge

        return Stream()


class Probe(unittest.TestCase):
    def test_retained_session_ignores_new_challenge_on_reused_endpoint(self):
        peer = RetainedSessions([40000, 40000])
        with patch.object(normal.socket, 'socket', side_effect=peer.socket), \
                patch.object(normal.os, 'urandom', side_effect=[b'old!', b'new!']):
            self.assertTrue(normal.probe())
            # Separate one-off calls have no shared endpoint history. This
            # reproduces the old observer failure against a responsive peer.
            self.assertFalse(normal.probe())
        self.assertEqual(peer.active, 0)

    def test_observer_history_discards_reused_endpoint_before_transmitting(self):
        peer = RetainedSessions([40000, 40000, 40001])
        used = set()
        observed = {}
        with patch.object(normal.socket, 'socket', side_effect=peer.socket), \
                patch.object(normal.os, 'urandom', side_effect=[b'old!', b'new!']) as random:
            self.assertTrue(normal.probe(used_ports=used, diagnostics=observed))
            self.assertTrue(normal.probe(used_ports=used, diagnostics=observed))
        self.assertEqual(used, {40000, 40001})
        self.assertEqual([len(stream.sent) for stream in peer.sockets], [1, 0, 1])
        self.assertEqual([stream.receives for stream in peer.sockets], [1, 0, 1])
        self.assertEqual(random.call_count, 2)
        self.assertEqual(peer.sessions[('127.0.0.1', 40001)], b'new!')
        self.assertEqual(observed, dict(condition='responsive', source_port=40001,
                                       discarded_allocations=1))
        self.assertEqual(peer.active, 0)

    def test_transmitted_failure_is_not_retried_and_port_stays_reserved(self):
        for response, condition in [('drop', 'udp-timeout'), ('refused', 'udp-refused'),
                                    ('malformed', 'udp-malformed-reply'),
                                    ('wrong-challenge', 'udp-malformed-reply')]:
            with self.subTest(response=response):
                peer = RetainedSessions([40000, 40001], response)
                used = set()
                observed = {}
                with patch.object(normal.socket, 'socket', side_effect=peer.socket):
                    self.assertFalse(normal.probe(used_ports=used, diagnostics=observed))
                self.assertEqual(used, {40000})
                self.assertEqual(observed['condition'], condition)
                self.assertEqual(len(peer.sockets), 1)
                self.assertEqual(len(peer.sockets[0].sent), 1)
                self.assertEqual(peer.sockets[0].receives, 1)
                self.assertEqual(peer.active, 0)

    def test_allocation_and_history_caps_are_explicit_failures_without_packets(self):
        for used, allocations in [({40000}, normal.PROBE_ALLOCATION_ATTEMPTS),
                                  (set(range(normal.PROBE_PORT_LIMIT)), 0)]:
            with self.subTest(allocations=allocations):
                peer = RetainedSessions(itertools.repeat(40000))
                observed = {}
                before = set(used)
                with patch.object(normal.socket, 'socket', side_effect=peer.socket), \
                        self.assertRaisesRegex(RuntimeError, 'source port allocation exhausted'):
                    normal.probe(used_ports=used, diagnostics=observed)
                self.assertEqual(used, before)
                self.assertEqual(len(peer.sockets), allocations)
                self.assertTrue(all(not stream.sent for stream in peer.sockets))
                self.assertEqual(observed, dict(condition='udp-allocation-exhausted',
                    source_port=40000 if allocations else None, discarded_allocations=allocations))
                self.assertEqual(peer.active, 0)


if __name__ == '__main__':
    unittest.main()
