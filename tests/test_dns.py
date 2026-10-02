import struct
import unittest
from unittest import mock

from netcheck import build_dns_query, dns_query, parse_dns_a, read_interface_dns


def _response(txid: int, name: str, ip: bytes) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    q += struct.pack(">HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + ip
    return header + q + answer


class TestDns(unittest.TestCase):
    def test_build_query_header(self):
        packet = build_dns_query("example.com", 0x1234)
        self.assertEqual(packet[:2], b"\x12\x34")
        self.assertEqual(struct.unpack(">H", packet[4:6])[0], 1)  # QDCOUNT

    def test_parse_a_record(self):
        packet = _response(0x1234, "example.com", bytes([93, 184, 216, 34]))
        self.assertEqual(parse_dns_a(packet), ["93.184.216.34"])

    def test_parse_no_answer(self):
        header = struct.pack(">HHHHHH", 1, 0x8180, 0, 0, 0, 0)
        self.assertEqual(parse_dns_a(header), [])

    def test_truncated_response_returns_empty(self):
        self.assertEqual(parse_dns_a(b"\x00"), [])

    def test_malformed_question_count_does_not_raise(self):
        header = struct.pack(">HHHHHH", 1, 0x8180, 9, 0, 0, 0)
        self.assertEqual(parse_dns_a(header), [])

    def test_truncated_rdata_no_raise(self):
        header = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0)
        q = b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + b"\x5d\xb8"
        self.assertEqual(parse_dns_a(header + q + answer), [])

    def test_dns_query_binds_source(self):
        with mock.patch("netcheck.socket.socket") as sock_cls:
            sock = sock_cls.return_value
            sock.recvfrom.side_effect = OSError("no reply")
            ok, _ms, answers = dns_query("1.1.1.1", "example.com",
                                         source="192.168.1.50")
            self.assertFalse(ok)
            self.assertEqual(answers, [])
            sock.bind.assert_called_once_with(("192.168.1.50", 0))

    def test_dns_query_without_source_does_not_bind(self):
        with mock.patch("netcheck.socket.socket") as sock_cls:
            sock = sock_cls.return_value
            sock.recvfrom.side_effect = OSError("no reply")
            dns_query("1.1.1.1", "example.com")
            sock.bind.assert_not_called()

    def test_interface_dns_uses_resolvectl(self):
        def runner(argv):
            return 0, "Link 2 (eth0): 192.168.1.1 8.8.8.8\n", ""
        self.assertEqual(read_interface_dns("eth0", runner),
                         ["192.168.1.1", "8.8.8.8"])

    def test_interface_dns_falls_back_to_nmcli(self):
        def runner(argv):
            if argv[0] == "resolvectl":
                return 1, "", "not found"
            return 0, "192.168.1.1\n1.1.1.1\n", ""
        self.assertEqual(read_interface_dns("eth0", runner),
                         ["192.168.1.1", "1.1.1.1"])

    def test_interface_dns_returns_none_when_tools_missing(self):
        def runner(argv):
            raise OSError("missing")
        self.assertIsNone(read_interface_dns("eth0", runner))

    def test_interface_dns_none_without_iface(self):
        self.assertIsNone(read_interface_dns(None))


if __name__ == "__main__":
    unittest.main()
