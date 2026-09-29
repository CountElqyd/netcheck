import struct
import unittest

from netcheck import build_dns_query, parse_dns_a


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


if __name__ == "__main__":
    unittest.main()
