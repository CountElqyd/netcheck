import unittest

from netcheck import (
    ber_decode_integer,
    ber_decode_oid,
    ber_decode_tlv,
    ber_encode_integer,
    ber_encode_length,
    ber_encode_oid,
    ber_encode_sequence,
)


class TestBer(unittest.TestCase):
    def test_length_short_and_long(self):
        self.assertEqual(ber_encode_length(5), b"\x05")
        self.assertEqual(ber_encode_length(200), b"\x81\xc8")

    def test_integer_round_trip(self):
        for n in (0, 1, 127, 128, 32768, 2_000_000_000):
            tag, value, nxt = ber_decode_tlv(ber_encode_integer(n))
            self.assertEqual(tag, 0x02)
            self.assertEqual(ber_decode_integer(value), n)
            self.assertEqual(nxt, len(ber_encode_integer(n)))

    def test_oid_round_trip(self):
        for oid in ("1.3.6.1", "1.3.6.1.4.1.171.10.76.20.1.17.5.1.3"):
            tag, value, _ = ber_decode_tlv(ber_encode_oid(oid))
            self.assertEqual(tag, 0x06)
            self.assertEqual(ber_decode_oid(value), oid)

    def test_sequence_integer(self):
        encoded = ber_encode_sequence([ber_encode_integer(7)])
        tag, value, _ = ber_decode_tlv(encoded)
        self.assertEqual(tag, 0x30)
        _, inner, _ = ber_decode_tlv(value)
        self.assertEqual(ber_decode_integer(inner), 7)


if __name__ == "__main__":
    unittest.main()
