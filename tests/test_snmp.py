import unittest
from unittest import mock

from netcheck import (
    SnmpClient,
    SnmpError,
    _encode_request,
    _oid_key,
    _parse_response,
    ber_decode_tlv,
    decode_port_list,
    decode_value,
)


class TestSnmp(unittest.TestCase):
    def test_port_list_decode(self):
        # MSB of octet0 = port 1, LSB of octet0 = port 8, LSB of octet1 = port 16
        self.assertEqual(decode_port_list(b"\x81\x01"), [1, 8, 16])
        self.assertEqual(decode_port_list(b"\x00\x00"), [])

    def test_decode_value_integer(self):
        self.assertEqual(decode_value(0x02, b"\x01"), 1)
        self.assertEqual(decode_value(0x41, b"\x00\x64"), 100)

    def test_decode_value_counter64(self):
        self.assertEqual(decode_value(0x46, b"\x00\x00\x01E"), 325)

    def test_encode_request_round_trip(self):
        packed = _encode_request("public", 1, 42, 0xA0, ["1.3.6.1.2.1.1.1.0"])
        version, req_id, varbinds = _parse_response(packed)
        self.assertEqual(version, 1)
        self.assertEqual(req_id, 42)
        self.assertEqual(varbinds[0][0], "1.3.6.1.2.1.1.1.0")

    def test_encode_request_context_tag(self):
        packed = _encode_request("public", 1, 42, 0xA0, ["1.3.6.1.2.1.1.1.0"])
        _, message, _ = ber_decode_tlv(packed)
        offset = 0
        _, _, offset = ber_decode_tlv(message, offset)
        _, _, offset = ber_decode_tlv(message, offset)
        tag, _, _ = ber_decode_tlv(message, offset)
        self.assertEqual(tag, 0xA0)

    def test_oid_key_numeric_order(self):
        self.assertLess(_oid_key("1.3.6.1.2.2.9"), _oid_key("1.3.6.1.2.2.10"))

    def test_exception_tags_decode_to_none(self):
        for tag in (0x80, 0x81, 0x82):
            self.assertIsNone(decode_value(tag, b""))

    def test_get_bulk_field_count(self):
        packed = _encode_request("public", 1, 42, 0xA5, ["1.3.6.1.2.1.2.2.1.2"],
                                 max_repetitions=25)
        _, message, _ = ber_decode_tlv(packed)
        offset = 0
        _, _, offset = ber_decode_tlv(message, offset)
        _, _, offset = ber_decode_tlv(message, offset)
        tag, pdu, _ = ber_decode_tlv(message, offset)
        self.assertEqual(tag, 0xA5)
        po, fields = 0, 0
        while po < len(pdu):
            _, _, po = ber_decode_tlv(pdu, po)
            fields += 1
        self.assertEqual(fields, 4)

    def test_client_construction(self):
        client = SnmpClient("10.90.90.90", "public")
        self.assertEqual(client.host, "10.90.90.90")

    def test_client_binds_source(self):
        with mock.patch("netcheck.socket.socket") as sock_cls:
            sock = sock_cls.return_value
            sock.recvfrom.side_effect = OSError("timeout")
            client = SnmpClient("10.90.90.90", "public",
                                source="10.90.90.100", retries=0)
            with self.assertRaises(SnmpError):
                client._exchange(b"\x00")
            sock.bind.assert_called_once_with(("10.90.90.100", 0))


if __name__ == "__main__":
    unittest.main()