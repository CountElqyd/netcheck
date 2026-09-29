import unittest

from netcheck import BRIDGE_FDB_OID, QB_FDB_OID, mac_from_oid_suffix, mac_to_oid_suffix


class TestMacFromOidSuffix(unittest.TestCase):
    def test_recovers_mac_from_qbridge_oid(self):
        mac = "00:1E:58:AA:BB:CC"
        oid = f"{QB_FDB_OID}.{mac_to_oid_suffix(mac)}"
        self.assertEqual(mac_from_oid_suffix(oid, QB_FDB_OID), mac)

    def test_recovers_mac_from_bridge_oid(self):
        mac = "3C:07:54:9A:BC:DE"
        oid = f"{BRIDGE_FDB_OID}.{mac_to_oid_suffix(mac)}"
        self.assertEqual(mac_from_oid_suffix(oid, BRIDGE_FDB_OID), mac)

    def test_returns_none_when_not_under_base(self):
        oid = f"{QB_FDB_OID}.0.30.88.170.187.204"
        self.assertIsNone(mac_from_oid_suffix(oid, BRIDGE_FDB_OID))

    def test_returns_none_on_wrong_octet_count(self):
        oid = f"{QB_FDB_OID}.0.30.88"
        self.assertIsNone(mac_from_oid_suffix(oid, QB_FDB_OID))

    def test_returns_none_on_non_integer_suffix(self):
        oid = f"{QB_FDB_OID}.0.30.88.170.187.x"
        self.assertIsNone(mac_from_oid_suffix(oid, QB_FDB_OID))


if __name__ == "__main__":
    unittest.main()
