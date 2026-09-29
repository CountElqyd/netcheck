import unittest

from netcheck import (
    BASE_PORT_IFINDEX_OID,
    BRIDGE_FDB_OID,
    QB_FDB_OID,
    Config,
    Devicelist,
    SnmpError,
    collect_devices,
    mac_from_oid_suffix,
    mac_to_oid_suffix,
)


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


MAC_A = "00:1E:58:AA:BB:CC"
MAC_B = "3C:07:54:9A:BC:DE"


def _suffix(mac):
    return mac_to_oid_suffix(mac)


class FakeClient:
    def __init__(self, host, community, **kw):
        self.host = host

    def walk(self, base_oid):
        if base_oid == QB_FDB_OID:
            if self.host == "10.90.90.90":
                return [(f"{QB_FDB_OID}.{_suffix(MAC_A)}", 5)]
            if self.host == "10.90.90.91":
                return [(f"{QB_FDB_OID}.{_suffix(MAC_B)}", 8)]
            return []
        if base_oid == BASE_PORT_IFINDEX_OID:
            return [(f"{BASE_PORT_IFINDEX_OID}.5", 5),
                    (f"{BASE_PORT_IFINDEX_OID}.8", 8)]
        return []


class BridgeOnlyClient(FakeClient):
    def walk(self, base_oid):
        if base_oid == QB_FDB_OID:
            return []
        if base_oid == BRIDGE_FDB_OID:
            return [(f"{BRIDGE_FDB_OID}.{_suffix(MAC_A)}", 5)]
        if base_oid == BASE_PORT_IFINDEX_OID:
            return [(f"{BASE_PORT_IFINDEX_OID}.5", 5)]
        return []


class ExplodingClient(FakeClient):
    def __init__(self, host, community, **kw):
        super().__init__(host, community, **kw)
        self.bad = host == "10.90.90.91"

    def walk(self, base_oid):
        if self.bad:
            raise SnmpError("timeout")
        return super().walk(base_oid)


class TestCollectDevices(unittest.TestCase):
    def test_collects_macs_and_ports_per_switch(self):
        cfg = Config(switches={"dlink1": "10.90.90.90", "dlink2": "10.90.90.91"},
                     snmp_community="public")
        result = collect_devices(cfg, client_factory=FakeClient)
        self.assertIsInstance(result, Devicelist)
        self.assertEqual(result.devices["dlink1"], {MAC_A: 5})
        self.assertEqual(result.devices["dlink2"], {MAC_B: 8})
        self.assertEqual(result.errors, [])

    def test_bridge_fallback_when_qbridge_empty(self):
        cfg = Config(switches={"dlink1": "10.90.90.90"}, snmp_community="public")
        result = collect_devices(cfg, client_factory=BridgeOnlyClient)
        self.assertEqual(result.devices["dlink1"], {MAC_A: 5})

    def test_switch_error_yields_partial_result(self):
        cfg = Config(switches={"dlink1": "10.90.90.90", "dlink2": "10.90.90.91"},
                     snmp_community="public")
        result = collect_devices(cfg, client_factory=ExplodingClient)
        self.assertEqual(result.devices["dlink1"], {MAC_A: 5})
        self.assertEqual(result.devices["dlink2"], {})
        self.assertTrue(any("dlink2" in e for e in result.errors))

    def test_no_community_returns_empty(self):
        result = collect_devices(Config(), client_factory=FakeClient)
        self.assertEqual(result.devices, {})


if __name__ == "__main__":
    unittest.main()
