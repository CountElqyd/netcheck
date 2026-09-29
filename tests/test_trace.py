import unittest

from netcheck import (
    BASE_PORT_IFINDEX_OID,
    BRIDGE_FDB_OID,
    QB_FDB_OID,
    Status,
    trace_mac,
)

MAC = "00:1E:58:AA:BB:CC"
SUFFIX = ".0.30.88.170.187.204"


def _cfg():
    return type("C", (), {"switches": {"dlink1": "10.90.90.90"},
                          "snmp_community": "public", "timeout": 3.0,
                          "switch_user": "admin", "switch_pass": "x"})()


class QbClient:
    def __init__(self, host, community, **kw):
        pass

    def walk(self, base_oid):
        if base_oid == QB_FDB_OID:
            return [(QB_FDB_OID + SUFFIX, 5)]
        if base_oid == BASE_PORT_IFINDEX_OID:
            return [(f"{BASE_PORT_IFINDEX_OID}.5", 101)]
        return []


class BridgeFallbackClient:
    def __init__(self, host, community, **kw):
        pass

    def walk(self, base_oid):
        if base_oid == BRIDGE_FDB_OID:
            return [(BRIDGE_FDB_OID + SUFFIX, 7)]
        if base_oid == BASE_PORT_IFINDEX_OID:
            return [(f"{BASE_PORT_IFINDEX_OID}.7", 7)]
        return []


class BothTablesClient:
    def __init__(self, host, community, **kw):
        pass

    def walk(self, base_oid):
        if base_oid == QB_FDB_OID:
            return [(QB_FDB_OID + SUFFIX, 5)]
        if base_oid == BRIDGE_FDB_OID:
            return [(BRIDGE_FDB_OID + SUFFIX, 9)]
        if base_oid == BASE_PORT_IFINDEX_OID:
            return [(f"{BASE_PORT_IFINDEX_OID}.5", 5), (f"{BASE_PORT_IFINDEX_OID}.9", 9)]
        return []


class TestTrace(unittest.TestCase):
    def test_qbridge_first_and_ifindex_translated(self):
        result = trace_mac(_cfg(), MAC, client_factory=QbClient)
        self.assertIs(result.status, Status.PASS)
        self.assertIn("dlink1", result.detail)
        self.assertIn("port 101", result.detail)

    def test_bridge_fallback_when_qbridge_empty(self):
        result = trace_mac(_cfg(), MAC, client_factory=BridgeFallbackClient)
        self.assertIn("port 7", result.detail)

    def test_qbridge_preferred_over_bridge(self):
        result = trace_mac(_cfg(), MAC, client_factory=BothTablesClient)
        self.assertIn("port 5", result.detail)
        self.assertNotIn("port 9", result.detail)


if __name__ == "__main__":
    unittest.main()
