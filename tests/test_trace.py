import unittest

from netcheck import (
    BASE_PORT_IFINDEX_OID,
    BRIDGE_FDB_OID,
    QB_FDB_OID,
    SnmpError,
    Status,
    mac_to_oid_suffix,
    trace_mac,
)

MAC = "00:1E:58:AA:BB:CC"
SUFFIX = ".0.30.88.170.187.204"
FDB_OID = BRIDGE_FDB_OID
BASE_OID = BASE_PORT_IFINDEX_OID


def _cfg(switches=None):
    return type("C", (), {"switches": switches or {"dlink1": "10.90.90.90"},
                          "snmp_community": "public", "timeout": 3.0,
                          "switch_user": "admin", "switch_pass": "x"})()


class FakeClient:
    def __init__(self, host, community, **kw):
        self.host = host

    def walk(self, base_oid):
        if base_oid == FDB_OID:
            return [(FDB_OID + SUFFIX, 5)]
        if base_oid == BASE_OID:
            return [(f"{BASE_OID}.5", 5)]
        return []


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

    def test_trace_lands_on_edge_port(self):
        cfg = _cfg()
        result = trace_mac(cfg, MAC, client_factory=FakeClient)
        self.assertIs(result.status, Status.PASS)
        self.assertIn("dlink1", result.detail)
        self.assertIn("port 5", result.detail)

    def test_mac_to_oid_suffix(self):
        self.assertEqual(mac_to_oid_suffix("00:1E:58:AA:BB:CC"),
                         "0.30.88.170.187.204")
        self.assertEqual(mac_to_oid_suffix("00-1e-58-aa-bb-cc"),
                         "0.30.88.170.187.204")

    def test_trace_hops_to_downstream_switch(self):
        class HopClient(FakeClient):
            def walk(self, base_oid):
                if base_oid == FDB_OID:
                    if self.host == "10.90.90.90":
                        return [(f"{FDB_OID}{SUFFIX}", 24)]
                    return [(f"{FDB_OID}{SUFFIX}", 5)]
                if base_oid == BASE_OID:
                    return [(f"{BASE_OID}.5", 5), (f"{BASE_OID}.24", 24)]
                return []

        cfg = _cfg({"dlink1": "10.90.90.90", "dlink2": "10.90.90.91"})
        result = trace_mac(cfg, MAC, client_factory=HopClient)
        self.assertIs(result.status, Status.PASS)
        self.assertIn("dlink2", result.detail)
        self.assertIn("port 5", result.detail)

    def test_trace_port_23_is_isp(self):
        class IspClient(FakeClient):
            def walk(self, base_oid):
                if base_oid == FDB_OID:
                    return [(f"{FDB_OID}{SUFFIX}", 23)]
                if base_oid == BASE_OID:
                    return [(f"{BASE_OID}.23", 23)]
                return []

        result = trace_mac(_cfg(), MAC, client_factory=IspClient)
        self.assertIs(result.status, Status.PASS)
        self.assertIn("ISP", result.detail)

    def test_telnet_fallback_used_when_snmp_empty(self):
        class EmptyClient(FakeClient):
            def walk(self, base_oid):
                return []

        class FakeTelnet:
            def __init__(self, host, timeout=5.0):
                self.host = host

            def connect(self):
                pass

            def login(self, user, password):
                return ""

            def run_command(self, cmd, wait=1.0):
                return b"00:1E:58:AA:BB:CC  9\n"

            def close(self):
                pass

        result = trace_mac(_cfg(), MAC,
                           client_factory=EmptyClient, telnet_factory=FakeTelnet)
        self.assertIs(result.status, Status.PASS)
        self.assertIn("dlink1", result.detail)
        self.assertIn("port 9", result.detail)

    def test_snmp_error_falls_back(self):
        class ErrClient(FakeClient):
            def walk(self, base_oid):
                raise SnmpError("down")

        class FakeTelnet:
            def __init__(self, host, timeout=5.0):
                pass

            def connect(self):
                pass

            def login(self, user, password):
                return ""

            def run_command(self, cmd, wait=1.0):
                return b"00:1E:58:AA:BB:CC  9\n"

            def close(self):
                pass

        result = trace_mac(_cfg(), MAC,
                           client_factory=ErrClient, telnet_factory=FakeTelnet)
        self.assertIs(result.status, Status.PASS)
        self.assertIn("port 9", result.detail)

    def test_not_found_is_warn(self):
        class EmptyClient(FakeClient):
            def walk(self, base_oid):
                return []

        class FakeTelnet:
            def __init__(self, host, timeout=5.0):
                pass

            def connect(self):
                pass

            def login(self, user, password):
                return ""

            def run_command(self, cmd, wait=1.0):
                return b""

            def close(self):
                pass

        result = trace_mac(_cfg(), MAC,
                           client_factory=EmptyClient, telnet_factory=FakeTelnet)
        self.assertIs(result.status, Status.WARN)


if __name__ == "__main__":
    unittest.main()
