import unittest

from netcheck import SnmpError, Status, trace_mac

FDB_OID = "1.3.6.1.2.1.17.4.3.1.2"
BASE_OID = "1.3.6.1.2.1.17.1.4.1.2"


class FakeClient:
    def __init__(self, host, community, **kw):
        self.host = host

    def walk(self, base_oid):
        if base_oid == FDB_OID:
            return [("1.3.6.1.2.1.17.4.3.1.2.0.30.88.170.187.204", 5)]
        if base_oid == BASE_OID:
            return [(f"{BASE_OID}.5", 5)]
        return []


def _cfg(switches=None):
    return type("C", (), {"switches": switches or {"dlink1": "10.90.90.90"},
                          "snmp_community": "public", "timeout": 3.0,
                          "switch_user": "admin", "switch_pass": "x"})()


class TestTrace(unittest.TestCase):
    def test_trace_lands_on_edge_port(self):
        cfg = _cfg()
        result = trace_mac(cfg, "00:1E:58:AA:BB:CC", client_factory=FakeClient)
        self.assertIs(result.status, Status.PASS)
        self.assertIn("dlink1", result.detail)
        self.assertIn("port 5", result.detail)

    def test_mac_to_oid_suffix(self):
        from netcheck import mac_to_oid_suffix
        self.assertEqual(mac_to_oid_suffix("00:1E:58:AA:BB:CC"),
                         "0.30.88.170.187.204")
        self.assertEqual(mac_to_oid_suffix("00-1e-58-aa-bb-cc"),
                         "0.30.88.170.187.204")

    def test_trace_hops_to_downstream_switch(self):
        class HopClient(FakeClient):
            def walk(self, base_oid):
                if base_oid == FDB_OID:
                    if self.host == "10.90.90.90":
                        return [(f"{FDB_OID}.0.30.88.170.187.204", 24)]
                    return [(f"{FDB_OID}.0.30.88.170.187.204", 5)]
                if base_oid == BASE_OID:
                    return [(f"{BASE_OID}.5", 5), (f"{BASE_OID}.24", 24)]
                return []

        cfg = _cfg({"dlink1": "10.90.90.90", "dlink2": "10.90.90.91"})
        result = trace_mac(cfg, "00:1E:58:AA:BB:CC", client_factory=HopClient)
        self.assertIs(result.status, Status.PASS)
        self.assertIn("dlink2", result.detail)
        self.assertIn("port 5", result.detail)

    def test_trace_port_23_is_isp(self):
        class IspClient(FakeClient):
            def walk(self, base_oid):
                if base_oid == FDB_OID:
                    return [(f"{FDB_OID}.0.30.88.170.187.204", 23)]
                if base_oid == BASE_OID:
                    return [(f"{BASE_OID}.23", 23)]
                return []

        result = trace_mac(_cfg(), "00:1E:58:AA:BB:CC", client_factory=IspClient)
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

        result = trace_mac(_cfg(), "00:1E:58:AA:BB:CC",
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

        result = trace_mac(_cfg(), "00:1E:58:AA:BB:CC",
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

        result = trace_mac(_cfg(), "00:1E:58:AA:BB:CC",
                           client_factory=EmptyClient, telnet_factory=FakeTelnet)
        self.assertIs(result.status, Status.WARN)


if __name__ == "__main__":
    unittest.main()
