import unittest

from netcheck import (
    BASE_PORT_IFINDEX_OID,
    BRIDGE_FDB_OID,
    QB_FDB_OID,
    Config,
    Devicelist,
    SnmpError,
    access_devices,
    collect_devices,
    mac_from_oid_suffix,
    mac_to_oid_suffix,
    parse_port_spec,
    parse_uplink_ports,
    uplink_ports_for,
)


class TestMacFromOidSuffix(unittest.TestCase):
    def test_recovers_mac_from_qbridge_oid(self):
        mac = "00:1E:58:AA:BB:CC"
        oid = f"{QB_FDB_OID}.{mac_to_oid_suffix(mac)}"
        self.assertEqual(mac_from_oid_suffix(oid, QB_FDB_OID), mac)

    def test_recovers_mac_from_real_qbridge_oid_with_fdbid(self):
        mac = "00:1E:58:AA:BB:CC"
        oid = f"{QB_FDB_OID}.1.{mac_to_oid_suffix(mac)}"
        parts = oid[len(QB_FDB_OID) + 1:].split(".")
        self.assertEqual(len(parts), 7)
        self.assertEqual(mac_from_oid_suffix(oid, QB_FDB_OID), mac)

    def test_recovers_mac_from_bridge_oid(self):
        mac = "3C:07:54:9A:BC:DE"
        oid = f"{BRIDGE_FDB_OID}.{mac_to_oid_suffix(mac)}"
        self.assertEqual(mac_from_oid_suffix(oid, BRIDGE_FDB_OID), mac)

    def test_returns_none_when_not_under_base(self):
        oid = f"{QB_FDB_OID}.0.30.88.170.187.204"
        self.assertIsNone(mac_from_oid_suffix(oid, BRIDGE_FDB_OID))

    def test_returns_none_on_fewer_than_six_octets(self):
        oid = f"{QB_FDB_OID}.0.30.88"
        self.assertIsNone(mac_from_oid_suffix(oid, QB_FDB_OID))

    def test_returns_none_on_non_integer_suffix(self):
        oid = f"{QB_FDB_OID}.0.30.88.170.187.x"
        self.assertIsNone(mac_from_oid_suffix(oid, QB_FDB_OID))

    def test_returns_none_on_out_of_range_octet(self):
        oid = f"{QB_FDB_OID}.1.0.30.88.170.187.300"
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
                return [(f"{QB_FDB_OID}.1.{_suffix(MAC_A)}", 5)]
            if self.host == "10.90.90.91":
                return [(f"{QB_FDB_OID}.1.{_suffix(MAC_B)}", 8)]
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

    def test_source_is_forwarded_to_client_factory(self):
        seen = {}

        class CapturingClient(FakeClient):
            def __init__(self, host, community, **kw):
                super().__init__(host, community, **kw)
                seen["source"] = kw.get("source")

        cfg = Config(switches={"dlink1": "10.90.90.90"}, snmp_community="public")
        collect_devices(cfg, client_factory=CapturingClient, source="10.90.90.100")
        self.assertEqual(seen["source"], "10.90.90.100")


class TestUplinkPortParsing(unittest.TestCase):
    def test_single_port_and_range(self):
        self.assertEqual(parse_port_spec("24"), {24})
        self.assertEqual(parse_port_spec("23-27"), {23, 24, 25, 26, 27})

    def test_plus_joins_multiple_specs(self):
        self.assertEqual(parse_port_spec("24-25+27"), {24, 25, 27})

    def test_invalid_parts_ignored(self):
        self.assertEqual(parse_port_spec("x+24"), {24})
        self.assertEqual(parse_port_spec("bad"), set())

    def test_global_and_per_switch(self):
        global_ports, per_switch = parse_uplink_ports("23-27,dlink2:24-25")
        self.assertEqual(global_ports, {23, 24, 25, 26, 27})
        self.assertEqual(per_switch, {"dlink2": {24, 25}})

    def test_uplink_ports_for_falls_back_to_global(self):
        cfg = Config(uplink_ports={23, 24}, uplink_ports_by_switch={"dlink2": {24}})
        self.assertEqual(uplink_ports_for(cfg, "dlink2"), {24})
        self.assertEqual(uplink_ports_for(cfg, "dlink1"), {23, 24})


class TestAccessDevices(unittest.TestCase):
    def test_drops_uplink_ports(self):
        devs = Devicelist(devices={"dlink1": {MAC_A: 5, MAC_B: 25}})
        result = access_devices(devs, lambda switch: {25})
        self.assertEqual(result.devices["dlink1"], {MAC_A: 5})

    def test_per_switch_uplinks(self):
        devs = Devicelist(devices={"dlink1": {MAC_A: 5}, "dlink2": {MAC_B: 8}})
        result = access_devices(
            devs, lambda switch: {5} if switch == "dlink1" else set())
        self.assertEqual(result.devices["dlink1"], {})
        self.assertEqual(result.devices["dlink2"], {MAC_B: 8})

    def test_dedupes_keeping_least_populated_port(self):
        mac_e = "00:1E:58:AA:BB:EE"
        devs = Devicelist(devices={
            "dlink1": {MAC_A: 24, mac_e: 24},
            "dlink2": {MAC_A: 10},
        })
        result = access_devices(devs, lambda switch: set())
        self.assertEqual(result.devices["dlink1"], {mac_e: 24})
        self.assertEqual(result.devices["dlink2"], {MAC_A: 10})

    def test_errors_preserved(self):
        devs = Devicelist(devices={"dlink1": {}}, errors=["dlink1: SNMP unavailable (x)"])
        result = access_devices(devs, lambda switch: set())
        self.assertEqual(result.errors, ["dlink1: SNMP unavailable (x)"])


from netcheck import (
    CheckResult,
    Status,
    check_device_inventory,
    format_inventory,
)


class TestFormatInventory(unittest.TestCase):
    def test_marks_only_rogue_mac(self):
        devs = Devicelist(devices={"dlink1": {MAC_A: 5, MAC_B: 8}})
        text = format_inventory(devs, [MAC_A])
        lines = [ln for ln in text.splitlines() if "port" in ln]
        self.assertEqual(len(lines), 2)
        rogue_line = next(ln for ln in lines if "AA:BB:CC" in ln)
        ok_line = next(ln for ln in lines if "9A:BC:DE" in ln)
        self.assertIn("ROGUE", rogue_line)
        self.assertNotIn("ROGUE", ok_line)

    def test_sorts_rows_by_port(self):
        devs = Devicelist(devices={"dlink1": {MAC_A: 9, MAC_B: 3}})
        lines = [ln for ln in format_inventory(devs, []).splitlines() if "port" in ln]
        self.assertIn(" 3 ", lines[0])
        self.assertIn(" 9 ", lines[1])

    def test_headers_per_switch_then_rows_sorted_by_port(self):
        mac_c = "00:1E:58:11:22:33"
        devs = Devicelist(devices={
            "dlink1": {MAC_A: 9, mac_c: 1},
            "dlink2": {MAC_B: 3},
        })
        lines = format_inventory(devs, []).splitlines()
        headers = [ln.strip() for ln in lines
                   if ln.startswith("    ") and "port" not in ln]
        port_lines = [ln for ln in lines if "port" in ln]
        self.assertEqual(headers, ["dlink1", "dlink2"])
        self.assertEqual(len(port_lines), 3)
        self.assertIn(" 1 ", port_lines[0])
        self.assertIn(" 9 ", port_lines[1])
        self.assertIn(" 3 ", port_lines[2])

    def test_includes_vendor(self):
        devs = Devicelist(devices={"dlink1": {"00:1E:58:11:22:33": 5}})
        self.assertIn("D-Link", format_inventory(devs, []))

    def test_error_lines_are_appended(self):
        devs = Devicelist(devices={"dlink2": {}}, errors=["dlink2: SNMP unavailable (x)"])
        self.assertIn("dlink2: SNMP unavailable", format_inventory(devs, []))


class TestCheckDeviceInventory(unittest.TestCase):
    def test_fail_when_rogue_present(self):
        cfg = Config(switches={"dlink1": "10.90.90.90"}, snmp_community="public")
        result = check_device_inventory(cfg, [MAC_A], client_factory=FakeClient)
        self.assertIs(result.status, Status.FAIL)
        self.assertEqual(result.id, 7)
        self.assertIn("Device inventory", result.title)

    def test_pass_when_no_rogue(self):
        cfg = Config(switches={"dlink1": "10.90.90.90"}, snmp_community="public")
        result = check_device_inventory(cfg, [], client_factory=FakeClient)
        self.assertIs(result.status, Status.PASS)

    def test_pass_with_partial_error_prints_table_once(self):
        cfg = Config(switches={"dlink1": "10.90.90.90", "dlink2": "10.90.90.91"},
                     snmp_community="public")
        result = check_device_inventory(cfg, [], client_factory=ExplodingClient)
        self.assertIs(result.status, Status.PASS)
        self.assertEqual(result.detail.count("port"), 1)
        self.assertEqual(result.detail.count(MAC_A), 1)
        self.assertIn("dlink2", result.detail)

    def test_warn_without_snmp(self):
        result = check_device_inventory(Config(), [], client_factory=FakeClient)
        self.assertIs(result.status, Status.WARN)

    def test_warn_when_all_switches_error(self):
        cfg = Config(switches={"dlink1": "10.90.90.91"}, snmp_community="public")
        result = check_device_inventory(cfg, [], client_factory=ExplodingClient)
        self.assertIs(result.status, Status.WARN)

    def test_uplink_port_entries_hidden(self):
        cfg = Config(switches={"dlink1": "10.90.90.90"}, snmp_community="public",
                     uplink_ports={5})
        result = check_device_inventory(cfg, [], client_factory=FakeClient)
        self.assertIs(result.status, Status.PASS)
        self.assertNotIn(MAC_A, result.detail)
        self.assertIn("1 on uplink ports hidden", result.detail)

    def test_rogue_seen_only_on_uplink_still_flagged(self):
        cfg = Config(switches={"dlink1": "10.90.90.90"}, snmp_community="public",
                     uplink_ports={5})
        result = check_device_inventory(cfg, [MAC_A], client_factory=FakeClient)
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("dlink1 port 5", result.detail)


if __name__ == "__main__":
    unittest.main()
