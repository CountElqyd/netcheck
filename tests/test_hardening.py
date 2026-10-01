import unittest

from netcheck import (
    Config,
    HardeningState,
    Status,
    STORM_FALLBACK_KBPS,
    check_hardening,
    evaluate_hardening,
    format_port_list,
    kbps_to_n,
    read_hardening_state,
)

BASELINE_GOOD = HardeningState(
    lbd_enabled=True, lbd_recover_time=0, storm_enabled=True, storm_type=3,
    storm_threshold=STORM_FALLBACK_KBPS, rstp_enabled=True, rstp_priority=4096,
    safeguard_enabled=True, dhcp_trusted_ports=[23, 24, 25, 26, 27],
    dhcp_trusted_servers=["192.168.1.1"], dos_enabled=True)
BASELINE_BAD = HardeningState(
    lbd_enabled=False, lbd_recover_time=60, storm_enabled=False, storm_type=1,
    storm_threshold=0, rstp_enabled=False, rstp_priority=32768,
    safeguard_enabled=False, dhcp_trusted_ports=[], dhcp_trusted_servers=[],
    dos_enabled=False)


class TestHardening(unittest.TestCase):
    def test_all_good_no_findings(self):
        self.assertEqual(evaluate_hardening(BASELINE_GOOD), [])

    def test_bad_reports_features(self):
        findings = "\n".join(evaluate_hardening(BASELINE_BAD))
        for feature in ("Loopback Detection", "Storm Control", "RSTP", "Safeguard"):
            self.assertIn(feature, findings)

    def test_measured_threshold_overrides(self):
        from dataclasses import replace
        state = replace(BASELINE_GOOD, storm_threshold=30000)
        self.assertEqual(evaluate_hardening(state, measured={"threshold": 30000}), [])
        self.assertTrue(evaluate_hardening(state))

    def test_unreadable_state_reports_not_exposed(self):
        findings = evaluate_hardening(HardeningState(readable=False))
        self.assertEqual(len(findings), 1)
        self.assertIn("not exposed", findings[0])

    def test_trusted_access_port_is_flagged(self):
        from dataclasses import replace
        state = replace(BASELINE_GOOD, dhcp_trusted_ports=[1, 2, 23, 24, 25, 26, 27])
        text = "\n".join(evaluate_hardening(state))
        self.assertIn("access ports trusted", text)
        self.assertIn("1-2", text)

    def test_screened_uplink_is_flagged(self):
        from dataclasses import replace
        state = replace(BASELINE_GOOD, dhcp_trusted_ports=[23, 24, 25])  # 26, 27 missing
        text = "\n".join(evaluate_hardening(state))
        self.assertIn("uplink/server port screened", text)
        self.assertIn("26-27", text)

    def test_no_trusted_server_flagged(self):
        from dataclasses import replace
        state = replace(BASELINE_GOOD, dhcp_trusted_servers=[])
        self.assertIn("no trusted DHCP server IP",
                      "\n".join(evaluate_hardening(state)))


COMPLIANT_VALUES = {
    "1.3.6.1.4.1.171.10.76.20.1.17.1.0": 1,
    "1.3.6.1.4.1.171.10.76.20.1.17.4.0": 0,
    "1.3.6.1.4.1.171.10.76.20.1.13.3.1.0": 1,
    "1.3.6.1.4.1.171.10.76.20.1.13.3.2.0": 3,
    "1.3.6.1.4.1.171.10.76.20.1.13.3.3.0": STORM_FALLBACK_KBPS,
    "1.3.6.1.4.1.171.10.76.20.1.6.1.1.0": 1,
    "1.3.6.1.4.1.171.10.76.20.1.6.1.3.0": 32768,
    "1.3.6.1.4.1.171.10.76.20.1.1.8.0": 1,
    "1.3.6.1.4.1.171.10.76.20.1.14.1.1.0": 2,
    "1.3.6.1.4.1.171.10.76.20.1.99.1.0": 1,
}


class CompliantClient:
    def __init__(self, host, community, **kw):
        pass

    def get(self, oids):
        return {oid: COMPLIANT_VALUES.get(oid) for oid in oids}

    def walk(self, base_oid):
        if base_oid.endswith(".14.2.1.1.2"):
            return [(f"{base_oid}.{p}", 2) for p in (23, 24, 25, 26, 27)]
        if base_oid.endswith(".14.7.3.1.2"):
            return [(f"{base_oid}.1", b"\xc0\xa8\x01\x01")]
        return []


class UnknownOidClient(CompliantClient):
    """Simulates firmware that does not expose the private MIB (every GET None)."""

    def get(self, oids):
        return {oid: None for oid in oids}

    def walk(self, base_oid):
        return []


class PerSwitchThresholdClient(CompliantClient):
    def __init__(self, host, community, **kw):
        self.host = host

    def get(self, oids):
        values = dict(COMPLIANT_VALUES)
        values["1.3.6.1.4.1.171.10.76.20.1.13.3.3.0"] = (
            10048 if self.host.endswith(".90") else 20032)
        return {oid: values.get(oid) for oid in oids}


class TestStormUnits(unittest.TestCase):
    def test_kbps_to_n_rounds_and_clamps(self):
        self.assertEqual(kbps_to_n(20032), 313)
        self.assertEqual(kbps_to_n(10048), 157)
        self.assertEqual(kbps_to_n(0), 1)
        self.assertEqual(kbps_to_n(64 * 99999), 16000)

    def test_fallback_is_a_valid_step(self):
        self.assertEqual(STORM_FALLBACK_KBPS % 64, 0)
        self.assertEqual(kbps_to_n(STORM_FALLBACK_KBPS), 313)


class TestPortListFormat(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(format_port_list([]), "none")

    def test_ranges(self):
        self.assertEqual(format_port_list([1, 2, 3, 5, 7, 8]), "1-3,5,7-8")

    def test_dedup_and_sort(self):
        self.assertEqual(format_port_list([3, 1, 2, 2]), "1-3")


class TestStormFindingWording(unittest.TestCase):
    def test_threshold_mismatch_shows_both_n(self):
        from dataclasses import replace
        state = replace(BASELINE_GOOD, storm_threshold=10048)
        text = "\n".join(evaluate_hardening(state))
        self.assertIn("N=157", text)
        self.assertIn("N=313", text)


class TestPerSwitchMeasured(unittest.TestCase):
    def test_each_switch_uses_its_own_recommendation(self):
        cfg = Config(switches={"dlink1": "10.90.90.90", "dlink2": "10.90.90.91"},
                     snmp_community="public")
        measured = {"dlink1": {"threshold": 10048}, "dlink2": {"threshold": 20032}}
        result = check_hardening(cfg, measured=measured,
                                 client_factory=PerSwitchThresholdClient)
        self.assertIs(result.status, Status.PASS)


class TestCheckHardening(unittest.TestCase):
    def test_compliant_switch_passes(self):
        result = check_hardening(Config(snmp_community="public"),
                                 client_factory=CompliantClient)
        self.assertIs(result.status, Status.PASS)

    def test_no_community_warns(self):
        result = check_hardening(Config(), client_factory=CompliantClient)
        self.assertIs(result.status, Status.WARN)

    def test_unreadable_switch_warns(self):
        cfg = Config(switches={"dlink1": "10.90.90.90"}, snmp_community="public")
        result = check_hardening(cfg, client_factory=UnknownOidClient)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("not exposed", result.detail)


class TestReadHardeningState(unittest.TestCase):
    def test_reads_scalars_with_dot_zero(self):
        state = read_hardening_state(CompliantClient("h", "c"))
        self.assertTrue(state.readable)
        self.assertTrue(state.lbd_enabled)
        self.assertTrue(state.rstp_enabled)
        self.assertEqual(state.storm_type, 3)
        self.assertEqual(state.storm_threshold, STORM_FALLBACK_KBPS)

    def test_all_none_marks_unreadable(self):
        state = read_hardening_state(UnknownOidClient("h", "c"))
        self.assertFalse(state.readable)

    def test_reads_dhcp_trusted_ports_and_servers(self):
        class DhcpClient(CompliantClient):
            def walk(self, base_oid):
                if base_oid.endswith(".14.2.1.1.2"):
                    return [(f"{base_oid}.23", 2), (f"{base_oid}.1", 1)]
                if base_oid.endswith(".14.7.3.1.2"):
                    return [(f"{base_oid}.1", b"\xc0\xa8\x01\x01")]
                return []

        state = read_hardening_state(DhcpClient("h", "c"))
        self.assertEqual(state.dhcp_trusted_ports, [23])
        self.assertEqual(state.dhcp_trusted_servers, ["192.168.1.1"])

if __name__ == "__main__":
    unittest.main()
