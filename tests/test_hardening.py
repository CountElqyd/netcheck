import unittest

from netcheck import Config, HardeningState, Status, check_hardening, evaluate_hardening

BASELINE_GOOD = HardeningState(
    lbd_enabled=True, lbd_recover_time=0, storm_enabled=True, storm_type=3,
    storm_threshold=20000, rstp_enabled=True, rstp_priority=4096,
    safeguard_enabled=True, dhcp_screen_ports=[1, 2], dos_enabled=True)

BASELINE_BAD = HardeningState(
    lbd_enabled=False, lbd_recover_time=60, storm_enabled=False, storm_type=1,
    storm_threshold=0, rstp_enabled=False, rstp_priority=32768,
    safeguard_enabled=False, dhcp_screen_ports=[], dos_enabled=False)


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


LOOP_OID = "1.3.6.1.4.1.171.10.76.20.1.17.5.1.3"

COMPLIANT_VALUES = {
    "1.3.6.1.4.1.171.10.76.20.1.17.1": 1,
    "1.3.6.1.4.1.171.10.76.20.1.17.4": 0,
    "1.3.6.1.4.1.171.10.76.20.1.13.3.1": 1,
    "1.3.6.1.4.1.171.10.76.20.1.13.3.2": 3,
    "1.3.6.1.4.1.171.10.76.20.1.13.3.3": 20000,
    "1.3.6.1.4.1.171.10.76.20.1.6.1.1": 1,
    "1.3.6.1.4.1.171.10.76.20.1.6.1.3": 32768,
    "1.3.6.1.4.1.171.10.76.20.1.1.8": 1,
    "1.3.6.1.4.1.171.10.76.20.1.14.7.1": b"\x81",
    "1.3.6.1.4.1.171.10.76.20.1.99.1": 1,
}


class CompliantClient:
    def __init__(self, host, community, **kw):
        pass

    def get(self, oids):
        return dict(COMPLIANT_VALUES)

    def walk(self, base_oid):
        return []


class LoopingCompliantClient(CompliantClient):
    def walk(self, base_oid):
        if base_oid == LOOP_OID:
            return [(f"{LOOP_OID}.7", 2)]
        return []


class TestCheckHardening(unittest.TestCase):
    def test_compliant_switch_passes(self):
        result, loops = check_hardening(Config(snmp_community="public"),
                                        client_factory=CompliantClient)
        self.assertIs(result.status, Status.PASS)
        self.assertEqual(loops, {})

    def test_loop_port_forces_fail_even_when_compliant(self):
        result, loops = check_hardening(
            Config(switches={"dlink1": "10.90.90.90"}, snmp_community="public"),
            client_factory=LoopingCompliantClient)
        self.assertIs(result.status, Status.FAIL)
        self.assertEqual(loops, {"dlink1": [7]})

    def test_no_community_warns(self):
        result, loops = check_hardening(Config(), client_factory=CompliantClient)
        self.assertIs(result.status, Status.WARN)
        self.assertEqual(loops, {})


if __name__ == "__main__":
    unittest.main()
