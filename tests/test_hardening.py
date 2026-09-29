import unittest

from netcheck import HardeningState, Status, evaluate_hardening

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
        self.assertTrue(evaluate_hardening(state))  # default 20000 would flag it


if __name__ == "__main__":
    unittest.main()
