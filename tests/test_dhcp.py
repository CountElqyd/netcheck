import builtins
import unittest
from unittest import mock

from netcheck import (
    Config,
    DhcpProbe,
    RogueResponder,
    Status,
    check_rogue_dhcp,
    scapy_dhcp_discover,
)


class TestDhcp(unittest.TestCase):
    def test_rogue_fails(self):
        rogue = RogueResponder("192.168.1.77", "AA:BB:CC:DD:EE:FF", "TP-Link")
        result, macs = check_rogue_dhcp(
            Config(), discover_fn=lambda cfg=None: DhcpProbe([rogue]))
        self.assertIs(result.status, Status.FAIL)
        self.assertEqual(macs, ["AA:BB:CC:DD:EE:FF"])
        self.assertIn("via scapy", result.detail)
        self.assertNotIn("Trace the responder", result.suggested_fix)
        self.assertIn("check 7", result.suggested_fix)
        self.assertIn("inventory", result.suggested_fix)

    def test_clean_passes_with_method(self):
        gw = RogueResponder("192.168.1.1", "00:1E:58:00:00:01", "D-Link")
        result, macs = check_rogue_dhcp(
            Config(), discover_fn=lambda cfg=None: DhcpProbe([gw]))
        self.assertIs(result.status, Status.PASS)
        self.assertEqual(macs, [])
        self.assertIn("probed via scapy", result.detail)
        self.assertIn("192.168.1.1", result.detail)

    def test_unavailable_warns_with_reason(self):
        result, _ = check_rogue_dhcp(
            Config(), discover_fn=lambda cfg=None: DhcpProbe(None, "scapy not installed"))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("not tested", result.detail)
        self.assertIn("scapy not installed", result.detail)

    def test_no_responders_warns(self):
        result, _ = check_rogue_dhcp(
            Config(), discover_fn=lambda cfg=None: DhcpProbe([]))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("no DHCP server answered", result.detail)

    def test_scapy_missing_reports_reason(self):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "scapy.all":
                raise ImportError("no scapy")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=fake_import):
            probe = scapy_dhcp_discover()
        self.assertIsInstance(probe, DhcpProbe)
        self.assertIsNone(probe.responders)
        self.assertIn("scapy not installed", probe.reason)


if __name__ == "__main__":
    unittest.main()
