import unittest

from netcheck import Config, RogueResponder, Status, check_rogue_dhcp, parse_nmap_dhcp

NMAP = """
| DHCP-Discover:
|   IP Offered: 192.168.1.77
|   Server IP: 192.168.1.77
|_  MAC: AA:BB:CC:DD:EE:FF (TP-Link)
"""


class TestDhcp(unittest.TestCase):
    def test_parse_nmap(self):
        rows = parse_nmap_dhcp(NMAP)
        self.assertEqual(rows[0].server_ip, "192.168.1.77")
        self.assertEqual(rows[0].mac, "AA:BB:CC:DD:EE:FF")

    def test_rogue_fails(self):
        rogue = RogueResponder("192.168.1.77", "AA:BB:CC:DD:EE:FF", "TP-Link")

        def discover(cfg=None):
            return [rogue]

        result, macs = check_rogue_dhcp(Config(), discover_fn=discover)
        self.assertIs(result.status, Status.FAIL)
        self.assertEqual(macs, ["AA:BB:CC:DD:EE:FF"])

    def test_clean_passes(self):
        gw = RogueResponder("192.168.1.1", "00:1E:58:00:00:01", "D-Link")

        def discover(cfg=None):
            return [gw]

        result, _ = check_rogue_dhcp(Config(), discover_fn=discover)
        self.assertIs(result.status, Status.PASS)

    def test_unknown_warns(self):
        result, _ = check_rogue_dhcp(Config(), discover_fn=lambda cfg=None: None)
        self.assertIs(result.status, Status.WARN)


if __name__ == "__main__":
    unittest.main()
