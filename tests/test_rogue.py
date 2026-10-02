import unittest

from netcheck import Config, Status, check_rogue_dhcp, DhcpProbe


class TestRogueIfaceForwarding(unittest.TestCase):
    def test_iface_is_forwarded_to_discover_fn(self):
        seen = {}

        def fake_discover(cfg=None, iface=None):
            seen["iface"] = iface
            return DhcpProbe(None, "stub")

        check_rogue_dhcp(Config(), discover_fn=fake_discover, iface="eth0")
        self.assertEqual(seen["iface"], "eth0")

    def test_no_iface_passes_none(self):
        seen = {}

        def fake_discover(cfg=None, iface=None):
            seen["iface"] = iface
            return DhcpProbe(None, "stub")

        check_rogue_dhcp(Config(), discover_fn=fake_discover)
        self.assertIsNone(seen["iface"])


if __name__ == "__main__":
    unittest.main()
