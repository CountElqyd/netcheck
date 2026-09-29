import unittest

from netcheck import Config, Status, check_local_config, parse_ipconfig_windows, parse_linux


IPCONFIG = """
Ethernet adapter Ethernet:
   IPv4 Address. . . . . . . . . . . : 192.168.1.50(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 58.71.2.8
                                       45.63.30.117
"""

IPCONFIG_APIPA = """
   IPv4 Address. . . . . . . . . . . : 169.254.10.10(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 192.168.1.1
"""

LINUX_ROUTE = "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 100"
LINUX_ADDR = """1: lo: <LOOPBACK,UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,UP> mtu 1500
    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0"""
LINUX_RESOLV = "nameserver 58.71.2.8\nnameserver 45.63.30.117\n"


class TestLocalConfig(unittest.TestCase):
    def test_parse_windows(self):
        lc = parse_ipconfig_windows(IPCONFIG)
        self.assertEqual(lc.ip, "192.168.1.50")
        self.assertEqual(lc.gateway, "192.168.1.1")
        self.assertEqual(lc.dns, ["58.71.2.8", "45.63.30.117"])

    def test_check_pass(self):
        result = check_local_config(Config(), local_fn=lambda: parse_ipconfig_windows(IPCONFIG))
        self.assertIs(result.status, Status.PASS)

    def test_check_apipa_fails(self):
        result = check_local_config(Config(), local_fn=lambda: parse_ipconfig_windows(IPCONFIG_APIPA))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("APIPA", result.likely_cause or "")

    def test_parse_linux_skips_loopback(self):
        lc = parse_linux(LINUX_ROUTE, LINUX_ADDR, LINUX_RESOLV)
        self.assertEqual(lc.ip, "192.168.1.50")
        self.assertEqual(lc.gateway, "192.168.1.1")
        self.assertEqual(lc.interface, "eth0")
        self.assertEqual(lc.dns, ["58.71.2.8", "45.63.30.117"])


if __name__ == "__main__":
    unittest.main()
