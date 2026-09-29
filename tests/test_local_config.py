import unittest

from netcheck import Config, Status, check_local_config, parse_ipconfig_windows


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
   Default Gateway . . . . . . . . . :
"""


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
        self.assertIn("169.254", result.detail or "")


if __name__ == "__main__":
    unittest.main()
