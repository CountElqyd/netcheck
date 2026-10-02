import unittest
from unittest import mock

from netcheck import (
    Config,
    InterfaceAddr,
    LanInterface,
    LocalConfig,
    Status,
    check_local_config,
    detect_local_config,
    office_network,
    parse_ipconfig_windows,
    parse_linux,
    parse_windows_dns,
)


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

    def test_off_subnet_address_fails_against_configured_gateway(self):
        cfg = Config(gateway="10.20.30.1")
        lc = LocalConfig(ip="192.168.68.160", gateway="192.168.68.1", dns=["1.1.1.1"])
        result = check_local_config(cfg, local_fn=lambda: lc)
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("10.20.30.0/24", result.likely_cause or "")

    def test_parse_linux_skips_loopback(self):
        lc = parse_linux(LINUX_ROUTE, LINUX_ADDR, LINUX_RESOLV)
        self.assertEqual(lc.ip, "192.168.1.50")
        self.assertEqual(lc.gateway, "192.168.1.1")
        self.assertEqual(lc.interface, "eth0")
        self.assertEqual(lc.dns, ["58.71.2.8", "45.63.30.117"])


class TestWiredCheckOne(unittest.TestCase):
    def test_windows_dns_aggregates_all_adapters(self):
        text = (
            "Ethernet adapter Ethernet:\n"
            "   DNS Servers . . . . . . . . . . . : 58.71.2.8\n"
            "                                       45.63.30.117\n"
            "Ethernet adapter Wi-Fi:\n"
            "   DNS Servers . . . . . . . . . . . : 192.168.68.1\n"
        )
        self.assertEqual(parse_windows_dns(text),
                         ["58.71.2.8", "45.63.30.117", "192.168.68.1"])

    def test_windows_dns_deduplicates(self):
        text = ("DNS Servers . . . . . . . . . . . : 1.1.1.1\n"
                "DNS Servers . . . . . . . . . . . : 1.1.1.1\n")
        self.assertEqual(parse_windows_dns(text), ["1.1.1.1"])

    def _lan(self, ip):
        return LanInterface("eth0", ip, [InterfaceAddr(ip, 24)])

    def test_detect_uses_wired_nic(self):
        cfg = Config()
        lan = self._lan("192.168.1.50")
        with mock.patch("netcheck.read_interface_dns", return_value=None), \
             mock.patch("netcheck.read_dns_servers", return_value=["1.1.1.1"]), \
             mock.patch("netcheck.default_route_interface", return_value="wlan0"):
            lc = detect_local_config(cfg, lan=lan)
        self.assertEqual(lc.interface, "eth0")
        self.assertEqual(lc.ip, "192.168.1.50")
        self.assertEqual(lc.gateway, "192.168.1.1")
        self.assertEqual(lc.default_route_interface, "wlan0")

    def test_pass_reports_wired_only_detail(self):
        cfg = Config()
        lan = self._lan("192.168.1.50")
        with mock.patch("netcheck.read_interface_dns", return_value=None), \
             mock.patch("netcheck.read_dns_servers",
                        return_value=["192.168.68.1", "1.1.1.1", "192.168.1.1"]), \
             mock.patch("netcheck.default_route_interface", return_value="wlan0"):
            result = check_local_config(
                cfg, local_fn=lambda: detect_local_config(cfg, lan=lan))
        self.assertIs(result.status, Status.PASS)
        self.assertNotIn("Wi-Fi", result.detail)
        self.assertNotIn("default route", result.detail)
        self.assertNotIn("192.168.68.1", result.detail)
        self.assertIn("1.1.1.1", result.detail)
        self.assertIn("192.168.1.1", result.detail)
        self.assertIn("interface: eth0", result.detail)
        self.assertIn("address  : 192.168.1.50/24", result.detail)
        self.assertIn("gateway  : 192.168.1.1", result.detail)
        self.assertIn("dns      : ", result.detail)

    def test_scoped_interface_dns_is_not_filtered(self):
        cfg = Config()
        lan = self._lan("192.168.1.50")
        with mock.patch("netcheck.read_interface_dns",
                        return_value=["192.168.68.1", "1.1.1.1"]), \
             mock.patch("netcheck.default_route_interface", return_value="wlan0"):
            lc = detect_local_config(cfg, lan=lan)
        self.assertTrue(lc.dns_scoped)
        result = check_local_config(cfg, local_fn=lambda: lc)
        self.assertIn("192.168.68.1", result.detail)

    def test_fail_when_not_on_office_lan(self):
        cfg = Config()
        lan = self._lan("10.90.90.100")
        with mock.patch("netcheck.read_interface_dns", return_value=None), \
             mock.patch("netcheck.read_dns_servers", return_value=["1.1.1.1"]), \
             mock.patch("netcheck.default_route_interface", return_value="wlan0"):
            result = check_local_config(
                cfg, local_fn=lambda: detect_local_config(cfg, lan=lan))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("192.168.1.0/24", result.likely_cause or "")

    def test_fail_without_lan(self):
        with mock.patch("netcheck.resolve_lan_interface", return_value=None):
            result = check_local_config(
                Config(), local_fn=lambda: detect_local_config(Config()))
        self.assertIs(result.status, Status.FAIL)

    def test_no_wired_nic_returns_empty(self):
        with mock.patch("netcheck.resolve_lan_interface", return_value=None):
            lc = detect_local_config(Config())
        self.assertIsNone(lc.ip)


if __name__ == "__main__":
    unittest.main()
