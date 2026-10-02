import unittest

from netcheck import (
    Config,
    InterfaceAddr,
    LanInterface,
    parse_linux_interfaces,
    parse_macos_interfaces,
    parse_windows_interfaces,
    resolve_lan_interface,
)

LINUX = """1: lo    inet 127.0.0.1/8 scope host lo
2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global dynamic eth0
3: wlan0    inet 192.168.68.160/24 brd 192.168.68.255 scope global dynamic wlan0
4: eth0    inet 10.90.90.100/24 scope global eth0
"""

MACOS = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 10.90.90.100 netmask 0xffffff00 broadcast 10.90.90.255
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 10.8.0.2 netmask 0xffffff00
"""

WINDOWS = """
Windows IP Configuration

Ethernet adapter Ethernet:

   Description . . . . . . . . . . . : Realtek PCIe GbE Family Controller
   IPv4 Address. . . . . . . . . . . : 192.168.1.50(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1

Wireless LAN adapter Wi-Fi:

   Description . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX201
   IPv4 Address. . . . . . . . . . . : 192.168.68.160(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.68.1

Ethernet adapter Ethernet 2:

   Description . . . . . . . . . . . : Realtek USB GbE Family Controller
   IPv4 Address. . . . . . . . . . . : 10.90.90.100(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
"""


class TestParsers(unittest.TestCase):
    def test_linux_parses_and_skips_loopback(self):
        ifaces = {i.name: i for i in parse_linux_interfaces(LINUX)}
        self.assertNotIn("lo", ifaces)
        self.assertEqual([a.ip for a in ifaces["eth0"].addrs],
                         ["192.168.1.50", "10.90.90.100"])
        self.assertEqual(ifaces["wlan0"].addrs[0].prefix, 24)

    def test_macos_parses_and_skips_virtual(self):
        ifaces = {i.name: i for i in parse_macos_interfaces(MACOS)}
        self.assertNotIn("lo0", ifaces)
        self.assertNotIn("utun0", ifaces)
        self.assertEqual(ifaces["en0"].addrs[0].ip, "192.168.1.50")
        self.assertEqual(ifaces["en0"].addrs[0].prefix, 24)

    def test_windows_parses_adapters_and_gateway(self):
        ifaces = {i.name: i for i in parse_windows_interfaces(WINDOWS)}
        self.assertEqual(ifaces["Ethernet"].addrs[0].ip, "192.168.1.50")
        self.assertEqual(ifaces["Ethernet"].gateway, "192.168.1.1")
        self.assertEqual(ifaces["Ethernet 2"].addrs[0].ip, "10.90.90.100")


class TestResolveLan(unittest.TestCase):
    def test_picks_wired_office_nic_over_wifi(self):
        lan = resolve_lan_interface(Config(), interfaces=parse_linux_interfaces(LINUX))
        self.assertEqual(lan.name, "eth0")
        self.assertEqual(lan.primary_ip, "192.168.1.50")

    def test_macos_picks_en0(self):
        lan = resolve_lan_interface(Config(), interfaces=parse_macos_interfaces(MACOS))
        self.assertEqual(lan.name, "en0")
        self.assertEqual(lan.primary_ip, "192.168.1.50")

    def test_windows_picks_named_ethernet(self):
        lan = resolve_lan_interface(Config(), interfaces=parse_windows_interfaces(WINDOWS))
        self.assertEqual(lan.name, "Ethernet")
        self.assertEqual(lan.primary_ip, "192.168.1.50")

    def test_returns_none_without_candidate(self):
        only_wifi = [i for i in parse_linux_interfaces(LINUX) if i.name == "wlan0"]
        self.assertIsNone(resolve_lan_interface(Config(), interfaces=only_wifi))

    def test_override_selects_named_interface(self):
        cfg = Config(lan_interface="en1")
        lan = resolve_lan_interface(cfg, interfaces=parse_macos_interfaces(MACOS))
        self.assertEqual(lan.name, "en1")
        self.assertEqual(lan.primary_ip, "10.90.90.100")


class TestSourceFor(unittest.TestCase):
    def test_source_for_selects_on_subnet_address(self):
        lan = LanInterface("eth0", "192.168.1.50",
                           [InterfaceAddr("192.168.1.50", 24),
                            InterfaceAddr("10.90.90.100", 24)])
        self.assertEqual(lan.source_for("10.90.90.90"), "10.90.90.100")
        self.assertEqual(lan.source_for("1.1.1.1"), "192.168.1.50")


if __name__ == "__main__":
    unittest.main()
