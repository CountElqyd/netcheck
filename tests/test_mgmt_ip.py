import unittest

from netcheck import (
    Config,
    InterfaceAddr,
    LanInterface,
    ensure_mgmt_address,
    format_command,
    mgmt_add_argv,
    mgmt_del_argv,
)


def _lan(*ips):
    return LanInterface("eth0", ips[0], [InterfaceAddr(ip, 24) for ip in ips])


class TestArgv(unittest.TestCase):
    def test_add_argv_per_platform(self):
        self.assertEqual(
            mgmt_add_argv("eth0", "10.90.90.100", platform="linux"),
            ["ip", "addr", "replace", "10.90.90.100/24", "dev", "eth0"])
        self.assertEqual(
            mgmt_add_argv("en0", "10.90.90.100", platform="darwin"),
            ["ifconfig", "en0", "alias", "10.90.90.100", "255.255.255.0"])
        self.assertEqual(
            mgmt_add_argv("Ethernet", "10.90.90.100", platform="win32"),
            ["netsh", "interface", "ipv4", "add", "address", "Ethernet",
             "10.90.90.100", "255.255.255.0"])

    def test_del_argv_per_platform(self):
        self.assertEqual(
            mgmt_del_argv("eth0", "10.90.90.100", platform="linux"),
            ["ip", "addr", "del", "10.90.90.100/24", "dev", "eth0"])
        self.assertEqual(
            mgmt_del_argv("en0", "10.90.90.100", platform="darwin"),
            ["ifconfig", "en0", "-alias", "10.90.90.100"])
        self.assertEqual(
            mgmt_del_argv("Ethernet", "10.90.90.100", platform="win32"),
            ["netsh", "interface", "ipv4", "delete", "address", "Ethernet",
             "10.90.90.100"])


class TestFormatCommand(unittest.TestCase):
    def test_posix_default_has_no_quotes(self):
        self.assertEqual(
            format_command(["ifconfig", "en0", "alias", "10.90.90.100",
                            "255.255.255.0"], platform="linux"),
            "ifconfig en0 alias 10.90.90.100 255.255.255.0")

    def test_posix_quotes_argument_with_space(self):
        self.assertEqual(
            format_command(["ip", "addr", "replace", "a b"], platform="linux"),
            "ip addr replace 'a b'")

    def test_windows_quotes_interface_with_spaces(self):
        self.assertEqual(
            format_command(["netsh", "interface", "ipv4", "add", "address",
                            "Local Area Connection", "10.90.90.100",
                            "255.255.255.0"], platform="win32"),
            'netsh interface ipv4 add address "Local Area Connection" '
            "10.90.90.100 255.255.255.0")


class TestEnsureMgmtAddress(unittest.TestCase):
    def test_present_returns_present_and_no_command(self):
        result = ensure_mgmt_address(
            Config(), _lan("192.168.1.50", "10.90.90.100"))
        self.assertFalse(result.added)
        self.assertEqual(result.detail, "present")
        self.assertIsNone(result.command)

    def test_missing_returns_add_command_without_running(self):
        result = ensure_mgmt_address(Config(), _lan("192.168.1.50"))
        self.assertFalse(result.added)
        self.assertEqual(result.detail, "missing")
        self.assertEqual(result.command,
                         ["ip", "addr", "replace", "10.90.90.100/24",
                          "dev", "eth0"])

    def test_no_lan_is_a_no_op(self):
        result = ensure_mgmt_address(Config(), None)
        self.assertFalse(result.added)
        self.assertIsNone(result.command)

    def test_invalid_mgmt_address_raises(self):
        with self.assertRaises(ValueError):
            ensure_mgmt_address(Config(mgmt_address="8.8.8.8"),
                                _lan("192.168.1.50"))


if __name__ == "__main__":
    unittest.main()
