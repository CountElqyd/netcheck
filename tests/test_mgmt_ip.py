import io
import unittest
from unittest import mock

from netcheck import (
    Config,
    InterfaceAddr,
    LanInterface,
    ensure_mgmt_address,
    mgmt_add_argv,
    mgmt_del_argv,
    remove_mgmt_address,
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


class TestEnsureMgmtAddress(unittest.TestCase):
    def test_present_does_not_prompt_or_run(self):
        calls = []
        result = ensure_mgmt_address(
            Config(), _lan("192.168.1.50", "10.90.90.100"),
            tty=io.StringIO("y\n"), runner=lambda *a, **k: calls.append(a) or (0, "", ""))
        self.assertFalse(result.added)
        self.assertEqual(calls, [])

    def test_missing_prompt_yes_adds_and_verifies(self):
        added = _lan("192.168.1.50", "10.90.90.100")
        with mock.patch("netcheck.resolve_lan_interface", return_value=added):
            result = ensure_mgmt_address(
                Config(), _lan("192.168.1.50"),
                tty=io.StringIO("y\n"),
                runner=lambda *a, **k: (0, "", ""))
        self.assertTrue(result.added)
        self.assertEqual(result.address, "10.90.90.100")

    def test_permission_failure_returns_command(self):
        with mock.patch("netcheck.resolve_lan_interface",
                        return_value=_lan("192.168.1.50")):
            result = ensure_mgmt_address(
                Config(), _lan("192.168.1.50"),
                tty=io.StringIO("y\n"),
                runner=lambda *a, **k: (1, "", "Operation not permitted"))
        self.assertFalse(result.added)
        self.assertEqual(result.command,
                         ["ip", "addr", "replace", "10.90.90.100/24", "dev", "eth0"])

    def test_declined_returns_command(self):
        result = ensure_mgmt_address(
            Config(), _lan("192.168.1.50"),
            tty=io.StringIO("n\n"), runner=lambda *a, **k: (0, "", ""))
        self.assertFalse(result.added)
        self.assertIsNotNone(result.command)

    def test_no_fix_returns_command(self):
        result = ensure_mgmt_address(
            Config(), _lan("192.168.1.50"), allow_fix=False,
            tty=io.StringIO("y\n"), runner=lambda *a, **k: (0, "", ""))
        self.assertFalse(result.added)
        self.assertIsNotNone(result.command)

    def test_no_lan_is_a_no_op(self):
        result = ensure_mgmt_address(Config(), None, tty=io.StringIO("y\n"))
        self.assertFalse(result.added)
        self.assertIsNone(result.command)

    def test_invalid_mgmt_address_raises(self):
        with self.assertRaises(ValueError):
            ensure_mgmt_address(Config(mgmt_address="8.8.8.8"), _lan("192.168.1.50"),
                                tty=io.StringIO("y\n"))

    def test_remove_runs_del_argv(self):
        calls = []
        remove_mgmt_address(Config(), "eth0",
                            runner=lambda *a, **k: calls.append(a) or (0, "", ""))
        self.assertEqual(calls[0][0], ["ip", "addr", "del", "10.90.90.100/24",
                                       "dev", "eth0"])


if __name__ == "__main__":
    unittest.main()
