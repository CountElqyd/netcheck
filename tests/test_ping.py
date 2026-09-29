import sys
import unittest
from unittest import mock

from netcheck import parse_ping_output, ping, ping_argv, run_command

LINUX = """PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 1.000/1.500/2.000/0.500 ms
"""

MACOS = """PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=9.1 ms

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 2 packets received, 33.3% packet loss
round-trip min/avg/max/stddev = 9.100/9.500/9.900/0.400 ms
"""

WINDOWS = """
Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=11ms TTL=118

Ping statistics for 8.8.8.8:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
Approximate round trip times in milli-seconds:
    Minimum = 10ms, Maximum = 12ms, Average = 11ms
"""


class TestPing(unittest.TestCase):
    def test_linux(self):
        r = parse_ping_output("192.168.1.1", LINUX)
        self.assertEqual((r.transmitted, r.received), (3, 3))
        self.assertEqual(r.loss_pct, 0.0)
        self.assertEqual(r.avg_ms, 1.5)

    def test_macos_loss(self):
        r = parse_ping_output("1.1.1.1", MACOS)
        self.assertEqual(r.loss_pct, 33.3)
        self.assertEqual(r.max_ms, 9.9)

    def test_windows(self):
        r = parse_ping_output("8.8.8.8", WINDOWS)
        self.assertEqual((r.transmitted, r.received), (4, 3))
        self.assertEqual(r.loss_pct, 25.0)
        self.assertEqual(r.avg_ms, 11.0)

    def test_ping_argv_per_platform(self):
        with mock.patch("sys.platform", "win32"):
            self.assertEqual(ping_argv("8.8.8.8", 3), ["ping", "-n", "3", "8.8.8.8"])
        with mock.patch("sys.platform", "linux"):
            self.assertEqual(ping_argv("8.8.8.8", 3), ["ping", "-c", "3", "8.8.8.8"])
        with mock.patch("sys.platform", "darwin"):
            self.assertEqual(ping_argv("8.8.8.8", 3), ["ping", "-c", "3", "8.8.8.8"])

    def test_ping_uses_injected_runner(self):
        seen = {}

        def fake_runner(args, timeout=10.0):
            seen["args"] = args
            return 0, "3 packets transmitted, 3 received, 0% packet loss", ""

        result = ping("192.168.1.1", count=3, runner=fake_runner)
        self.assertEqual(result.received, 3)
        self.assertIn("192.168.1.1", seen["args"])

    def test_run_command_captures_output(self):
        code, out, _ = run_command([sys.executable, "-c", "print('hi')"])
        self.assertEqual(code, 0)
        self.assertIn("hi", out)


if __name__ == "__main__":
    unittest.main()
