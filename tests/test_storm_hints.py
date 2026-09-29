import unittest

from netcheck import Config, PingResult, Status, check_storm_hints


class TestStormHints(unittest.TestCase):
    def test_loop_ports_flag_fail(self):
        gateway = PingResult(host="192.168.1.1", transmitted=10, received=10,
                             loss_pct=0.0, min_ms=1.0, avg_ms=5.0, max_ms=40.0)
        result = check_storm_hints(Config(), gateway, loop_ports={"dlink1": [7]},
                                   client_factory=lambda *a, **k: None)
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("dlink1", result.detail)

    def test_clean_passes(self):
        gateway = PingResult(host="192.168.1.1", transmitted=10, received=10,
                             loss_pct=0.0, min_ms=1.0, avg_ms=1.0, max_ms=2.0)
        result = check_storm_hints(Config(), gateway, loop_ports={},
                                   client_factory=lambda *a, **k: None)
        self.assertIs(result.status, Status.PASS)


if __name__ == "__main__":
    unittest.main()
