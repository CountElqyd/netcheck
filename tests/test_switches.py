import unittest

from netcheck import Config, PingResult, Status, check_switches


def _ping(host, **kw):
    ok = host != "10.90.90.93"
    return PingResult(host=host, transmitted=2, received=2 if ok else 0,
                      loss_pct=0.0 if ok else 100.0)


class TestSwitches(unittest.TestCase):
    def test_one_unreachable_warns(self):
        result = check_switches(Config(), ping_fn=_ping)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("dlink4", result.detail)

    def test_all_reachable_passes(self):
        good = lambda h, **k: PingResult(host=h, transmitted=2, received=2, loss_pct=0.0)
        self.assertIs(check_switches(Config(), ping_fn=good).status, Status.PASS)

    def test_multiple_unreachable_are_newline_separated(self):
        def all_down(host, **kw):
            return PingResult(host=host, transmitted=2, received=0, loss_pct=100.0)
        result = check_switches(Config(), ping_fn=all_down)
        self.assertIn("\n", result.detail)

    def test_cascade_hint_uses_configured_uplink(self):
        cfg = Config(uplink_ports={23, 24, 25, 26, 27},
                     uplink_ports_by_switch={"dlink4": {25}})
        result = check_switches(cfg, ping_fn=_ping)  # dlink4 is down in _ping
        self.assertIn("25", result.detail)
        self.assertNotIn("26", result.detail)


if __name__ == "__main__":
    unittest.main()
