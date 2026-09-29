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


if __name__ == "__main__":
    unittest.main()
