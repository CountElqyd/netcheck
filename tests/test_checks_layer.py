import unittest

from netcheck import (
    Config,
    LocalConfig,
    PingResult,
    Reporter,
    Status,
    check_dns,
    check_gateway,
    check_internet,
    run_layer_checks,
)


def _ping(host, **kw):
    return PingResult(host=host, transmitted=10, received=10, loss_pct=0.0,
                      min_ms=1.0, avg_ms=1.5, max_ms=2.0)


class TestLayerChecks(unittest.TestCase):
    def test_gateway_pass(self):
        self.assertIs(check_gateway(Config(), ping_fn=_ping).status, Status.PASS)

    def test_gateway_fail(self):
        bad = lambda h, **k: PingResult(host=h, transmitted=10, received=0, loss_pct=100.0)
        self.assertIs(check_gateway(Config(), ping_fn=bad).status, Status.FAIL)

    def test_internet_warn_one(self):
        def one(host, **kw):
            ok = host == "1.1.1.1"
            return PingResult(host=host, transmitted=4, received=4 if ok else 0,
                              loss_pct=0.0 if ok else 100.0)
        self.assertIs(check_internet(Config(), ping_fn=one).status, Status.WARN)

    def test_dns_isp_down_public_up(self):
        def q(server, name, **kw):
            return (server in ("1.1.1.1", "8.8.8.8")), 10.0, ["93.184.216.34"]
        result = check_dns(Config(), query_fn=q)
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("ISP DNS", result.likely_cause or "")


def ok_local():
    return LocalConfig(ip="192.168.1.50", gateway="192.168.1.1", dns=["1.1.1.1"])


class TestRunLayerChecks(unittest.TestCase):
    def test_local_fail_stops(self):
        reporter = Reporter(color=False)
        calls = {"ping": 0, "query": 0}

        def pf(host, **kw):
            calls["ping"] += 1
            return PingResult(host=host)

        def qf(*a, **k):
            calls["query"] += 1
            return True, 1.0, ["x"]

        run_layer_checks(Config(), reporter, local_fn=lambda: LocalConfig(ip=None),
                         ping_fn=pf, query_fn=qf)
        self.assertEqual([r.id for r in reporter.results], [1])
        self.assertEqual((calls["ping"], calls["query"]), (0, 0))

    def test_gateway_fail_stops(self):
        reporter = Reporter(color=False)
        calls = {"query": 0}

        def pf(host, **kw):
            return PingResult(host=host, transmitted=10, received=0, loss_pct=100.0)

        def qf(*a, **k):
            calls["query"] += 1
            return True, 1.0, ["x"]

        run_layer_checks(Config(), reporter, local_fn=ok_local, ping_fn=pf, query_fn=qf)
        self.assertEqual([r.id for r in reporter.results], [1, 2])
        self.assertEqual(calls["query"], 0)

    def test_all_pass_runs_all(self):
        reporter = Reporter(color=False)

        def pf(host, **kw):
            return PingResult(host=host, transmitted=10, received=10, loss_pct=0.0,
                              min_ms=1.0, avg_ms=1.5, max_ms=2.0)

        def qf(*a, **k):
            return True, 1.0, ["93.184.216.34"]

        run_layer_checks(Config(), reporter, local_fn=ok_local, ping_fn=pf, query_fn=qf)
        self.assertEqual([r.id for r in reporter.results], [1, 2, 3, 4])


if __name__ == "__main__":
    unittest.main()
