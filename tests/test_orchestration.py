import io
import unittest

import netcheck


class TestOrchestration(unittest.TestCase):
    def test_quick_runs_only_layer_checks(self):
        reporter = netcheck.Reporter(color=False)
        netcheck.run_all(netcheck.Config(), reporter, quick=True,
                         runner=lambda *a, **k: (0, "", ""))
        self.assertTrue(all(r.id <= 4 for r in reporter.results))
        self.assertGreaterEqual(len(reporter.results), 1)

    def test_parser_has_flags(self):
        parser = netcheck.build_parser()
        args = parser.parse_args(["--quick", "--no-measure", "--no-fix"])
        self.assertTrue(args.quick)
        self.assertTrue(args.no_measure)
        self.assertTrue(args.no_fix)

    def test_main_version(self):
        self.assertEqual(netcheck.main(["--version"]), 0)

    def test_default_config_path(self):
        self.assertEqual(netcheck.build_parser().parse_args([]).config, "netcheck.ini")

    def test_run_all_contains_unexpected_error(self):
        reporter = netcheck.Reporter(color=False)
        original = netcheck.check_switches
        netcheck.check_switches = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            netcheck.run_all(netcheck.Config(), reporter, runner=lambda *a, **k: (0, "", ""))
        finally:
            netcheck.check_switches = original
        self.assertTrue(any(r.id == 98 for r in reporter.results))


if __name__ == "__main__":
    unittest.main()
