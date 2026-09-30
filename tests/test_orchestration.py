import contextlib
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

    def test_sample_and_timeout_reject_non_positive(self):
        parser = netcheck.build_parser()
        for flag in ("--sample", "--timeout"):
            for value in ("0", "-5"):
                with self.assertRaises(SystemExit) as cm:
                    with contextlib.redirect_stderr(io.StringIO()):
                        parser.parse_args([flag, value])
                self.assertEqual(cm.exception.code, 2)

    def test_sample_and_timeout_accept_positive(self):
        parser = netcheck.build_parser()
        args = parser.parse_args(["--sample", "12.5", "--timeout", "1"])
        self.assertEqual(args.sample, 12.5)
        self.assertEqual(args.timeout, 1.0)

    def test_main_version(self):
        self.assertEqual(netcheck.main(["--version"]), 0)

    def test_default_config_path(self):
        self.assertEqual(netcheck.build_parser().parse_args([]).config, "netcheck.ini")

    def test_failing_check_does_not_stop_later_checks(self):
        reporter = netcheck.Reporter(color=False)
        orig_switches = netcheck.check_switches
        orig_rogue = netcheck.check_rogue_dhcp
        netcheck.check_switches = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("boom"))
        netcheck.check_rogue_dhcp = lambda *a, **k: (
            netcheck.CheckResult(6, "Rogue DHCP", netcheck.Status.PASS, detail="stub"), [])
        try:
            netcheck.run_all(netcheck.Config(), reporter, no_measure=True,
                             runner=lambda *a, **k: (0, "", ""))
        finally:
            netcheck.check_switches = orig_switches
            netcheck.check_rogue_dhcp = orig_rogue
        ids = [r.id for r in reporter.results]
        self.assertIn(5, ids)
        self.assertIn(7, ids)
        self.assertIn(8, ids)
        self.assertIn(9, ids)
        check5 = next(r for r in reporter.results if r.id == 5)
        self.assertIs(check5.status, netcheck.Status.WARN)
        self.assertIn("check failed", check5.detail)
        check7 = next(r for r in reporter.results if r.id == 7)
        self.assertIs(check7.status, netcheck.Status.WARN)

    def test_check7_always_emits_inventory(self):
        reporter = netcheck.Reporter(color=False)
        orig = netcheck.check_device_inventory
        orig_rogue = netcheck.check_rogue_dhcp
        netcheck.check_device_inventory = lambda *a, **k: netcheck.CheckResult(
            7, "Device inventory", netcheck.Status.PASS, detail="0 devices")
        netcheck.check_rogue_dhcp = lambda *a, **k: (
            netcheck.CheckResult(6, "Rogue DHCP", netcheck.Status.PASS, detail="stub"), [])
        try:
            netcheck.run_all(netcheck.Config(), reporter, no_measure=True,
                             runner=lambda *a, **k: (0, "", ""))
        finally:
            netcheck.check_device_inventory = orig
            netcheck.check_rogue_dhcp = orig_rogue
        check7 = [r for r in reporter.results if r.id == 7]
        self.assertEqual(len(check7), 1)
        self.assertIn("Device inventory", check7[0].title)

    def test_outer_handler_reports_internal_error(self):
        reporter = netcheck.Reporter(color=False)
        orig = netcheck.run_layer_checks
        netcheck.run_layer_checks = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("phase-a boom"))
        try:
            netcheck.run_all(netcheck.Config(), reporter,
                             runner=lambda *a, **k: (0, "", ""))
        finally:
            netcheck.run_layer_checks = orig
        self.assertTrue(any(r.id == 98 for r in reporter.results))

    def test_verbose_prints_traceback_only_when_requested(self):
        def run_once(verbose):
            reporter = netcheck.Reporter(color=False)
            stderr = io.StringIO()
            orig = netcheck.run_layer_checks
            netcheck.run_layer_checks = lambda *a, **k: (_ for _ in ()).throw(
                RuntimeError("layer boom"))
            try:
                with contextlib.redirect_stderr(stderr):
                    netcheck.run_all(netcheck.Config(), reporter,
                                     runner=lambda *a, **k: (0, "", ""),
                                     verbose=verbose)
            finally:
                netcheck.run_layer_checks = orig
            return stderr.getvalue(), reporter

        loud, _ = run_once(True)
        quiet, quiet_reporter = run_once(False)
        self.assertIn("Traceback", loud)
        self.assertIn("layer boom", loud)
        self.assertNotIn("Traceback", quiet)
        self.assertTrue(any(r.id == 98 for r in quiet_reporter.results))

    def test_verbose_preamble_reports_effective_config(self):
        reporter = netcheck.Reporter(color=False)
        stderr = io.StringIO()
        orig = netcheck.run_layer_checks
        netcheck.run_layer_checks = lambda *a, **k: None
        try:
            with contextlib.redirect_stderr(stderr):
                netcheck.run_all(netcheck.Config(verbose=True), reporter, quick=True,
                                 runner=lambda *a, **k: (0, "", ""))
        finally:
            netcheck.run_layer_checks = orig
        out = stderr.getvalue()
        self.assertIn("[verbose]", out)
        self.assertIn("gateway=", out)
        self.assertIn("snmp_community=not set", out)
        self.assertNotIn("\033", out)

    def test_no_verbose_emits_no_diagnostics(self):
        reporter = netcheck.Reporter(color=False)
        stderr = io.StringIO()
        orig = netcheck.run_layer_checks
        netcheck.run_layer_checks = lambda *a, **k: None
        try:
            with contextlib.redirect_stderr(stderr):
                netcheck.run_all(netcheck.Config(), reporter, quick=True,
                                 runner=lambda *a, **k: (0, "", ""))
        finally:
            netcheck.run_layer_checks = orig
        self.assertNotIn("[verbose]", stderr.getvalue())

    def test_verbose_traces_swallowed_snmp_error(self):
        def boom(*a, **k):
            raise netcheck.SnmpError("kaboom")

        loud_cfg = netcheck.Config(snmp_community="public", verbose=True,
                                   switches={"dlink1": "10.90.90.90"})
        quiet_cfg = netcheck.Config(snmp_community="public",
                                    switches={"dlink1": "10.90.90.90"})
        loud = io.StringIO()
        quiet = io.StringIO()
        with contextlib.redirect_stderr(loud):
            netcheck.check_hardening(loud_cfg, client_factory=boom)
        with contextlib.redirect_stderr(quiet):
            netcheck.check_hardening(quiet_cfg, client_factory=boom)
        self.assertIn("Traceback", loud.getvalue())
        self.assertIn("kaboom", loud.getvalue())
        self.assertNotIn("Traceback", quiet.getvalue())

    def test_verbose_traces_storm_measure_error(self):
        def boom(*a, **k):
            raise netcheck.SnmpError("storm boom")

        cfg = netcheck.Config(snmp_community="public", verbose=True,
                              switches={"dlink1": "10.90.90.90"})
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = netcheck.measure_storm_threshold(
                cfg, sample_seconds=0.01, client_factory=boom)
        self.assertEqual(result, {})
        self.assertIn("Traceback", stderr.getvalue())
        self.assertIn("storm boom", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
