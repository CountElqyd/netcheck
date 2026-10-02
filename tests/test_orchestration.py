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
        args = parser.parse_args(["--quick", "--hardening"])
        self.assertTrue(args.quick)
        self.assertTrue(args.hardening)

    def test_sample_defaults_to_none(self):
        self.assertIsNone(netcheck.build_parser().parse_args([]).sample)

    def test_hardening_defaults_off(self):
        self.assertFalse(netcheck.build_parser().parse_args([]).hardening)

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
            netcheck.run_all(netcheck.Config(), reporter, hardening=True,
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

    def test_check9_absent_by_default(self):
        reporter = netcheck.Reporter(color=False)
        orig_rogue = netcheck.check_rogue_dhcp
        netcheck.check_rogue_dhcp = lambda *a, **k: (
            netcheck.CheckResult(6, "Rogue DHCP", netcheck.Status.PASS, detail="stub"), [])
        try:
            netcheck.run_all(netcheck.Config(), reporter,
                             runner=lambda *a, **k: (0, "", ""))
        finally:
            netcheck.check_rogue_dhcp = orig_rogue
        self.assertNotIn(9, [r.id for r in reporter.results])

    def test_sample_emits_threshold_check(self):
        reporter = netcheck.Reporter(color=False)
        orig_measure = netcheck.measure_storm_threshold
        orig_rogue = netcheck.check_rogue_dhcp
        netcheck.measure_storm_threshold = lambda cfg, sample_seconds=0, **k: {
            "dlink1": {"threshold": 20032}}
        netcheck.check_rogue_dhcp = lambda *a, **k: (
            netcheck.CheckResult(6, "Rogue DHCP", netcheck.Status.PASS, detail="stub"), [])
        try:
            netcheck.run_all(netcheck.Config(), reporter, sample=0.01,
                             runner=lambda *a, **k: (0, "", ""))
        finally:
            netcheck.measure_storm_threshold = orig_measure
            netcheck.check_rogue_dhcp = orig_rogue
        check10 = [r for r in reporter.results if r.id == 10]
        self.assertEqual(len(check10), 1)
        self.assertIn("N=313", check10[0].detail)

    def test_check7_always_emits_inventory(self):
        reporter = netcheck.Reporter(color=False)
        orig = netcheck.check_device_inventory
        orig_rogue = netcheck.check_rogue_dhcp
        netcheck.check_device_inventory = lambda *a, **k: netcheck.CheckResult(
            7, "Device inventory", netcheck.Status.PASS, detail="0 devices")
        netcheck.check_rogue_dhcp = lambda *a, **k: (
            netcheck.CheckResult(6, "Rogue DHCP", netcheck.Status.PASS, detail="stub"), [])
        try:
            netcheck.run_all(netcheck.Config(), reporter,
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
            netcheck.check_device_inventory(loud_cfg, [], client_factory=boom)
        with contextlib.redirect_stderr(quiet):
            netcheck.check_device_inventory(quiet_cfg, [], client_factory=boom)
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

    def test_parser_has_remove_mgmt_ip(self):
        self.assertFalse(netcheck.build_parser().parse_args([]).remove_mgmt_ip)
        self.assertTrue(
            netcheck.build_parser().parse_args(["--remove-mgmt-ip"]).remove_mgmt_ip)

    def test_run_all_sources_pings_from_management_address(self):
        lan = netcheck.LanInterface(
            "eth0", "192.168.1.50",
            [netcheck.InterfaceAddr("192.168.1.50", 24),
             netcheck.InterfaceAddr("10.90.90.100", 24)])
        seen = []

        def runner(args, timeout=10.0):
            seen.append(list(args))
            return 0, "", ""

        reporter = netcheck.Reporter(color=False)
        orig_resolve = netcheck.resolve_lan_interface
        orig_rogue = netcheck.check_rogue_dhcp
        netcheck.resolve_lan_interface = lambda *a, **k: lan
        netcheck.check_rogue_dhcp = lambda *a, **k: (
            netcheck.CheckResult(6, "Rogue DHCP", netcheck.Status.PASS, detail="stub"), [])
        try:
            netcheck.run_all(netcheck.Config(), reporter, runner=runner)
        finally:
            netcheck.resolve_lan_interface = orig_resolve
            netcheck.check_rogue_dhcp = orig_rogue
        pings = [a for a in seen if a and a[0] == "ping"]
        self.assertTrue(any("10.90.90.100" in a for a in pings))

    def test_run_all_stops_before_switch_checks_when_mgmt_missing(self):
        lan = netcheck.LanInterface(
            "eth0", "192.168.1.50", [netcheck.InterfaceAddr("192.168.1.50", 24)])
        reporter = netcheck.Reporter(color=False)
        orig_resolve = netcheck.resolve_lan_interface
        netcheck.resolve_lan_interface = lambda *a, **k: lan
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                netcheck.run_all(netcheck.Config(), reporter,
                                 runner=lambda *a, **k: (0, "", ""))
        finally:
            netcheck.resolve_lan_interface = orig_resolve
        ids = [r.id for r in reporter.results]
        self.assertNotIn(6, ids)
        check5 = next(r for r in reporter.results if r.id == 5)
        self.assertIs(check5.status, netcheck.Status.WARN)
        self.assertIn("not run", check5.detail)

    def test_run_all_runs_checks_in_numeric_order(self):
        lan = netcheck.LanInterface(
            "eth0", "192.168.1.50",
            [netcheck.InterfaceAddr("192.168.1.50", 24),
             netcheck.InterfaceAddr("10.90.90.100", 24)])
        reporter = netcheck.Reporter(color=False)
        orig = {name: getattr(netcheck, name) for name in (
            "resolve_lan_interface", "run_layer_checks", "check_switches",
            "check_rogue_dhcp", "check_device_inventory", "check_storm_hints")}

        def layer(cfg, rep, **k):
            for i in (1, 2, 3, 4):
                rep.add(netcheck.CheckResult(i, f"c{i}", netcheck.Status.PASS))

        netcheck.resolve_lan_interface = lambda *a, **k: lan
        netcheck.run_layer_checks = layer
        netcheck.check_switches = lambda *a, **k: netcheck.CheckResult(
            5, "Switches", netcheck.Status.PASS, detail="stub")
        netcheck.check_rogue_dhcp = lambda *a, **k: (
            netcheck.CheckResult(6, "Rogue DHCP", netcheck.Status.PASS,
                                 detail="stub"), [])
        netcheck.check_device_inventory = lambda *a, **k: netcheck.CheckResult(
            7, "Device inventory", netcheck.Status.PASS, detail="stub")
        netcheck.check_storm_hints = lambda *a, **k: netcheck.CheckResult(
            8, "Loop/storm hints", netcheck.Status.PASS, detail="stub")
        try:
            netcheck.run_all(netcheck.Config(), reporter,
                             runner=lambda *a, **k: (0, "", ""))
        finally:
            for name, fn in orig.items():
                setattr(netcheck, name, fn)
        self.assertEqual([r.id for r in reporter.results], [1, 2, 3, 4, 5, 6, 7, 8])

    def test_main_rejects_invalid_gateway(self):
        stderr = io.StringIO()
        orig_load = netcheck.load_config
        orig_resolve = netcheck.resolve_lan_interface
        netcheck.load_config = lambda *a, **k: netcheck.Config(gateway="foo")
        netcheck.resolve_lan_interface = lambda *a, **k: None
        try:
            with contextlib.redirect_stderr(stderr):
                code = netcheck.main(["--remove-mgmt-ip"])
        finally:
            netcheck.load_config = orig_load
            netcheck.resolve_lan_interface = orig_resolve
        self.assertEqual(code, 2)
        self.assertIn("invalid gateway", stderr.getvalue())

    def test_main_rejects_blank_gateway(self):
        stderr = io.StringIO()
        orig_load = netcheck.load_config
        orig_resolve = netcheck.resolve_lan_interface
        netcheck.load_config = lambda *a, **k: netcheck.Config(gateway="")
        netcheck.resolve_lan_interface = lambda *a, **k: None
        try:
            with contextlib.redirect_stderr(stderr):
                code = netcheck.main([])
        finally:
            netcheck.load_config = orig_load
            netcheck.resolve_lan_interface = orig_resolve
        self.assertEqual(code, 2)
        self.assertIn("invalid gateway", stderr.getvalue())

    def test_main_remove_mgmt_ip_reports_removal(self):
        present = netcheck.LanInterface(
            "eth0", "192.168.1.50",
            [netcheck.InterfaceAddr("192.168.1.50", 24),
             netcheck.InterfaceAddr("10.90.90.100", 24)])
        absent = netcheck.LanInterface(
            "eth0", "192.168.1.50",
            [netcheck.InterfaceAddr("192.168.1.50", 24)])
        state = {"removed": False}
        calls = []

        def resolve(*a, **k):
            return absent if state["removed"] else present

        def remove(cfg, iface, **k):
            calls.append(iface)
            state["removed"] = True

        orig_load = netcheck.load_config
        orig_resolve = netcheck.resolve_lan_interface
        orig_remove = netcheck.remove_mgmt_address
        netcheck.load_config = lambda *a, **k: netcheck.Config()
        netcheck.resolve_lan_interface = resolve
        netcheck.remove_mgmt_address = remove
        stdout = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout):
                code = netcheck.main(["--remove-mgmt-ip"])
        finally:
            netcheck.load_config = orig_load
            netcheck.resolve_lan_interface = orig_resolve
            netcheck.remove_mgmt_address = orig_remove
        self.assertEqual(code, 0)
        self.assertEqual(calls, ["eth0"])
        self.assertIn("removed 10.90.90.100/24 from eth0", stdout.getvalue())

    def test_main_remove_mgmt_ip_fails_when_address_still_present(self):
        present = netcheck.LanInterface(
            "eth0", "192.168.1.50",
            [netcheck.InterfaceAddr("192.168.1.50", 24),
             netcheck.InterfaceAddr("10.90.90.100", 24)])
        orig_load = netcheck.load_config
        orig_resolve = netcheck.resolve_lan_interface
        orig_remove = netcheck.remove_mgmt_address
        netcheck.load_config = lambda *a, **k: netcheck.Config()
        netcheck.resolve_lan_interface = lambda *a, **k: present
        netcheck.remove_mgmt_address = lambda *a, **k: None
        stderr = io.StringIO()
        try:
            with contextlib.redirect_stderr(stderr):
                code = netcheck.main(["--remove-mgmt-ip"])
        finally:
            netcheck.load_config = orig_load
            netcheck.resolve_lan_interface = orig_resolve
            netcheck.remove_mgmt_address = orig_remove
        self.assertEqual(code, 1)
        self.assertIn("could not remove", stderr.getvalue())

    def test_verbose_marks_each_layer_check(self):
        reporter = netcheck.Reporter(color=False)
        stderr = io.StringIO()
        local = netcheck.LocalConfig(ip="192.168.1.50",
                                     gateway="192.168.1.1", dns=["1.1.1.1"])
        ping_ok = lambda h, **k: netcheck.PingResult(
            host=h, transmitted=10, received=10, loss_pct=0.0,
            min_ms=1.0, avg_ms=1.0, max_ms=1.0)
        query_ok = lambda s, n, **k: (True, 1.0, ["1.2.3.4"])
        with contextlib.redirect_stderr(stderr):
            netcheck.run_layer_checks(netcheck.Config(verbose=True), reporter,
                                      local_fn=lambda: local,
                                      ping_fn=ping_ok, query_fn=query_ok)
        out = stderr.getvalue()
        for n in (1, 2, 3, 4):
            self.assertIn(f"starting check {n}", out)
            self.assertIn(f"check {n} done", out)


if __name__ == "__main__":
    unittest.main()
