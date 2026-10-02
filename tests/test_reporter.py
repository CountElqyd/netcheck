import unittest

from netcheck import CheckResult, Reporter, Status


class TestReporter(unittest.TestCase):
    def test_exit_code_no_fail(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "Local config", Status.PASS, detail="ok"))
        r.add(CheckResult(2, "Gateway", Status.WARN, detail="loss"))
        self.assertEqual(r.exit_code(), 1)

    def test_exit_code_fail_wins(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "Local config", Status.WARN))
        r.add(CheckResult(2, "Gateway", Status.FAIL))
        self.assertEqual(r.exit_code(), 2)

    def test_render_contains_lines_and_fix(self):
        r = Reporter(color=False)
        r.add(CheckResult(6, "Rogue DHCP", Status.FAIL, detail="192.168.1.77",
                          likely_cause="rogue server", suggested_fix="unplug it"))
        text = r.render()
        self.assertIn("[FAIL]", text)
        self.assertIn("6. Rogue DHCP", text)
        self.assertIn("Likely cause: rogue server", text)
        self.assertIn("Suggested fix: unplug it", text)

    def test_render_has_legend_and_summary(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "Local config", Status.PASS, detail="ok"))
        r.add(CheckResult(2, "Gateway", Status.WARN, detail="loss"))
        r.add(CheckResult(3, "Internet by IP", Status.FAIL, detail="down"))
        text = r.render()
        self.assertIn("Legend:", text)
        self.assertIn("1 PASS", text)
        self.assertIn("1 WARN", text)
        self.assertIn("1 FAIL", text)
        self.assertIn("exit code 2", text)

    def test_render_detail_on_its_own_indented_line(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "A", Status.PASS, detail="one"))
        lines = r.render().splitlines()
        self.assertTrue(lines[0].startswith("[PASS]  1. A"))
        self.assertEqual(lines[1], "      one")

    def test_render_title_no_trailing_space(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "A", Status.PASS, detail="one"))
        r.add(CheckResult(2, "Long title here", Status.PASS, detail="two"))
        heads = [ln for ln in r.render().splitlines() if ln.startswith("[PASS]")]
        self.assertEqual(heads[0], "[PASS]  1. A")
        self.assertEqual(heads[1], "[PASS]  2. Long title here")

    def test_render_omits_placeholder_lines(self):
        r = Reporter(color=False)
        r.add(CheckResult(9, "Hardening audit", Status.WARN, suggested_fix="do x"))
        text = r.render()
        self.assertNotIn("Likely cause: -", text)
        self.assertIn("Suggested fix: do x", text)

    def test_render_omits_cause_block_when_absent(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "Local config", Status.PASS, detail="ok"))
        text = r.render()
        self.assertNotIn("Likely cause:", text)
        self.assertNotIn("Suggested fix:", text)

    def test_render_emits_each_cause(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "A", Status.FAIL, likely_cause="cause one"))
        r.add(CheckResult(2, "B", Status.FAIL, likely_cause="cause two"))
        text = r.render()
        self.assertIn("cause one", text)
        self.assertIn("cause two", text)

    def test_render_color_override(self):
        r = Reporter(color=True)
        r.add(CheckResult(1, "Local config", Status.PASS, detail="ok"))
        self.assertIn("\033", r.render())
        self.assertNotIn("\033", r.render(color=False))

    def test_render_default_follows_reporter_color(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "Local config", Status.PASS, detail="ok"))
        self.assertNotIn("\033", r.render())
        self.assertIn("\033", r.render(color=True))

    def test_quiet_only_summary(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "Local config", Status.PASS, detail="ok"))
        r.add(CheckResult(2, "Gateway", Status.WARN, detail="loss"))
        text = r.render(quiet=True)
        self.assertNotIn("Local config", text)
        self.assertNotIn("Legend:", text)
        self.assertIn("Summary:", text)

    def test_to_dict_schema(self):
        r = Reporter(color=False)
        r.add(CheckResult(6, "Rogue DHCP", Status.FAIL, detail="x",
                          likely_cause="c", suggested_fix="f"))
        d = r.to_dict()
        self.assertEqual(d["exit_code"], 2)
        self.assertEqual(d["summary"]["FAIL"], 1)
        self.assertEqual(len(d["checks"]), 1)
        self.assertEqual(d["checks"][0]["status"], "FAIL")
        self.assertEqual(d["checks"][0]["title"], "Rogue DHCP")
        self.assertEqual(d["checks"][0]["suggested_fix"], "f")

    def test_long_detail_wraps(self):
        r = Reporter(color=False)
        r.add(CheckResult(7, "Device inventory", Status.PASS, detail="word " * 80))
        lines = r.render().splitlines()
        self.assertTrue(all(len(ln) <= 100 for ln in lines))
        self.assertGreater(len([ln for ln in lines if ln.startswith("      ")]), 1)

    def test_render_preserves_detail_newlines(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "A", Status.PASS, detail="first\nsecond"))
        lines = r.render().splitlines()
        self.assertEqual(lines[1], "      first")
        self.assertEqual(lines[2], "      second")

    def test_render_indents_each_block_line(self):
        r = Reporter(color=False)
        r.add(CheckResult(7, "Device inventory", Status.PASS,
                          detail="2 end devices\ndlink1\n    port 5  AA:BB"))
        text = r.render()
        self.assertIn("\n      dlink1", text)
        self.assertIn("\n          port 5  AA:BB", text)

    def test_multiline_cause_labels_once_and_aligns(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "A", Status.FAIL,
                          likely_cause="first line\nsecond line"))
        lines = r.render().splitlines()
        causes = [ln for ln in lines if "Likely cause:" in ln]
        self.assertEqual(len(causes), 1)
        idx = lines.index("      Likely cause: first line")
        self.assertEqual(lines[idx + 1], " " * 20 + "second line")

    def test_body_indent_matches_between_detail_and_cause(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "A", Status.FAIL, detail="one",
                          likely_cause="cause"))
        lines = r.render().splitlines()
        self.assertEqual(lines[1], "      one")
        self.assertEqual(lines[2], "      Likely cause: cause")

    def test_render_splits_cause_at_semicolons(self):
        r = Reporter(color=False)
        r.add(CheckResult(3, "Internet", Status.FAIL,
                          suggested_fix="check the router; retry later"))
        lines = r.render().splitlines()
        self.assertIn("      Suggested fix: check the router", lines)
        self.assertIn(" " * 21 + "retry later", lines)

    def test_command_renders_verbatim_at_body_indent(self):
        cmd = "sudo ip addr replace 10.90.90.100/24 dev eth0"
        r = Reporter(color=False)
        r.add(CheckResult(5, "Switches", Status.WARN,
                          suggested_fix="Add it:", command=cmd))
        lines = r.render().splitlines()
        self.assertIn("      Suggested fix: Add it:", lines)
        self.assertIn("      " + cmd, lines)

    def test_command_is_not_wrapped_even_when_long(self):
        cmd = "sudo ip addr replace 10.90.90.100/24 dev eth0 " + "x" * 80
        r = Reporter(color=False)
        r.add(CheckResult(5, "Switches", Status.WARN, command=cmd))
        self.assertIn("      " + cmd, r.render().splitlines())

    def test_command_multiline_renders_each_verbatim(self):
        r = Reporter(color=False)
        r.add(CheckResult(6, "Rogue DHCP", Status.WARN,
                          command="first cmd\nsecond cmd"))
        lines = r.render().splitlines()
        self.assertIn("      first cmd", lines)
        self.assertIn("      second cmd", lines)

    def test_command_omitted_from_quiet(self):
        r = Reporter(color=False)
        r.add(CheckResult(5, "Switches", Status.WARN, command="run me"))
        self.assertNotIn("run me", r.render(quiet=True))

    def test_to_dict_includes_command(self):
        r = Reporter(color=False)
        r.add(CheckResult(5, "Switches", Status.WARN, command="run me"))
        self.assertEqual(r.to_dict()["checks"][0]["command"], "run me")

    def test_placeholder_renders_command_between_prose(self):
        r = Reporter(color=False)
        r.add(CheckResult(6, "Rogue DHCP", Status.FAIL,
                          suggested_fix="First, find the port:\n{command}\nThen unplug.",
                          command="uv run --with scapy netcheck.py --inventory"))
        lines = r.render().splitlines()
        self.assertIn("      Suggested fix: First, find the port:", lines)
        self.assertIn("      uv run --with scapy netcheck.py --inventory", lines)
        self.assertIn("      Then unplug.", lines)

    def test_placeholder_command_is_not_wrapped(self):
        cmd = "uv run --with scapy netcheck.py --inventory " + "x" * 80
        r = Reporter(color=False)
        r.add(CheckResult(6, "Rogue DHCP", Status.FAIL,
                          suggested_fix="Find it:\n{command}\nThen unplug.", command=cmd))
        self.assertIn("      " + cmd, r.render().splitlines())

    def test_to_dict_substitutes_command_placeholder(self):
        r = Reporter(color=False)
        r.add(CheckResult(6, "Rogue DHCP", Status.FAIL,
                          suggested_fix="run:\n{command}", command="do it"))
        check = r.to_dict()["checks"][0]
        self.assertNotIn("{command}", check["suggested_fix"])
        self.assertIn("do it", check["suggested_fix"])
        self.assertEqual(check["command"], "do it")

    def test_footer_describes_optin_checks(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "Local config", Status.PASS, detail="ok"))
        text = r.render()
        self.assertIn("Deeper opt-in checks:", text)
        self.assertIn("--inventory", text)
        self.assertIn("--hardening", text)
        self.assertIn("--sample N", text)

    def test_footer_hidden_when_optin_check_ran(self):
        r = Reporter(color=False)
        r.add(CheckResult(8, "Device inventory", Status.PASS, detail="ok"))
        self.assertNotIn("Deeper opt-in checks:", r.render())

    def test_footer_hidden_in_quiet(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "Local config", Status.PASS, detail="ok"))
        self.assertNotIn("Deeper opt-in checks:", r.render(quiet=True))

    def test_footer_recommends_inventory_when_rogue(self):
        r = Reporter(color=False)
        r.add(CheckResult(6, "Rogue DHCP", Status.FAIL, detail="x"))
        self.assertIn("Rogue DHCP found: run --inventory", r.render())

    def test_footer_omits_rogue_line_when_no_rogue(self):
        r = Reporter(color=False)
        r.add(CheckResult(6, "Rogue DHCP", Status.PASS, detail="ok"))
        self.assertNotIn("Rogue DHCP found", r.render())

    def test_tags_and_titles_align(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "A", Status.PASS, detail="x"))
        r.add(CheckResult(2, "Long title here", Status.WARN, detail="y"))
        r.add(CheckResult(3, "B", Status.FAIL, detail="z"))
        heads = [ln for ln in r.render().splitlines() if ln.startswith("[")]
        starts = [ln.index(". ") + 2 for ln in heads]
        self.assertEqual(len(set(starts)), 1)


if __name__ == "__main__":
    unittest.main()
