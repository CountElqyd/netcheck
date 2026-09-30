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

    def test_render_aligns_detail_column(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "A", Status.PASS, detail="one"))
        r.add(CheckResult(2, "Long title here", Status.PASS, detail="two"))
        lines = [ln for ln in r.render().splitlines() if ln.startswith("[PASS]")]
        self.assertEqual(lines[0].index(" - "), lines[1].index(" - "))

    def test_render_aligns_detail_column_with_long_title(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "A", Status.PASS, detail="one"))
        r.add(CheckResult(6, "Trace aa:bb:cc:dd:ee:ff", Status.PASS, detail="two"))
        lines = [ln for ln in r.render().splitlines() if ln.startswith("[PASS]")]
        self.assertEqual(lines[0].index(" - "), lines[1].index(" - "))

    def test_render_placeholders_missing_cause(self):
        r = Reporter(color=False)
        r.add(CheckResult(9, "Hardening audit", Status.WARN, suggested_fix="do x"))
        text = r.render()
        self.assertIn("Likely cause: -", text)
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


if __name__ == "__main__":
    unittest.main()
