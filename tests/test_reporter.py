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
        self.assertIn("[FAIL] 6. Rogue DHCP", text)
        self.assertIn("Likely cause: rogue server", text)
        self.assertIn("Suggested fix: unplug it", text)

    def test_render_emits_each_cause(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "A", Status.FAIL, likely_cause="cause one"))
        r.add(CheckResult(2, "B", Status.FAIL, likely_cause="cause two"))
        text = r.render()
        self.assertIn("cause one", text)
        self.assertIn("cause two", text)


if __name__ == "__main__":
    unittest.main()
