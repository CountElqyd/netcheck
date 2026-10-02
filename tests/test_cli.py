import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

import netcheck


class TestCli(unittest.TestCase):
    def test_version_exits_zero(self):
        self.assertEqual(netcheck.main(["--version"]), 0)

    def test_version_value(self):
        self.assertRegex(netcheck.__version__, r"^\d+\.\d+\.\d+$")

    def test_log_writes_color_free_report(self):
        def fake_run_all(cfg, reporter, **kwargs):
            reporter.add(netcheck.CheckResult(
                1, "Local config", netcheck.Status.PASS, detail="ok"))

        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                with mock.patch.object(netcheck, "run_all", fake_run_all), \
                        contextlib.redirect_stdout(stdout), \
                        contextlib.redirect_stderr(io.StringIO()), \
                        mock.patch.object(sys.stdout, "isatty", return_value=True):
                    code = netcheck.main(["--log", "--quick"])
                logs = [f for f in os.listdir(tmp)
                        if f.startswith("netcheck-") and f.endswith(".log")]
                self.assertEqual(len(logs), 1)
                with open(os.path.join(tmp, logs[0])) as fh:
                    report = fh.read()
            finally:
                os.chdir(old_cwd)

        self.assertEqual(code, 0)
        self.assertIn("[PASS]", stdout.getvalue())
        self.assertIn("\033", stdout.getvalue())
        self.assertIn("[PASS]", report)
        self.assertNotIn("\033", report)

    def test_log_does_not_overwrite_same_second_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                stamp = "20260101-000000"
                first = netcheck._log_path(stamp)
                with open(first, "w") as fh:
                    fh.write("first")
                second = netcheck._log_path(stamp)
            finally:
                os.chdir(old_cwd)

        self.assertNotEqual(first, second)
        self.assertEqual(second, "netcheck-20260101-000000-1.log")

    def test_warns_when_default_config_missing(self):
        def fake_run_all(cfg, reporter, **kwargs):
            reporter.add(netcheck.CheckResult(1, "Local config", netcheck.Status.PASS))

        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                with mock.patch.object(netcheck, "run_all", fake_run_all), \
                        contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(stderr):
                    code = netcheck.main(["--quick"])
            finally:
                os.chdir(old_cwd)
        self.assertEqual(code, 0)
        self.assertIn("not found", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
