import unittest

import netcheck


class TestCli(unittest.TestCase):
    def test_version_exits_zero(self):
        self.assertEqual(netcheck.main(["--version"]), 0)

    def test_version_value(self):
        self.assertRegex(netcheck.__version__, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
