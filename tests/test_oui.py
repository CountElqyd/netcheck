import unittest

from netcheck import lookup_vendor


class TestOui(unittest.TestCase):
    def test_known_vendor(self):
        self.assertEqual(lookup_vendor("00:1e:58:aa:bb:cc"), "D-Link")

    def test_unknown_vendor(self):
        self.assertIsNone(lookup_vendor("02:00:00:00:00:00"))

    def test_case_and_separator_tolerant(self):
        self.assertEqual(lookup_vendor("001E58AABBCC"), "D-Link")


if __name__ == "__main__":
    unittest.main()
