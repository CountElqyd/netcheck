import os
import unittest

ASSETS = ["netcheck.py", "netcheck.ini.example", "USAGE.md"]


class TestReleaseAssets(unittest.TestCase):
    def test_assets_exist(self):
        for asset in ASSETS:
            self.assertTrue(os.path.exists(asset), asset)


if __name__ == "__main__":
    unittest.main()
