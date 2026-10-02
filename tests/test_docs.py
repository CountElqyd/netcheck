import os
import unittest

from netcheck import Config, load_config


class TestDocs(unittest.TestCase):
    def test_example_config_exists(self):
        self.assertTrue(
            os.path.exists("netcheck.ini.example"),
            "netcheck.ini.example must exist in the repo root",
        )

    def test_example_config_parses(self):
        cfg = load_config(path="netcheck.ini.example", env={})
        self.assertEqual(cfg.gateway, "192.168.1.1")
        self.assertEqual(len(cfg.switches), 5)
        self.assertEqual(
            list(cfg.switches.values()),
            ["10.90.90.90", "10.90.90.91", "10.90.90.92", "10.90.90.93", "10.90.90.94"],
        )
        # Differs from the built-in default (""), so this only passes when the
        # example file is actually read.
        self.assertEqual(cfg.snmp_community, "netcheck-ro")
        self.assertEqual(cfg.storm_safety_factor, 4)
        self.assertEqual(cfg.storm_floor_kbps, 10000)

    def test_example_config_lists_mgmt_keys(self):
        with open("netcheck.ini.example") as fh:
            text = fh.read()
        self.assertIn("mgmt_address", text)
        self.assertIn("lan_interface", text)


if __name__ == "__main__":
    unittest.main()
