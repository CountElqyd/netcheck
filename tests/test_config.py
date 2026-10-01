import os
import tempfile
import unittest

from netcheck import Config, load_config


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = load_config(env={})
        self.assertEqual(cfg.gateway, "192.168.1.1")
        self.assertEqual(cfg.switches["dlink1"], "10.90.90.90")
        self.assertEqual(cfg.switches["dlink5"], "10.90.90.94")
        self.assertEqual(cfg.storm_safety_factor, 4)
        self.assertEqual(cfg.storm_floor_kbps, 10000)
        self.assertEqual(cfg.uplink_ports, {23, 24, 25, 26, 27})
        self.assertEqual(cfg.uplink_ports_by_switch, {})

    def test_env_overrides(self):
        cfg = load_config(env={"NETCHECK_SNMP_COMMUNITY": "ro", "NETCHECK_GATEWAY": "10.0.0.1"})
        self.assertEqual(cfg.snmp_community, "ro")
        self.assertEqual(cfg.gateway, "10.0.0.1")

    def test_ini_then_env_precedence(self):
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as fh:
            fh.write("[netcheck]\ngateway = 172.16.0.1\nsnmp_community = filecomm\n")
            path = fh.name
        try:
            cfg = load_config(path=path, env={"NETCHECK_SNMP_COMMUNITY": "envcomm"})
            self.assertEqual(cfg.gateway, "172.16.0.1")          # file wins over default
            self.assertEqual(cfg.snmp_community, "envcomm")      # env wins over file
        finally:
            os.unlink(path)

    def test_malformed_switches_ignored(self):
        cfg = load_config(env={"NETCHECK_SWITCHES": "dlink1=10.0.0.1,bad,"})
        self.assertEqual(cfg.switches, {"dlink1": "10.0.0.1"})

    def test_non_numeric_storm_uses_default(self):
        cfg = load_config(env={"NETCHECK_STORM_SAFETY_FACTOR": "abc"})
        self.assertEqual(cfg.storm_safety_factor, 4)

    def test_repr_hides_secrets(self):
        cfg = load_config(env={"NETCHECK_SNMP_COMMUNITY": "s3cret",
                               "NETCHECK_SWITCH_PASS": "hunter2"})
        text = repr(cfg)
        self.assertNotIn("s3cret", text)
        self.assertNotIn("hunter2", text)

    def test_uplink_ports_env(self):
        cfg = load_config(env={"NETCHECK_UPLINK_PORTS": "23-27,dlink2:24-25"})
        self.assertEqual(cfg.uplink_ports, {23, 24, 25, 26, 27})
        self.assertEqual(cfg.uplink_ports_by_switch, {"dlink2": {24, 25}})

    def test_uplink_ports_ini(self):
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as fh:
            fh.write("[netcheck]\nuplink_ports = 1-2\n")
            path = fh.name
        try:
            cfg = load_config(path=path, env={})
            self.assertEqual(cfg.uplink_ports, {1, 2})
        finally:
            os.unlink(path)

    def test_uplink_ports_spoke_layout(self):
        spec = "23-27,dlink2:24,dlink3:25,dlink4:25,dlink5:25"
        cfg = load_config(env={"NETCHECK_UPLINK_PORTS": spec})
        self.assertEqual(cfg.uplink_ports, {23, 24, 25, 26, 27})
        self.assertEqual(cfg.uplink_ports_by_switch,
                         {"dlink2": {24}, "dlink3": {25}, "dlink4": {25},
                          "dlink5": {25}})


if __name__ == "__main__":
    unittest.main()
