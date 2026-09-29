import unittest

from netcheck import parse_debug_info

SAMPLE = """
ARP Table
IP Address       MAC Address        Port
192.168.1.77     aa-bb-cc-dd-ee-ff  eth1.5
MAC Address Table
VLAN  MAC Address        Port
1     aa-bb-cc-dd-ee-ff  5
1     00-1e-58-00-00-01  23
"""


class TestDebugInfo(unittest.TestCase):
    def test_parse_mac_to_port(self):
        table = parse_debug_info(SAMPLE)
        self.assertEqual(table["AA:BB:CC:DD:EE:FF"], 5)
        self.assertEqual(table["00:1E:58:00:00:01"], 23)

    def test_empty(self):
        self.assertEqual(parse_debug_info("nothing here"), {})


if __name__ == "__main__":
    unittest.main()
