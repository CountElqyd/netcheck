# tests/test_storm_measure.py
import unittest

from netcheck import ceil_to_64, compute_threshold, measure_storm_threshold


class FakeCounterClient:
    reads = 0

    def __init__(self, host, community, **kw):
        self.host = host

    def walk(self, base_oid):
        FakeCounterClient.reads += 1
        delta = 0 if FakeCounterClient.reads == 1 else 10_000
        if base_oid == "1.3.6.1.2.1.31.1.1.1.9":
            return [("1.3.6.1.2.1.31.1.1.1.9.1", delta)]
        if base_oid == "1.3.6.1.2.1.31.1.1.1.8":
            return [("1.3.6.1.2.1.31.1.1.1.8.1", 0)]
        return []


class TestStormMeasure(unittest.TestCase):
    def test_ceil_to_64(self):
        self.assertEqual(ceil_to_64(1), 64)
        self.assertEqual(ceil_to_64(64), 64)
        self.assertEqual(ceil_to_64(65), 128)

    def test_compute_threshold_floor_and_cap(self):
        self.assertEqual(compute_threshold(100, 1_000_000), 10000)   # floor
        self.assertEqual(compute_threshold(100_000, 1_000_000), 400000)  # 4x
        self.assertEqual(compute_threshold(900_000, 1_000_000), 800000)  # cap 0.8x

    def test_measure_empty_without_community(self):
        cfg = type("C", (), {"switches": {"dlink1": "10.90.90.90"},
                             "snmp_community": "", "timeout": 1.0,
                             "storm_safety_factor": 4, "storm_floor_kbps": 10000})()
        self.assertEqual(measure_storm_threshold(cfg, sample_seconds=0), {})


if __name__ == "__main__":
    unittest.main()
