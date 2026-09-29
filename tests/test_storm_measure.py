# tests/test_storm_measure.py
import unittest
from unittest import mock

from netcheck import Config, ceil_to_64, compute_threshold, measure_storm_threshold


class FakeCounterClient:
    calls = 0

    def __init__(self, host, community, **kw):
        pass

    def walk(self, base_oid):
        if base_oid == "1.3.6.1.2.1.31.1.1.1.9":
            FakeCounterClient.calls += 1
            value = 100_000 if FakeCounterClient.calls == 1 else 200_000
            return [("1.3.6.1.2.1.31.1.1.1.9.1", value)]
        if base_oid == "1.3.6.1.2.1.31.1.1.1.8":
            return [("1.3.6.1.2.1.31.1.1.1.8.1", 0)]
        return []


class TestStormMeasure(unittest.TestCase):
    def test_ceil_to_64(self):
        self.assertEqual(ceil_to_64(1), 64)
        self.assertEqual(ceil_to_64(64), 64)
        self.assertEqual(ceil_to_64(65), 128)

    def test_compute_threshold_floor_and_cap(self):
        self.assertEqual(compute_threshold(100, 1_000_000), 10000)
        self.assertEqual(compute_threshold(100_000, 1_000_000), 400000)
        self.assertEqual(compute_threshold(900_000, 1_000_000), 800000)

    def test_measure_empty_without_community(self):
        cfg = Config(snmp_community="", switches={"dlink1": "10.90.90.90"})
        self.assertEqual(measure_storm_threshold(cfg, sample_seconds=0), {})

    def test_measure_computes_threshold(self):
        FakeCounterClient.calls = 0
        cfg = Config(snmp_community="public", switches={"dlink1": "10.90.90.90"},
                     storm_safety_factor=4, storm_floor_kbps=10000)
        with mock.patch("netcheck.time.sleep"):
            result = measure_storm_threshold(cfg, sample_seconds=10,
                                             client_factory=FakeCounterClient)
        self.assertEqual(result, {"dlink1": {"threshold": 20480}})


if __name__ == "__main__":
    unittest.main()
