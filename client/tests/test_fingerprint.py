"""Vectors generated with Fingerprint2 2.1.0 under node."""

import unittest

from sdu_connect.fingerprint import DeviceIdentity, murmur_x64_128


VECTORS = [
    ("", "24700f9f1986800ab4fcc880530dd0ed"),
    ("abc", "f04961ae49bab9266bb906b7e9ce9afb"),
    ("hello world", "90c585e5eeae55dd54dea7b1e3d8c113"),
    (
        "userAgent = Chrome\nplatform = MacIntel\n",
        "dfb2baf2bc091005bda9d8370b209789",
    ),
]


class MurmurTest(unittest.TestCase):
    def test_known_vectors(self) -> None:
        for text, expected in VECTORS:
            with self.subTest(text=text):
                self.assertEqual(murmur_x64_128(text.encode("latin-1")), expected)


class DeviceTest(unittest.TestCase):
    def test_stable_across_calls(self) -> None:
        first = DeviceIdentity.generate()
        second = DeviceIdentity.generate()
        self.assertEqual(first.details, second.details)
        self.assertEqual(first.murmur_s, second.murmur_s)
        self.assertNotIn("deviceMemory", first.details)
        self.assertNotIn("screenResolution", first.details)

    def test_roundtrip(self) -> None:
        import tempfile
        from pathlib import Path

        device = DeviceIdentity.generate()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "device.json"
            device.save(path)
            loaded = DeviceIdentity.load(path)
        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.details, device.details)
        self.assertEqual(loaded.murmur_s, device.murmur_s)
        self.assertEqual(loaded.i, device.i)


if __name__ == "__main__":
    unittest.main()
