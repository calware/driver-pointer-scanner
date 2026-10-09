"""Focused, read-only tests of KMDF queue callback root discovery."""
import hashlib
import unittest
from pathlib import Path

from scanner import Image
from wdf_probe import discover_wdf_io_control


ROOT = Path(__file__).resolve().parent
INSTALLED_1394 = Path(r"C:\Windows\System32\drivers\1394ohci.sys")


class WdfProbeTests(unittest.TestCase):
    def test_wdm_fixture_is_not_mistaken_for_kmdf(self):
        result = discover_wdf_io_control(ROOT / "fixtures" / "positive-O2.sys")
        self.assertEqual(result["roots_rvas"], [])
        self.assertIn("no_WdfVersionBind_import", result["limitations"])

    @unittest.skipUnless(INSTALLED_1394.exists(), "Windows 1394ohci.sys is absent")
    def test_installed_1394_queue_registration(self):
        before = hashlib.sha256(INSTALLED_1394.read_bytes()).digest()
        image = Image(INSTALLED_1394)
        result = discover_wdf_io_control(image)
        # Independently inspect the three instructions anchoring the claim.
        code = image.instructions(image.base + 0x255f0)
        self.assertIn("[rbp - 1]", code[image.base + 0x2563b].op_str)
        self.assertIn("[rax + 0x4c0]", code[image.base + 0x256aa].op_str)
        self.assertIn("[rbp - 0x29]", code[image.base + 0x25651].op_str)
        registration = next(r for r in result["registrations"] if r["callback_rva"] == "0x15990")
        self.assertEqual(registration["queue_create_call_rva"], "0x256b6")
        self.assertEqual(registration["config_size"], 0x60)
        self.assertTrue(image.executable(image.base + int(registration["callback_rva"], 16)))
        self.assertEqual(before, hashlib.sha256(INSTALLED_1394.read_bytes()).digest())


if __name__ == "__main__":
    unittest.main()
