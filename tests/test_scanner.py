import tempfile
import unittest
from pathlib import Path
from miniav.core.scanner import scan_file
from miniav.core.policy import decide


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def scan(self, name, data):
        p = self.root / name
        p.write_bytes(data)
        result = scan_file(p, rules_dir=self.root / "missing_rules")
        return result, decide(result)

    def test_text_is_clean(self):
        result, policy = self.scan("readme.txt", b"hello, static analysis")
        self.assertEqual(policy.action, "CLEAN")
        self.assertEqual(len(result.sha256), 64)

    def test_double_extension_is_quarantined(self):
        result, policy = self.scan("factura.pdf.exe", b"MZ" + b"\0" * 120)
        self.assertEqual(policy.action, "QUARANTINED")
        self.assertTrue(any(f.blocking for f in result.findings))

    def test_ordinary_executable_is_quarantined(self):
        _, policy = self.scan("setup.exe", b"MZ" + b"\0" * 120)
        self.assertEqual(policy.action, "QUARANTINED")

    def test_corrupt_zip_is_error(self):
        _, policy = self.scan("broken.zip", b"not actually a zip")
        self.assertEqual(policy.action, "ERROR")

    def test_ebml_clean(self):
        _, policy = self.scan("movie.mkv", b"\x1aE\xdf\xa3" + b"\0" * 100)
        self.assertEqual(policy.action, "CLEAN")

    def test_encoded_script_quarantined(self):
        _, policy = self.scan("launch.ps1", b"powershell -EncodedCommand AAA")
        self.assertEqual(policy.action, "QUARANTINED")

    def test_missing_file_is_error(self):
        result = scan_file(self.root / "missing")
        self.assertEqual(decide(result).action, "ERROR")
