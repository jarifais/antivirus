import hashlib
import tempfile
import unittest
from pathlib import Path

from miniav.core.pe import inspect_pe
from miniav.core.policy import decide
from miniav.core.scanner import scan_file
from tests.pe_fixture import make_pe


class PETests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def scan(self, data, name="setup.exe", config=None):
        file = self.root / name
        file.write_bytes(data)
        return scan_file(file, config, rules_dir=self.root / "no-yara")

    def test_valid_pe_parser(self):
        file = self.root / "valid.exe"
        file.write_bytes(make_pe())
        pe = inspect_pe(file)
        self.assertEqual(pe.bits, 32)
        self.assertEqual(len(pe.sections), 1)
        self.assertEqual(pe.imports, ())

    def test_unknown_pe_is_retained_not_labeled_malware(self):
        result = self.scan(make_pe())
        self.assertEqual(decide(result).action, "QUARANTINED")
        self.assertTrue(any(f.code == "PE_REVIEW_REQUIRED" for f in result.findings))
        self.assertFalse(any(f.code == "ACTIVE_FILE" for f in result.findings))

    def test_explicitly_approved_hash_passes(self):
        data = make_pe()
        result = self.scan(data, config={
            "trusted_executable_sha256": [hashlib.sha256(data).hexdigest()]})
        self.assertEqual(decide(result).action, "CLEAN")
        self.assertTrue(result.capabilities["trusted_sha256"])

    def test_approved_hash_does_not_override_rwx(self):
        data = make_pe(rwx=True)
        result = self.scan(data, config={
            "trusted_executable_sha256": [hashlib.sha256(data).hexdigest()]})
        self.assertEqual(decide(result).action, "QUARANTINED")
        self.assertTrue(any(f.code == "PE_RWX_SECTION" for f in result.findings))

    def test_malformed_pe_is_error(self):
        result = self.scan(b"MZ" + b"\x00" * 120)
        self.assertEqual(decide(result).action, "ERROR")

    def test_mismatched_extension_is_not_clean(self):
        result = self.scan(make_pe(), name="video.mkv")
        self.assertEqual(decide(result).action, "QUARANTINED")

    def test_disguised_pe_script_extension_stays_blocked_even_if_trusted(self):
        data = make_pe()
        result = self.scan(data, name="update.ps1", config={
            "trusted_executable_sha256": [hashlib.sha256(data).hexdigest()]})
        self.assertEqual(decide(result).action, "QUARANTINED")
        self.assertTrue(any(f.code == "MISMATCH_EXECUTABLE" for f in result.findings))

    def test_double_extension_still_blocks(self):
        data = make_pe()
        result = self.scan(data, name="factura.pdf.exe", config={
            "trusted_executable_sha256": [hashlib.sha256(data).hexdigest()]})
        self.assertEqual(decide(result).action, "QUARANTINED")

    def test_import_parsing(self):
        file = self.root / "imports.exe"
        file.write_bytes(make_pe(import_name="CreateRemoteThread"))
        self.assertIn("KERNEL32.dll!CreateRemoteThread", inspect_pe(file).imports)

    def test_invalid_hash_setting_fails_closed(self):
        result = self.scan(make_pe(), config={"trusted_executable_sha256": ["invalid"]})
        self.assertEqual(decide(result).action, "ERROR")

    def test_non_pe_executable_is_error(self):
        result = self.scan(b"not a PE", name="fake.exe")
        self.assertEqual(decide(result).action, "ERROR")
