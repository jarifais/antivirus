"""Filename spoofing regression cases: all fixtures are only harmless names."""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from miniav.core.filenames import inspect_filename
from miniav.core.policy import decide
from miniav.core.scanner import scan_file
from tests.pe_fixture import make_pe


class FilenameTests(unittest.TestCase):
    def assert_codes(self, name, expected):
        result = inspect_filename(name)
        self.assertIn(expected, {f.code for f in result.findings})
        self.assertTrue(any(f.blocking for f in result.findings
                            if f.code == expected))
        return result

    def test_classic_double_extension(self):
        self.assert_codes("factura.pdf.exe", "DOUBLE_EXTENSION")

    def test_uppercase_doc_script(self):
        self.assert_codes("PAGO.DOCX.PS1", "DOUBLE_EXTENSION")

    def test_dll_after_photo_extension(self):
        self.assert_codes("foto.jpg.dll", "DOUBLE_EXTENSION")

    def test_csv_followed_by_script(self):
        self.assert_codes("datos.csv.cmd", "DOUBLE_EXTENSION")

    def test_fullwidth_dots_and_active_extension(self):
        self.assert_codes("factura\uff0epdf\uff0eexe", "DOUBLE_EXTENSION")

    def test_ideographic_dot(self):
        self.assert_codes("factura\u3002pdf\u3002exe", "DOUBLE_EXTENSION")

    def test_cyrillic_confusable_extension(self):
        result = self.assert_codes("factura.pdf.\u0435\u0445\u0435",
                                   "FILENAME_CONFUSABLE_EXTENSION")
        self.assertEqual(result.effective_suffix, ".exe")

    def test_zero_width_inside_active_extension(self):
        self.assert_codes("factura.pdf.e\u200bxe", "DOUBLE_EXTENSION")

    def test_rlo_control_detected(self):
        self.assert_codes("factura\u202eexe.pdf", "FILENAME_BIDI_CONTROL")

    def test_unicode_isolate_control_detected(self):
        self.assert_codes("factura\u2067.pdf", "FILENAME_BIDI_CONTROL")

    def test_windows_trailing_dot_space(self):
        self.assert_codes("factura.pdf.exe. ", "FILENAME_TRAILING_DOT_SPACE")

    def test_ads_like_filename(self):
        self.assert_codes("nota.txt:payload.exe", "FILENAME_ADS_LIKE")

    def test_neutral_unicode_name_is_not_suspicious(self):
        for name in ("café.pdf", "写真.jpg", "resumen.final.pdf", "backup.tar.gz",
                     "normal.exe", "program.ps1", "readme.txt",
                     "app.v2.exe", "program.1.0.exe"):
            with self.subTest(name=name):
                self.assertEqual(inspect_filename(name).findings, ())

    def test_long_whitespace_gap_is_only_a_review_indicator(self):
        result = inspect_filename("nota.exe" + " " * 20 + ".pdf")
        self.assertTrue(any(f.code == "FILENAME_WHITESPACE_GAP"
                            for f in result.findings))
        self.assertFalse(any(f.blocking for f in result.findings))

    def test_no_paths_are_changed_by_inspection(self):
        name = "documento.pdf.e\u200bxe"
        result = inspect_filename(name)
        self.assertEqual(name, "documento.pdf.e\u200bxe")
        self.assertEqual(result.effective_suffix, ".exe")

    def test_trusted_pe_with_benign_versioned_filename_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "app.v2.exe"
            data = make_pe()
            path.write_bytes(data)
            result = scan_file(path, {
                "trusted_executable_sha256": [hashlib.sha256(data).hexdigest()]
            }, rules_dir=root / "no-yara")
            self.assertEqual(decide(result).action, "CLEAN")
            self.assertFalse(any(f.analyzer == "filenames" for f in result.findings))


    def test_intervening_empty_dots_are_not_allowed(self):
        self.assert_codes("invoice.pdf...exe", "DOUBLE_EXTENSION_OBSCURED")

    def test_document_extension_hidden_by_version(self):
        self.assert_codes("invoice.pdf.v2.exe", "DOUBLE_EXTENSION_OBSCURED")

    def test_document_extension_hidden_by_space_segment(self):
        self.assert_codes("receipt.docx. .cmd", "DOUBLE_EXTENSION_OBSCURED")

    def test_ads_after_active_extension(self):
        self.assert_codes("report.pdf.exe:payload", "FILENAME_ADS_LIKE")

    def test_ads_with_a_legitimate_colon_not_auto_blocked(self):
        result = inspect_filename("appointment:notes.txt")
        self.assertTrue(any(f.code == "FILENAME_ADS_LIKE" for f in result.findings))
        self.assertFalse(any(f.blocking for f in result.findings))

    def test_low_risk_ads_and_controls_stay_below_review_threshold(self):
        # A single colon or tab in an inert filename is not malware proof.
        for name in ("appointment:notes.txt", "notes:\t.txt", "hello\t.txt"):
            with self.subTest(name=name):
                result = inspect_filename(name)
                self.assertLess(sum(f.score for f in result.findings), 20)
                self.assertFalse(any(f.blocking for f in result.findings))
                self.assertTrue(all(f.severity == "low" for f in result.findings))

    def test_hidden_active_extension(self):
        self.assert_codes(".exe", "FILENAME_HIDDEN_ACTIVE")

    def test_control_in_active_extension(self):
        self.assert_codes("invoice.pdf.e\nxe", "FILENAME_UNSAFE_CONTROL")

    def test_whitespace_before_active_extension(self):
        self.assert_codes("program. exe", "FILENAME_EXTENSION_WHITESPACE")

    def test_unrecognized_mixed_unicode_extension_is_review(self):
        result = inspect_filename("invoice.pdf.\u0247xe")
        self.assertIn("FILENAME_MIXED_UNICODE_EXTENSION",
                      {f.code for f in result.findings})
        self.assertFalse(any(f.blocking for f in result.findings))

    def test_unicode_only_extension_is_not_called_executable(self):
        result = inspect_filename("invoice.pdf.日本語")
        self.assertFalse(any(f.code == "FILENAME_CONFUSABLE_EXTENSION"
                             for f in result.findings))
        self.assertFalse(any(f.code == "FILENAME_MIXED_UNICODE_EXTENSION"
                             for f in result.findings))

    def test_neutral_colon_and_controls_are_review_only(self):
        result = inspect_filename("notes:\t.txt")
        self.assertTrue(result.findings)
        self.assertFalse(any(f.blocking for f in result.findings))

    def test_document_chain_with_approved_binary_still_quarantined(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "guide.pdf.version.exe"
            data = make_pe()
            path.write_bytes(data)
            result = scan_file(path, {
                "trusted_executable_sha256": [hashlib.sha256(data).hexdigest()]
            }, rules_dir=root / "no-yara")
            self.assertEqual(decide(result).action, "QUARANTINED")
            self.assertTrue(any(f.code == "DOUBLE_EXTENSION_OBSCURED" for f in result.findings))

    def test_trusted_script_hash_cannot_override_double_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "factura.pdf.ps1"
            data = b"Write-Host Hello"
            path.write_bytes(data)
            result = scan_file(path, {
                "trusted_script_sha256": [hashlib.sha256(data).hexdigest()]
            }, rules_dir=root / "no-yara")
            self.assertEqual(decide(result).action, "QUARANTINED")
            self.assertTrue(any(f.code == "DOUBLE_EXTENSION" for f in result.findings))

    def test_trusted_pe_hash_cannot_override_double_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "factura.pdf.exe"
            data = make_pe()
            path.write_bytes(data)
            result = scan_file(path, {
                "trusted_executable_sha256": [hashlib.sha256(data).hexdigest()]
            }, rules_dir=root / "no-yara")
            self.assertEqual(decide(result).action, "QUARANTINED")
            self.assertTrue(any(f.code == "DOUBLE_EXTENSION" for f in result.findings))

    def test_unicode_decoy_scanner_integration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "factura\uff0epdf\uff0eexe"
            path.write_bytes(b"harmless synthetic text")
            result = scan_file(path, rules_dir=root / "no-yara")
            self.assertEqual(decide(result).action, "QUARANTINED")
            self.assertTrue(any(f.code == "DOUBLE_EXTENSION" for f in result.findings))
