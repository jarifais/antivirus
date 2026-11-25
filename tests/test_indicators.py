"""All curated indicator rules are covered by deterministic, harmless fixtures."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from miniav.core.indicators import (
    CATALOG_PATH, IndicatorCatalogError, load_catalog, scan_indicators,
)
from miniav.core.policy import decide
from miniav.core.scanner import scan_file


class IndicatorCatalogTests(unittest.TestCase):
    def test_all_rules_match_expected_synthetic_fixture(self):
        catalog = load_catalog()
        self.assertGreaterEqual(len(catalog["rules"]), 40)
        ids = set()
        for rule in catalog["rules"]:
            self.assertNotIn(rule["id"], ids)
            ids.add(rule["id"])
            tokens = [g[0] for g in rule["groups"]]
            source = (" ".join(tokens) if rule["scope"] == "script" else tuple(tokens))
            with self.subTest(rule=rule["id"]):
                findings = scan_indicators(catalog, rule["scope"], source)
                self.assertIn(rule["id"], {finding.code for finding in findings})

    def test_neutral_inputs_have_no_matches(self):
        catalog = load_catalog()
        self.assertFalse(scan_indicators(catalog, "script", "hello world"))
        self.assertFalse(scan_indicators(catalog, "pe_import", ("kernel32!getlasterror",)))

    def test_catalog_version_fingerprint_is_stable(self):
        catalog = load_catalog()
        self.assertEqual(catalog["sha256"], hashlib.sha256(CATALOG_PATH.read_bytes()).hexdigest())
        self.assertEqual(len(catalog["sha256"]), 64)

    def test_rejects_duplicate_rule_identifiers(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
            catalog["rules"].append(dict(catalog["rules"][0]))
            path.write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaises(IndicatorCatalogError):
                load_catalog(path)

    def test_rejects_unbounded_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            path.write_bytes(b"x" * 131073)
            with self.assertRaises(IndicatorCatalogError):
                load_catalog(path)

    def test_rejects_unsupported_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
            catalog["schema_version"] = 2
            path.write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaises(IndicatorCatalogError):
                load_catalog(path)

    def test_detection_scans_script_without_yara(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "sample.ps1"
            path.write_text("Set-MpPreference -DisableRealtimeMonitoring $true", encoding="utf-8")
            result = scan_file(path, rules_dir=root / "no-yara")
            codes = {finding.code for finding in result.findings}
            self.assertIn("SC_DEFENDER_DISABLE", codes)
            self.assertEqual(decide(result).action, "QUARANTINED")
            self.assertEqual(result.capabilities["indicator_catalog"]["version"], "2026.11.25.1")

    def test_plain_script_not_automatically_malware(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "hello.ps1"
            path.write_text("Write-Host Hello", encoding="utf-8")
            result = scan_file(path, rules_dir=root / "no-yara")
            codes = {finding.code for finding in result.findings}
            self.assertEqual(codes, {"SCRIPT_REVIEW_REQUIRED"})
            self.assertEqual(decide(result).action, "QUARANTINED")

    def test_strong_indicator_overrides_hash_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"Set-MpPreference -DisableRealtimeMonitoring $true"
            path = root / "override.ps1"
            path.write_bytes(data)
            result = scan_file(path, {
                "trusted_script_sha256": [hashlib.sha256(data).hexdigest()],
            }, rules_dir=root / "no-yara")
            self.assertEqual(decide(result).action, "QUARANTINED")
            self.assertIn("SC_DEFENDER_DISABLE", {f.code for f in result.findings})

    def test_exact_import_matching_avoids_substring_confusions(self):
        catalog = load_catalog()
        findings = scan_indicators(catalog, "pe_import",
            ("kernel32!notcreateremotethread", "kernel32!writeprocessmemory"))
        self.assertNotIn("PE_REMOTE_THREAD", {f.code for f in findings})

    def test_malformed_rule_rejected_before_scanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            obj = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
            obj["rules"][0]["groups"] = [[""]]
            path.write_text(json.dumps(obj), encoding="utf-8")
            with self.assertRaises(IndicatorCatalogError):
                load_catalog(path)
