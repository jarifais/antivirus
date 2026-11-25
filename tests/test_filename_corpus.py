"""Reproducible synthetic filename corpus; no files are opened or executed."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from miniav.core.filenames import inspect_filename


CORPUS = Path(__file__).parent / "data" / "filename_cases.json"


class FilenameCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(CORPUS.read_text(encoding="utf-8"))
        assert cls.data["schema_version"] == 1

    def test_all_deceptive_cases_have_blocking_findings(self):
        self.assertGreaterEqual(len(self.data["positive"]), 30)
        for example in self.data["positive"]:
            with self.subTest(name=repr(example["name"])):
                result = inspect_filename(example["name"])
                self.assertIn(example["expected_code"],
                              {finding.code for finding in result.findings})
                self.assertTrue(any(finding.blocking for finding in result.findings))

    def test_all_curated_benign_names_remain_below_review(self):
        self.assertGreaterEqual(len(self.data["benign"]), 30)
        for name in self.data["benign"]:
            with self.subTest(name=repr(name)):
                result = inspect_filename(name)
                self.assertFalse(any(f.blocking for f in result.findings))
                self.assertLess(sum(f.score for f in result.findings), 20)

    def test_review_candidates_not_mislabeled_as_blocking_evidence(self):
        for example in self.data["review"]:
            with self.subTest(name=repr(example["name"])):
                result = inspect_filename(example["name"])
                self.assertIn(example["expected_code"],
                              {f.code for f in result.findings})
                self.assertGreaterEqual(sum(f.score for f in result.findings), 20)
                self.assertFalse(any(f.blocking for f in result.findings))
