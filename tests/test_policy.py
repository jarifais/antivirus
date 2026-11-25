import unittest
from miniav.core.models import Finding, ScanResult
from miniav.core.policy import decide, verdict


def result(**changes):
    fields = dict(scan_id="a", path="test", size=10, sha256="",
                  sha1="", md5="", extension=".txt", detected_type="Text/script-like file",
                  entropy=0.0, findings=[], score=0, raw_score=0,
                  verdict="SIN INDICIOS RELEVANTES", yara_matches=[])
    fields.update(changes)
    return ScanResult(**fields)


class PolicyTests(unittest.TestCase):
    def test_clean_only_if_complete(self):
        self.assertEqual(decide(result()).action, "CLEAN")

    def test_error_is_never_clean(self):
        self.assertEqual(decide(result(analysis_complete=False)).action, "ERROR")

    def test_errors_list_is_error(self):
        self.assertEqual(decide(result(errors=["bad"])).action, "ERROR")

    def test_blocking_precedes_parser_error(self):
        f = Finding("BLOCK", "high", 80, "blocked", blocking=True)
        self.assertEqual(decide(result(findings=[f], errors=["bad"])).action, "QUARANTINED")

    def test_score_threshold(self):
        self.assertEqual(decide(result(score=45)).action, "QUARANTINED")

    def test_verdict(self):
        self.assertEqual(verdict(70), "MUY SOSPECHOSO")
