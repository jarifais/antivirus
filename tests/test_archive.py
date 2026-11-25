import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from miniav.core.scanner import scan_file
from miniav.core.policy import decide


def zip_bytes(items):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, payload in items.items():
            z.writestr(name, payload)
    return buf.getvalue()


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def scan(self, items, **limits):
        p = self.root / "test.zip"
        p.write_bytes(zip_bytes(items))
        return scan_file(p, limits, rules_dir=self.root / "none")

    def test_clean_zip(self):
        self.assertEqual(decide(self.scan({"readme.txt": b"hi"})).action, "CLEAN")

    def test_zip_active_member(self):
        self.assertEqual(decide(self.scan({"setup.exe": b"MZ"})).action, "QUARANTINED")

    def test_zip_traversal(self):
        self.assertEqual(decide(self.scan({"../outside.txt": b"hi"})).action, "QUARANTINED")

    def test_zip_limit_fail_closed(self):
        self.assertEqual(decide(self.scan({"large.txt": b"x" * 100},
                                          max_member_bytes=10)).action, "ERROR")
