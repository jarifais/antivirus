import tempfile
import unittest
from pathlib import Path
from miniav.config import DEFAULT_CONFIG, default_pipeline_paths, validate_config
from miniav.pipeline import process_one
from miniav.state import StateDB


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        incoming = self.root / "Incoming"
        incoming.mkdir()
        self.cfg = {**DEFAULT_CONFIG, "incoming_dir": str(incoming),
                    **default_pipeline_paths(incoming)}
        self.roles = validate_config(self.cfg, create_outputs=True)
        self.db = StateDB(self.root / "state.sqlite3")
        self.addCleanup(self.db.close)

    def run_file(self, name, data):
        source = self.roles["incoming_dir"] / name
        source.write_bytes(data)
        return process_one(source, self.roles, self.cfg, self.db, self.root / "reports")

    def test_clean_handoff(self):
        job = self.run_file("safe.txt", b"hello")
        self.assertEqual(job.state, "CLEAN")
        self.assertTrue(Path(job.target_path).exists())

    def test_suspicious_handoff(self):
        job = self.run_file("factura.pdf.exe", b"MZ" + b"\0" * 40)
        self.assertEqual(job.state, "QUARANTINED")
        self.assertFalse(list(self.roles["clean_dir"].iterdir()))

    def test_error_handoff(self):
        job = self.run_file("broken.zip", b"bad zip")
        self.assertEqual(job.state, "ERROR")
        self.assertFalse(list(self.roles["clean_dir"].iterdir()))
