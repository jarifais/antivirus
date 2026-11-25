import tempfile
import unittest
from pathlib import Path
from miniav.state import Job, StateDB


class StateTests(unittest.TestCase):
    def test_persistence(self):
        with tempfile.TemporaryDirectory() as temp:
            db = StateDB(Path(temp) / "state.sqlite3")
            try:
                job = Job.create("source.txt")
                job.state = "ERROR"
                db.save_job(job)
                self.assertEqual(db.recent_jobs(1)[0].state, "ERROR")
                self.assertEqual(db.recent_jobs(1)[0].source_path, "source.txt")
            finally:
                db.close()
