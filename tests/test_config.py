import tempfile
import unittest
from pathlib import Path
from miniav.config import DEFAULT_CONFIG, default_pipeline_paths, validate_config


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.incoming = self.root / "Incoming"
        self.incoming.mkdir()

    def config(self):
        return {**DEFAULT_CONFIG, "incoming_dir": str(self.incoming),
                **default_pipeline_paths(self.incoming)}

    def test_valid_roles(self):
        self.assertEqual(len(validate_config(self.config(), create_outputs=True)), 5)

    def test_roles_must_differ(self):
        cfg = self.config()
        cfg["clean_dir"] = cfg["processing_dir"]
        with self.assertRaises(ValueError):
            validate_config(cfg)

    def test_incoming_must_exist(self):
        cfg = self.config()
        cfg["incoming_dir"] = str(self.root / "missing")
        with self.assertRaises(ValueError):
            validate_config(cfg)
