from __future__ import annotations

import importlib.util
import platform
import shutil
import sys
from pathlib import Path

from miniav import MASTER_DOCUMENT_VERSION, __version__
from miniav.config import load_config, validate_config

BASE = Path(__file__).resolve().parent
CONFIG = BASE / "monitor_config.json"


def yesno(v: bool) -> str:
    return "OK" if v else "NO"


def main() -> int:
    print(f"MiniAntivirus {__version__} | Documento Maestro {MASTER_DOCUMENT_VERSION}")
    print(f"Python: {sys.version.split()[0]} | {platform.platform()}")
    print(f"YARA (yara-python): {yesno(importlib.util.find_spec('yara') is not None)}")
    print(f"7-Zip (py7zr):      {yesno(importlib.util.find_spec('py7zr') is not None)}")
    print(f"RAR (rarfile):      {yesno(importlib.util.find_spec('rarfile') is not None)}")
    print(f"7z CLI:             {shutil.which('7z') or 'no detectado'}")
    try:
        cfg = load_config(CONFIG)
        roles = validate_config(cfg, create_outputs=False)
        print("Configuración: OK")
        for k, v in roles.items():
            print(f"  {k:11}: {v}")
    except Exception as exc:
        print(f"Configuración: ERROR - {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
