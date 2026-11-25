"""Análisis puntual sin ejecutar ni mover archivos."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from miniav.config import load_config
from miniav.core.policy import decide
from miniav.core.scanner import scan_file


def main() -> int:
    parser = argparse.ArgumentParser(description="MiniAntivirus v0.3.0 (reconstrucción)")
    parser.add_argument("path", type=Path, help="Archivo que analizar")
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("monitor_config.json"))
    args = parser.parse_args()
    try:
        cfg = load_config(args.config)
        result = scan_file(args.path, cfg)
        decision = decide(result, suspicious_threshold=int(cfg["suspicious_score"]),
                          review_action=cfg["review_action"])
        print(json.dumps({"decision": decision.action, "reason": decision.reason,
                          "scan": result.to_dict()}, ensure_ascii=False, indent=2))
        return {"CLEAN": 0, "QUARANTINED": 1, "ERROR": 2}[decision.action]
    except Exception as exc:
        print(json.dumps({"decision": "ERROR", "error": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
