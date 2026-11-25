"""Servicio de vigilancia: escanea Incoming y entrega al siguiente paso."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from miniav.config import load_config, validate_config
from miniav.monitor import run_monitor

BASE = Path(__file__).resolve().parent


def main() -> int:
    parser = argparse.ArgumentParser(description="MiniAntivirus Incoming monitor (reconstrucción)")
    parser.add_argument("--once", action="store_true", help="Una sola ronda de estabilidad")
    parser.add_argument("--config", type=Path, default=BASE / "monitor_config.json")
    args = parser.parse_args()
    try:
        cfg = load_config(args.config)
        validate_config(cfg, create_outputs=False)
        jobs = run_monitor(cfg, BASE / "data" / "state.sqlite3",
                           BASE / "reports", once=args.once)
        for job in jobs:
            print(f"{job.state:12s} {job.source_path} -> {job.target_path}")
        return 2 if any(job.state == "ERROR" for job in jobs) else 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
