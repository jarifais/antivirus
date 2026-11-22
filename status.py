from __future__ import annotations

import argparse
from pathlib import Path

from miniav.state import StateDB

BASE = Path(__file__).resolve().parent
DB = BASE / "data" / "state.sqlite3"


def main() -> int:
    p = argparse.ArgumentParser(description="Estado reciente de MiniAntivirus")
    p.add_argument("--limit", type=int, default=30)
    args = p.parse_args()
    if not DB.exists():
        print("Aún no existe base de estado.")
        return 0
    db = StateDB(DB)
    try:
        jobs = db.recent_jobs(args.limit)
        print(f"{'ESTADO':13} {'SCORE':5} {'SHA256':12} ARCHIVO")
        print("-" * 90)
        for j in jobs:
            score = "-" if j.score is None else str(j.score)
            sha = (j.sha256 or "-")[:12]
            print(f"{j.state:13} {score:5} {sha:12} {Path(j.source_path).name}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
