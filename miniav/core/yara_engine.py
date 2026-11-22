from __future__ import annotations

import hashlib
from pathlib import Path

_COMPILED_CACHE_KEY = None
_COMPILED_CACHE = None

def rules_version(rules_dir: Path | None) -> str:
    if not rules_dir or not rules_dir.exists():
        return "none"
    h = hashlib.sha256()
    files = sorted(p for p in rules_dir.rglob("*.yar") if p.is_file())
    for p in files:
        h.update(p.name.encode("utf-8", "surrogatepass"))
        h.update(p.read_bytes())
    return h.hexdigest()[:16] if files else "none"


def yara_capability() -> tuple[bool, str]:
    try:
        import yara  # type: ignore
        return True, getattr(yara, "__version__", "available")
    except Exception as exc:
        return False, f"unavailable: {exc.__class__.__name__}"


def scan_yara(path: Path, rules_dir: Path | None, timeout_s: int = 15) -> tuple[list[str], str | None]:
    global _COMPILED_CACHE_KEY, _COMPILED_CACHE
    if not rules_dir or not rules_dir.exists():
        return [], None
    try:
        import yara  # type: ignore
    except Exception:
        return [], None
    files = sorted(p for p in rules_dir.rglob("*.yar") if p.is_file())
    if not files:
        return [], None
    try:
        key = tuple((str(p.resolve()), p.stat().st_mtime_ns, p.stat().st_size) for p in files)
        if key != _COMPILED_CACHE_KEY or _COMPILED_CACHE is None:
            namespaces = {f"r{i}": str(p) for i, p in enumerate(files)}
            _COMPILED_CACHE = yara.compile(filepaths=namespaces)
            _COMPILED_CACHE_KEY = key
        matches = _COMPILED_CACHE.match(str(path), timeout=max(1, int(timeout_s)))
        return sorted({m.rule for m in matches}), None
    except Exception as exc:
        return [], f"YARA: {exc}"
