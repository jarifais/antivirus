from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    code: str
    severity: str
    score: int
    message: str
    analyzer: str = "generic"
    location: str = ""
    blocking: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class NestedResult:
    internal_path: str
    size: int
    sha256: str
    detected_type: str
    score: int
    verdict: str
    analysis_complete: bool
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None


@dataclass
class ScanResult:
    scan_id: str
    path: str
    size: int
    sha256: str
    sha1: str
    md5: str
    extension: str
    detected_type: str
    entropy: float
    findings: list[Finding]
    score: int
    raw_score: int
    verdict: str
    yara_matches: list[str]
    analysis_complete: bool = True
    errors: list[str] = field(default_factory=list)
    nested_results: list[NestedResult] = field(default_factory=list)
    capabilities: dict[str, Any] = field(default_factory=dict)
    engine_version: str = ""
    policy_version: str = ""
    rules_version: str = ""
    scanned_at: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
