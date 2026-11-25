"""Versioned, bounded static indicator catalog. A match is not proof of malware.

Rules use literal substring matching (scripts) or exact imported API name
matching (PE), not user-configurable regular expressions or executed code.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .models import Finding

CATALOG_PATH = Path(__file__).resolve().parents[1] / "rules" / "indicators.json"
MAX_BYTES = 128 * 1024
MAX_RULES = 256
SCOPES = {"script", "pe_import"}


class IndicatorCatalogError(ValueError):
    """Missing, invalid, or unsupported indicator catalog."""


def load_catalog(path: Path | None = None) -> dict:
    source = CATALOG_PATH if path is None else Path(path)
    data = source.read_bytes()
    if not data or len(data) > MAX_BYTES:
        raise IndicatorCatalogError("Indicator catalog exceeds safe size or is empty")
    try:
        catalog = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IndicatorCatalogError("Indicator catalog is not valid JSON") from exc
    if not isinstance(catalog, dict) or catalog.get("schema_version") != 1:
        raise IndicatorCatalogError("Unsupported indicator catalog schema")
    rules = catalog.get("rules")
    if not isinstance(rules, list) or not 1 <= len(rules) <= MAX_RULES:
        raise IndicatorCatalogError("Invalid number of indicator rules")
    seen = set()
    for rule in rules:
        if not isinstance(rule, dict):
            raise IndicatorCatalogError("Rule must be an object")
        rid, scope = rule.get("id"), rule.get("scope")
        if (not isinstance(rid, str) or
                not re.fullmatch(r"[A-Z0-9_]{4,64}", rid) or
                rid in seen or scope not in SCOPES):
            raise IndicatorCatalogError("Invalid or duplicate rule ID/scope")
        seen.add(rid)
        if (not isinstance(rule.get("description"), str) or
                not 1 <= len(rule["description"]) <= 180):
            raise IndicatorCatalogError("Invalid rule description")
        if type(rule.get("score")) is not int or not 0 <= rule["score"] <= 100:
            raise IndicatorCatalogError("Invalid rule score")
        if not isinstance(rule.get("blocking"), bool):
            raise IndicatorCatalogError("Blocking flag must be boolean")
        attack = rule.get("attack", "")
        if not isinstance(attack, str) or (attack and
            not re.fullmatch(r"T\d{4}(?:\.\d{3})?", attack)):
            raise IndicatorCatalogError("Invalid ATT&CK technique")
        groups = rule.get("groups")
        if not isinstance(groups, list) or not 1 <= len(groups) <= 8:
            raise IndicatorCatalogError("Invalid match group count")
        for group in groups:
            if not isinstance(group, list) or not 1 <= len(group) <= 16:
                raise IndicatorCatalogError("Invalid match group")
            for token in group:
                if (not isinstance(token, str) or
                    not 2 <= len(token) <= 100 or not token.strip() or
                    any(ord(ch) < 32 for ch in token) or
                    token != token.casefold()):
                    raise IndicatorCatalogError("Unsafe/non-normalized literal token")
                if scope == "pe_import" and any(ch in token for ch in "! \t"):
                    raise IndicatorCatalogError("PE import token must be an API name")
    return {"version": catalog.get("catalog_version", "unspecified"),
            "sha256": hashlib.sha256(data).hexdigest(),
            "rules": rules}


def scan_indicators(catalog: dict, scope: str, value: str | tuple[str, ...]) -> list[Finding]:
    if scope not in SCOPES:
        raise ValueError("Unknown indicator scope")
    # Matching is read-only; bounded script sizes are enforced by caller.
    if scope == "script":
        text = str(value).casefold()
        matches = lambda token: token in text
    else:
        names = {v.rsplit("!", 1)[-1].casefold() for v in value}
        matches = lambda token: token in names
    findings = []
    for rule in catalog["rules"]:
        if rule["scope"] != scope:
            continue
        if all(any(matches(token) for token in group) for group in rule["groups"]):
            score = rule["score"]
            findings.append(Finding(
                rule["id"], "high" if score >= 45 else "medium" if score >= 20 else "low",
                score, rule["description"], "indicators",
                blocking=rule["blocking"],
                metadata={"attack_technique": rule.get("attack", ""),
                          "catalog_version": catalog["version"],
                          "catalog_sha256": catalog["sha256"]},
            ))
    return findings
