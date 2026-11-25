"""Bounded script inspection. Strings are indicators, never proof of malware."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Finding
from .indicators import load_catalog, scan_indicators


class ScriptInspectionError(ValueError):
    """Insufficient coverage to make a script safety decision."""


@dataclass(frozen=True)
class ScriptInfo:
    encoding: str
    findings: tuple[Finding, ...]
    catalog_version: str = ""


def _text(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\xff\xfe"):
        try:
            return data[2:].decode("utf-16-le", "strict"), "utf-16-le"
        except UnicodeError as exc:
            raise ScriptInspectionError("Malformed UTF-16 LE") from exc
    if data.startswith(b"\xfe\xff"):
        try:
            return data[2:].decode("utf-16-be", "strict"), "utf-16-be"
        except UnicodeError as exc:
            raise ScriptInspectionError("Malformed UTF-16 BE") from exc
    if data.startswith(b"\xef\xbb\xbf"):
        try:
            return data.decode("utf-8-sig", "strict"), "utf-8-sig"
        except UnicodeError as exc:
            raise ScriptInspectionError("Malformed UTF-8") from exc
    if len(data) >= 8:
        even = data[::2].count(0)
        odd = data[1::2].count(0)
        if odd >= len(data) // 5 and odd > even * 4:
            try:
                return data.decode("utf-16-le", "strict"), "utf-16-le"
            except UnicodeError as exc:
                raise ScriptInspectionError("Malformed inferred UTF-16 LE") from exc
        if even >= len(data) // 5 and even > odd * 4:
            try:
                return data.decode("utf-16-be", "strict"), "utf-16-be"
            except UnicodeError as exc:
                raise ScriptInspectionError("Malformed inferred UTF-16 BE") from exc
    if b"\x00" in data:
        raise ScriptInspectionError("Unexpected binary null in script")
    try:
        return data.decode("utf-8", "strict"), "utf-8"
    except UnicodeError:
        return data.decode("cp1252", "replace"), "windows-1252"


def inspect_script(data: bytes, *, max_size: int = 1024 * 1024) -> ScriptInfo:
    if len(data) > max_size:
        raise ScriptInspectionError("Script exceeds bounded inspection size")
    content, encoding = _text(data)
    normalized = content.casefold()
    findings: list[Finding] = []

    def add(code: str, score: int, message: str) -> None:
        findings.append(Finding(code, "high", score, message, "scripts",
                                blocking=True))

    # Encoded PowerShell is often legitimate in automation; signal risk, not proof.
    if re.search(r"(?:\bpowershell(?:\.exe)?\b.{0,100}?\s-(?:enc|encodedcommand)\b)|(?:\s-encodedcommand\b)", normalized):
        add("SCRIPT_ENCODED_POWERSHELL", 75, "PowerShell encoded-command indicator")

    download = bool(re.search(
        r"\b(?:invoke-webrequest|iwr|downloadstring|downloadfile|start-bitstransfer|"
        r"curl(?:\.exe)?|wget(?:\.exe)?)\b", normalized))
    execute = bool(re.search(
        r"\b(?:invoke-expression|iex|start-process|wscript\.shell|"
        r"subprocess\.(?:popen|run|call)|os\.system)\b", normalized))
    if download and execute:
        add("SCRIPT_DOWNLOAD_EXECUTE", 80, "Combined download and execution indicators")

    if re.search(
        r"(?:\bschtasks(?:\.exe)?\s+/create\b)|(?:\bregister-scheduledtask\b)|"
        r"(?:\bnew-scheduledtask\b)|"
        r"(?:\\currentversion\\run(?:once)?\\)|(?:\bcrontab\s+-[elr]\b)",
        normalized,
    ):
        add("SCRIPT_PERSISTENCE", 65, "Persistence-related command or registry path")

    catalog = load_catalog()
    findings.extend(scan_indicators(catalog, "script", content))
    return ScriptInfo(encoding, tuple(findings), catalog["version"])
