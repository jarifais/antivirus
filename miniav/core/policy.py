from __future__ import annotations

from dataclasses import dataclass

from .models import ScanResult


@dataclass(frozen=True)
class PolicyDecision:
    action: str  # CLEAN | QUARANTINED | ERROR
    reason: str


def verdict(score: int) -> str:
    if score >= 70:
        return "MUY SOSPECHOSO"
    if score >= 45:
        return "SOSPECHOSO"
    if score >= 20:
        return "REVISAR"
    return "SIN INDICIOS RELEVANTES"


def decide(result: ScanResult, *, suspicious_threshold: int = 45, review_action: str = "quarantine") -> PolicyDecision:
    # Explicit blocking findings win, including encrypted/noninspectable content.
    if any(f.blocking for f in result.findings) or any(any(f.blocking for f in n.findings) for n in result.nested_results):
        return PolicyDecision("QUARANTINED", "Regla de bloqueo explícita")
    if not result.analysis_complete or result.error or result.errors:
        return PolicyDecision("ERROR", "El análisis no pudo completarse de forma fiable")
    if result.score >= suspicious_threshold:
        return PolicyDecision("QUARANTINED", f"Score {result.score} >= umbral {suspicious_threshold}")
    if result.score >= 20 and review_action.lower() == "quarantine":
        return PolicyDecision("QUARANTINED", "Veredicto REVISAR y política restrictiva")
    return PolicyDecision("CLEAN", "Análisis completo y política satisfecha")
