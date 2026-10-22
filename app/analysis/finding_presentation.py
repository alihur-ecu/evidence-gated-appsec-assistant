from __future__ import annotations

from app.analysis.finding_adapter import TYPE_MAP
from app.models.finding import Finding, FindingType, ScanType


DISPLAY_LABELS: dict[FindingType, str] = {
    FindingType.SQL_INJECTION: "Potential SQL Injection",
    FindingType.XSS: "Potential Cross-Site Scripting",
    FindingType.COMMAND_INJECTION: "Potential Command Injection",
    FindingType.PATH_TRAVERSAL: "Potential Path Traversal",
    FindingType.SSRF: "Potential Server-Side Request Forgery",
    FindingType.XXE: "Potential XML External Entity Injection",
    FindingType.IDOR: "Potential Insecure Direct Object Reference",
    FindingType.OPEN_REDIRECT: "Potential Open Redirect",
    FindingType.FILE_INCLUSION: "Potential File Inclusion",
    FindingType.FILE_UPLOAD: "Potential Unrestricted File Upload",
    FindingType.CSRF: "Potential Cross-Site Request Forgery",
    FindingType.AUTHENTICATION_RATE_LIMITING: "Potential Authentication Rate-Limiting Weakness",
    FindingType.CODE_INJECTION: "Potential Code Injection",
    FindingType.INFORMATION_EXPOSURE: "Potential Sensitive Information Exposure",
    FindingType.FORCED_BROWSING: "Potential Forced Browsing (Direct Request)",
    FindingType.INSECURE_DESERIALIZATION: "Potential Insecure Deserialization",
}


INPUT_CONTEXT_FAMILIES = frozenset({
    FindingType.SQL_INJECTION,
    FindingType.XSS,
    FindingType.COMMAND_INJECTION,
    FindingType.CODE_INJECTION,
})


def effective_cwe(finding: Finding, metadata: dict | None = None) -> str | None:

    metadata = metadata or {}
    for value in (finding.proposed_cwe, metadata.get("proposed_cwe")):
        if isinstance(value, str) and value.strip() and value.strip().lower() not in {
            "not available", "none", "unknown", "n/a", "—", "-",
        }:
            return value.strip().upper()
    return None


def proposed_family(finding: Finding, metadata: dict | None = None) -> FindingType:
    
    if finding.finding_type is not FindingType.OTHER:
        return finding.finding_type
    cwe = effective_cwe(finding, metadata)
    if cwe:
        mapped = TYPE_MAP.get(cwe)
        if mapped:
            return mapped
    return FindingType.OTHER


def finding_label(finding: Finding, metadata: dict | None = None) -> str:
    """Always return a useful proposal label, never invent a proof."""
    family = proposed_family(finding, metadata)
    if family in DISPLAY_LABELS:
        return DISPLAY_LABELS[family]
    cwe = effective_cwe(finding, metadata)
    if cwe:
        return f"Potential Security Weakness ({cwe})"
    # Do not echo provider-supplied freeform strings as established categories.
    return "Potential Unclassified Security Weakness"


def proposal_quality_notes(finding: Finding, metadata: dict | None = None) -> list[str]:
   
    family = proposed_family(finding, metadata)
    notes: list[str] = []
    if finding.scan_type is ScanType.DYNAMIC and family in INPUT_CONTEXT_FAMILIES:
        if not isinstance(finding.parameter, str) or not finding.parameter.strip():
            notes.append(
                "No named input parameter was identified for this injection proposal. "
                "The entry point needs clarification before runtime verification."
            )
    cwe = effective_cwe(finding, metadata)
    if (
        cwe and finding.finding_type is not FindingType.OTHER
        and (mapped := TYPE_MAP.get(cwe)) is not None
        and mapped is not finding.finding_type
    ):
        notes.append(
            "The proposed CWE and vulnerability label describe different families; "
            "the classification requires human review."
        )
    return notes
