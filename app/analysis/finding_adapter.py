"""
Adapter from analysis-provider output to the canonical Finding model.

Providers are intentionally allowed to use slightly different naming
conventions. This module is the boundary that normalises their output
before the rest of the application consumes it.

Unknown vulnerability types are preserved as FindingType.OTHER instead
of being silently discarded.
"""

from __future__ import annotations

from typing import Any, Optional

from app.models.finding import (
    Finding,
    FindingStatus,
    FindingType,
    ScanType,
)


TYPE_MAP = {
    # SQL Injection
    "SQL_INJECTION": FindingType.SQL_INJECTION,
    "SQL INJECTION": FindingType.SQL_INJECTION,
    "SQLI": FindingType.SQL_INJECTION,
    "CWE-89": FindingType.SQL_INJECTION,

    # Cross-Site Scripting
    "XSS": FindingType.XSS,
    "CROSS_SITE_SCRIPTING": FindingType.XSS,
    "CROSS-SITE SCRIPTING": FindingType.XSS,
    "CWE-79": FindingType.XSS,

    # Command Injection
    "COMMAND_INJECTION": FindingType.COMMAND_INJECTION,
    "COMMAND INJECTION": FindingType.COMMAND_INJECTION,
    "OS_COMMAND_INJECTION": FindingType.COMMAND_INJECTION,
    "CWE-78": FindingType.COMMAND_INJECTION,

    # Path Traversal
    "PATH_TRAVERSAL": FindingType.PATH_TRAVERSAL,
    "PATH TRAVERSAL": FindingType.PATH_TRAVERSAL,
    "DIRECTORY_TRAVERSAL": FindingType.PATH_TRAVERSAL,
    "CWE-22": FindingType.PATH_TRAVERSAL,

    # Server-Side Request Forgery
    "SSRF": FindingType.SSRF,
    "SERVER_SIDE_REQUEST_FORGERY": FindingType.SSRF,
    "SERVER-SIDE REQUEST FORGERY": FindingType.SSRF,
    "CWE-918": FindingType.SSRF,

    # XML External Entity
    "XXE": FindingType.XXE,
    "XML_EXTERNAL_ENTITY": FindingType.XXE,
    "CWE-611": FindingType.XXE,

    # Insecure Direct Object Reference
    "IDOR": FindingType.IDOR,
    "INSECURE_DIRECT_OBJECT_REFERENCE": FindingType.IDOR,

    # Open Redirect
    "OPEN_REDIRECT": FindingType.OPEN_REDIRECT,
    "OPEN REDIRECT": FindingType.OPEN_REDIRECT,
    "CWE-601": FindingType.OPEN_REDIRECT,

    # File Inclusion
    "FILE_INCLUSION": FindingType.FILE_INCLUSION,
    "LOCAL_FILE_INCLUSION": FindingType.FILE_INCLUSION,
    "REMOTE_FILE_INCLUSION": FindingType.FILE_INCLUSION,

    # Insecure Deserialization
    "INSECURE_DESERIALIZATION":
        FindingType.INSECURE_DESERIALIZATION,
    "INSECURE DESERIALIZATION":
        FindingType.INSECURE_DESERIALIZATION,
    "CWE-502":
        FindingType.INSECURE_DESERIALIZATION,
}


SCAN_TYPE_MAP = {
    "STATIC": ScanType.STATIC,
    "SAST": ScanType.STATIC,
    "SOURCE": ScanType.STATIC,
    "SOURCE_CODE": ScanType.STATIC,

    "DYNAMIC": ScanType.DYNAMIC,
    "DAST": ScanType.DYNAMIC,
    "RUNTIME": ScanType.DYNAMIC,
}


def _clean_optional_string(value: Any) -> Optional[str]:
    """Return a trimmed string or None for missing/empty values."""

    if value is None:
        return None

    text = str(value).strip()

    return text if text else None


def _normalise_key(value: Any) -> str:
    """Normalise provider labels before mapping them."""

    if value is None:
        return ""

    return (
        str(value)
        .strip()
        .upper()
        .replace("-", "_")
        .replace("/", "_")
    )


def _normalise_finding_type(
    proposal: dict,
) -> tuple[FindingType, Optional[str]]:
    """
    Determine the canonical FindingType.

    The provider may describe the vulnerability using finding_type,
    vulnerability, type, name, or CWE.

    Unknown values are preserved through raw_finding_type.
    """

    candidates = [
        proposal.get("finding_type"),
        proposal.get("vulnerability"),
        proposal.get("type"),
        proposal.get("name"),
        proposal.get("proposed_cwe"),
        proposal.get("cwe"),
    ]

    for candidate in candidates:
        if candidate is None:
            continue

        raw = str(candidate).strip()

        # First try the exact uppercase representation because CWE
        # mappings contain hyphens.
        exact_key = raw.upper()

        if exact_key in TYPE_MAP:
            return TYPE_MAP[exact_key], None

        normalised_key = _normalise_key(raw)

        if normalised_key in TYPE_MAP:
            return TYPE_MAP[normalised_key], None

    raw_type = next(
        (
            str(candidate).strip()
            for candidate in candidates
            if candidate is not None
            and str(candidate).strip()
        ),
        None,
    )

    return FindingType.OTHER, raw_type


def _normalise_scan_type(
    analysis_result: dict,
    proposal: dict,
) -> ScanType:
    """Resolve STATIC/DYNAMIC origin without assuming a specific provider."""

    candidates = [
        proposal.get("scan_type"),
        analysis_result.get("scan_type"),
        analysis_result.get("analysis_type"),
        analysis_result.get("context_source"),
    ]

    for candidate in candidates:
        key = _normalise_key(candidate)

        if key in SCAN_TYPE_MAP:
            return SCAN_TYPE_MAP[key]

        # Existing mock/context labels may contain additional words.
        if "STATIC" in key:
            return ScanType.STATIC

        if "DYNAMIC" in key or "RUNTIME" in key:
            return ScanType.DYNAMIC

    return ScanType.UNKNOWN


def _normalise_line_number(value: Any) -> Optional[int]:
    """Convert provider line-number values to int when possible."""

    if value is None or value == "":
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalise_confidence(value: Any) -> Optional[float]:
    """
    Preserve LLM confidence as metadata only.

    Confidence is never used by this adapter to change finding status.
    """

    if value is None or value == "":
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def adapt_analysis_result(
    analysis_result: dict,
) -> list[tuple[Finding, dict]]:
    """
    Convert provider proposals into canonical Finding(PROPOSED) objects.

    This adapter deliberately supports heterogeneous providers so the
    application is not coupled to the mock, Gemini, DVWA, Juice Shop,
    one programming language, or one URL structure.
    """

    adapted: list[tuple[Finding, dict]] = []

    proposals = analysis_result.get("findings", [])

    if not isinstance(proposals, list):
        return adapted

    for index, proposal in enumerate(proposals, start=1):
        if not isinstance(proposal, dict):
            continue

        finding_type, raw_finding_type = (
            _normalise_finding_type(proposal)
        )

        scan_type = _normalise_scan_type(
            analysis_result,
            proposal,
        )

        finding_id = (
            _clean_optional_string(
                proposal.get("finding_id")
            )
            or f"F-{index:04d}"
        )

        proposed_cwe = _clean_optional_string(
            proposal.get("proposed_cwe")
            or proposal.get("cwe")
        )

        suggested_severity = _clean_optional_string(
            proposal.get("suggested_severity")
            or proposal.get("severity")
        )

        explanation = (
            _clean_optional_string(
                proposal.get("explanation")
            )
            or _clean_optional_string(
                proposal.get("why_vulnerable")
            )
            or _clean_optional_string(
                proposal.get("description")
            )
            or (
                "Candidate finding proposed by the configured "
                "analysis provider."
            )
        )

        source_file = _clean_optional_string(
            proposal.get("source_file")
            or proposal.get("file_path")
            or analysis_result.get("source_file")
        )

        finding = Finding(
            finding_id=finding_id,
            finding_type=finding_type,
            raw_finding_type=raw_finding_type,
            scan_type=scan_type,

            endpoint=_clean_optional_string(
                proposal.get("endpoint")
                or proposal.get("url")
            ),

            parameter=_clean_optional_string(
                proposal.get("parameter")
            ),

            method=_clean_optional_string(
                proposal.get("method")
            ),

            source_file=source_file,

            line_number=_normalise_line_number(
                proposal.get("line_number")
                or proposal.get("line")
            ),

            proposed_cwe=proposed_cwe,

            suggested_severity=suggested_severity,

            confidence=_normalise_confidence(
                proposal.get("confidence")
            ),

            explanation=explanation,

            # A provider/LLM is never allowed to promote itself.
            status=FindingStatus.PROPOSED,
        )

        metadata = {
            "analysis_id":
                analysis_result.get("analysis_id"),

            "target":
                analysis_result.get(
                    "application_name",
                    "Not specified",
                ),

            "source_file":
                source_file or "Not available",

            "line_number":
                finding.line_number,

            # Preserve provider provenance separately from runtime location.
            # Static findings are allowed to have no HTTP endpoint/parameter,
            # but the bounded source context that produced the proposal must
            # remain traceable for Oracle verification and reporting.
            "chunk_id":
                _clean_optional_string(proposal.get("chunk_id")),

            "observed_in_chunks":
                [
                    str(value).strip()
                    for value in (proposal.get("observed_in_chunks") or [])
                    if str(value).strip()
                ]
                if isinstance(proposal.get("observed_in_chunks"), (list, tuple, set))
                else (
                    [_clean_optional_string(proposal.get("observed_in_chunks"))]
                    if _clean_optional_string(proposal.get("observed_in_chunks"))
                    else []
                ),

            "chunk_start_line":
                _normalise_line_number(proposal.get("chunk_start_line")),

            "chunk_end_line":
                _normalise_line_number(proposal.get("chunk_end_line")),

            "scan_type":
                finding.scan_type.value,

            "proposed_cwe":
                proposed_cwe or "Not available",

            "suggested_severity":
                suggested_severity or "Not assessed",

            "proposal_source":
                analysis_result.get(
                    "provider",
                    "UNKNOWN",
                ),

            "context_source":
                analysis_result.get(
                    "context_source",
                    "UNKNOWN",
                ),

            "raw_finding_type":
                raw_finding_type,

            "confidence":
                finding.confidence,
        }

        adapted.append(
            (
                finding,
                metadata,
            )
        )

    return adapted