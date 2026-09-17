"""Adapter from the stable analysis contract to the canonical Finding model."""

from __future__ import annotations

from app.models.finding import Finding, FindingStatus, FindingType


TYPE_MAP = {
    "SQL_INJECTION": FindingType.SQL_INJECTION,
    "XSS": FindingType.XSS,
}


def adapt_analysis_result(analysis_result: dict) -> list[tuple[Finding, dict]]:
    """Convert provider proposals into Finding(PROPOSED) plus UI metadata."""
    adapted = []

    for index, proposal in enumerate(analysis_result.get("findings", []), start=1):
        raw_type = proposal.get("finding_type")
        finding_type = TYPE_MAP.get(raw_type)

        if finding_type is None:
            continue

        finding_id = f"F-{index:04d}"
        finding = Finding(
            finding_id=finding_id,
            finding_type=finding_type,
            endpoint=proposal.get("endpoint", ""),
            parameter=proposal.get("parameter", ""),
            method=proposal.get("method", "GET"),
            explanation=proposal.get("explanation", "Candidate finding proposed by the configured analysis provider."),
            status=FindingStatus.PROPOSED,
        )

        metadata = {
            "analysis_id": analysis_result.get("analysis_id"),
            "target": analysis_result.get("application_name", "Local Lab"),
            "source_file": analysis_result.get("source_file", "Not available"),
            "proposed_cwe": proposal.get("proposed_cwe", "Not available"),
            "suggested_severity": proposal.get("suggested_severity", "Not assessed"),
            "proposal_source": analysis_result.get("provider", "UNKNOWN"),
            "context_source": analysis_result.get("context_source", "UNKNOWN"),
        }
        adapted.append((finding, metadata))

    return adapted
