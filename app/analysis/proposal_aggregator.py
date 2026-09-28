"""
Proposal aggregation and deduplication.

LLM analysis may process overlapping source-code chunks independently.
As a result, the same candidate vulnerability can be proposed more than
once.

This module merges duplicate proposals while preserving provenance.

Architecture principle:

    AI proposes -> Evidence verifies -> Human decides

Aggregation never proves, refutes, or changes the lifecycle status of a
finding. It only normalises and deduplicates candidate proposals before
they are converted into canonical Finding objects.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Iterable, Optional


DEFAULT_LINE_TOLERANCE = 3


@dataclass
class AggregationResult:
    """Result of proposal aggregation."""

    findings: list[dict]
    proposals_received: int
    proposals_retained: int
    duplicates_merged: int

    def to_dict(self) -> dict:
        return {
            "findings": self.findings,
            "aggregation": {
                "proposals_received": self.proposals_received,
                "proposals_retained": self.proposals_retained,
                "duplicates_merged": self.duplicates_merged,
            },
        }


def _clean_string(value: Any) -> Optional[str]:
    """Return a stripped string or None."""

    if value is None:
        return None

    text = str(value).strip()

    return text if text else None


def _normalise_text(value: Any) -> Optional[str]:
    """
    Normalise text for comparison only.

    Original provider values are preserved in the returned proposal.
    """

    text = _clean_string(value)

    if text is None:
        return None

    return (
        text
        .upper()
        .replace("-", "_")
        .replace(" ", "_")
        .replace("/", "_")
    )


def _normalise_path(value: Any) -> Optional[str]:
    """Normalise source paths for duplicate comparison."""

    text = _clean_string(value)

    if text is None:
        return None

    return text.replace("\\", "/").lower()


def _normalise_line(value: Any) -> Optional[int]:
    """Convert a provider line value to an integer when possible."""

    if value is None or value == "":
        return None

    try:
        line = int(value)
    except (TypeError, ValueError):
        return None

    return line if line > 0 else None


def _proposal_source_file(proposal: dict) -> Optional[str]:
    return _normalise_path(
        proposal.get("source_file")
        or proposal.get("file_path")
    )


def _proposal_line(proposal: dict) -> Optional[int]:
    return _normalise_line(
        proposal.get("line_number")
        or proposal.get("line")
    )


def _proposal_type(proposal: dict) -> Optional[str]:
    """
    Return the best available vulnerability identity.

    CWE is considered after explicit vulnerability labels so providers
    are not required to use exactly the same schema.
    """

    candidates = (
        proposal.get("finding_type"),
        proposal.get("vulnerability"),
        proposal.get("type"),
        proposal.get("name"),
        proposal.get("proposed_cwe"),
        proposal.get("cwe"),
    )

    for candidate in candidates:
        normalised = _normalise_text(candidate)

        if normalised:
            return normalised

    return None


def _proposal_cwe(proposal: dict) -> Optional[str]:
    value = (
        proposal.get("proposed_cwe")
        or proposal.get("cwe")
    )

    text = _clean_string(value)

    return text.upper() if text else None


def _proposal_endpoint(proposal: dict) -> Optional[str]:
    return _clean_string(
        proposal.get("endpoint")
        or proposal.get("url")
    )


def _proposal_parameter(proposal: dict) -> Optional[str]:
    value = _clean_string(
        proposal.get("parameter")
    )

    return value.lower() if value else None


def _proposal_method(proposal: dict) -> Optional[str]:
    value = _clean_string(
        proposal.get("method")
    )

    return value.upper() if value else None


def _extract_chunk_ids(proposal: dict) -> list[str]:
    """
    Extract provenance identifiers from common provider representations.
    """

    chunk_ids: list[str] = []

    direct_chunk = _clean_string(
        proposal.get("chunk_id")
    )

    if direct_chunk:
        chunk_ids.append(direct_chunk)

    existing = proposal.get("observed_in_chunks")

    if isinstance(existing, str):
        existing = [existing]

    if isinstance(existing, (list, tuple, set)):
        for value in existing:
            cleaned = _clean_string(value)

            if cleaned and cleaned not in chunk_ids:
                chunk_ids.append(cleaned)

    return chunk_ids


def _same_static_location(
    first: dict,
    second: dict,
    *,
    line_tolerance: int,
) -> bool:
    """
    Determine whether two static proposals describe the same location.

    The source file must match.

    Exact or nearby line numbers are treated as the same location because
    overlapping chunks can cause an LLM to point at slightly different
    lines within the same vulnerable statement.

    Missing line numbers are not automatically merged unless another
    strong location signal is available.
    """

    first_file = _proposal_source_file(first)
    second_file = _proposal_source_file(second)

    if not first_file or not second_file:
        return False

    if first_file != second_file:
        return False

    first_line = _proposal_line(first)
    second_line = _proposal_line(second)

    if first_line is not None and second_line is not None:
        return (
            abs(first_line - second_line)
            <= line_tolerance
        )

    # If line information is missing, use runtime location only when it
    # exists in both proposals. This avoids merging every same-type
    # finding from one large source file.
    return _same_runtime_location(
        first,
        second,
    )


def _same_runtime_location(
    first: dict,
    second: dict,
) -> bool:
    """
    Determine whether two proposals describe the same runtime location.
    """

    first_endpoint = _proposal_endpoint(first)
    second_endpoint = _proposal_endpoint(second)

    if not first_endpoint or not second_endpoint:
        return False

    if first_endpoint != second_endpoint:
        return False

    first_method = _proposal_method(first)
    second_method = _proposal_method(second)

    if (
        first_method
        and second_method
        and first_method != second_method
    ):
        return False

    first_parameter = _proposal_parameter(first)
    second_parameter = _proposal_parameter(second)

    if (
        first_parameter
        and second_parameter
        and first_parameter != second_parameter
    ):
        return False

    return True


def _same_vulnerability(
    first: dict,
    second: dict,
) -> bool:
    """
    Compare vulnerability identity without relying on LLM confidence.
    """

    first_type = _proposal_type(first)
    second_type = _proposal_type(second)

    if (
        first_type
        and second_type
        and first_type == second_type
    ):
        return True

    first_cwe = _proposal_cwe(first)
    second_cwe = _proposal_cwe(second)

    if (
        first_cwe
        and second_cwe
        and first_cwe == second_cwe
    ):
        return True

    return False


def _are_duplicates(
    first: dict,
    second: dict,
    *,
    line_tolerance: int,
) -> bool:
    """
    Return True only when identity and location both correlate.

    Same vulnerability type alone is never enough to merge proposals.
    """

    if not _same_vulnerability(
        first,
        second,
    ):
        return False

    if _same_static_location(
        first,
        second,
        line_tolerance=line_tolerance,
    ):
        return True

    if _same_runtime_location(
        first,
        second,
    ):
        return True

    return False


def _merge_proposals(
    retained: dict,
    duplicate: dict,
) -> dict:
    """
    Merge provenance and useful missing metadata.

    The first proposal remains authoritative for conflicting descriptive
    values. Later proposals may fill fields that were previously absent.

    Confidence is preserved as provider metadata but is never used to
    determine whether the candidate is valid.
    """

    merged = deepcopy(retained)

    retained_chunks = _extract_chunk_ids(
        retained
    )

    duplicate_chunks = _extract_chunk_ids(
        duplicate
    )

    observed_in_chunks: list[str] = []

    for chunk_id in (
        retained_chunks
        + duplicate_chunks
    ):
        if chunk_id not in observed_in_chunks:
            observed_in_chunks.append(
                chunk_id
            )

    if observed_in_chunks:
        merged["observed_in_chunks"] = (
            observed_in_chunks
        )

    fill_if_missing = (
        "source_file",
        "file_path",
        "line_number",
        "line",
        "endpoint",
        "url",
        "parameter",
        "method",
        "finding_type",
        "vulnerability",
        "type",
        "name",
        "proposed_cwe",
        "cwe",
        "suggested_severity",
        "severity",
        "explanation",
        "why_vulnerable",
        "description",
        "confidence",
        "scan_type",
    )

    for field_name in fill_if_missing:
        current = merged.get(field_name)

        if current not in (
            None,
            "",
            [],
        ):
            continue

        incoming = duplicate.get(
            field_name
        )

        if incoming not in (
            None,
            "",
            [],
        ):
            merged[field_name] = (
                deepcopy(incoming)
            )

    return merged


class ProposalAggregator:
    """
    Deduplicate provider proposals while retaining audit provenance.

    This class deliberately knows nothing about Gemini, DVWA, Juice Shop,
    Flask, or the canonical Finding lifecycle.
    """

    def __init__(
        self,
        *,
        line_tolerance: int = DEFAULT_LINE_TOLERANCE,
    ) -> None:
        if line_tolerance < 0:
            raise ValueError(
                "line_tolerance cannot be negative."
            )

        self.line_tolerance = line_tolerance

    def aggregate(
        self,
        proposals: Iterable[dict],
    ) -> AggregationResult:
        """
        Aggregate duplicate candidate proposals.

        Invalid non-dictionary values are ignored because providers are
        external boundaries and should not crash the analysis pipeline.
        """

        valid_proposals = [
            deepcopy(proposal)
            for proposal in proposals
            if isinstance(proposal, dict)
        ]

        retained: list[dict] = []

        duplicates_merged = 0

        for proposal in valid_proposals:
            match_index: Optional[int] = None

            for index, existing in enumerate(
                retained
            ):
                if _are_duplicates(
                    existing,
                    proposal,
                    line_tolerance=(
                        self.line_tolerance
                    ),
                ):
                    match_index = index
                    break

            if match_index is None:
                prepared = deepcopy(
                    proposal
                )

                chunk_ids = (
                    _extract_chunk_ids(
                        prepared
                    )
                )

                if chunk_ids:
                    prepared[
                        "observed_in_chunks"
                    ] = chunk_ids

                retained.append(
                    prepared
                )

                continue

            retained[match_index] = (
                _merge_proposals(
                    retained[match_index],
                    proposal,
                )
            )

            duplicates_merged += 1

        return AggregationResult(
            findings=retained,
            proposals_received=len(
                valid_proposals
            ),
            proposals_retained=len(
                retained
            ),
            duplicates_merged=(
                duplicates_merged
            ),
        )


def aggregate_analysis_result(
    analysis_result: dict,
    *,
    line_tolerance: int = DEFAULT_LINE_TOLERANCE,
) -> dict:
    """
    Aggregate the findings contained in an analysis-provider result.

    All top-level provider metadata is preserved.
    """

    result = deepcopy(
        analysis_result
    )

    proposals = result.get(
        "findings",
        [],
    )

    if not isinstance(proposals, list):
        proposals = []

    aggregation = ProposalAggregator(
        line_tolerance=line_tolerance,
    ).aggregate(proposals)

    result["findings"] = (
        aggregation.findings
    )

    result["aggregation"] = {
        "proposals_received":
            aggregation.proposals_received,
        "proposals_retained":
            aggregation.proposals_retained,
        "duplicates_merged":
            aggregation.duplicates_merged,
    }

    return result