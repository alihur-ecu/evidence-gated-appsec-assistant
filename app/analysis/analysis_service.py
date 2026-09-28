"""
Provider-independent analysis service.

The web application calls this service rather than calling a specific
analysis implementation directly.

Changing the configured analysis provider or LLM proposer must not
require changes to the frontend workflow.

Architecture principle:

    AI proposes -> Evidence verifies -> Human decides
"""

from __future__ import annotations

import os
from uuid import uuid4

from app.analysis.proposal_aggregator import (
    aggregate_analysis_result,
)
from app.analysis.providers.mock_provider import (
    run_mock_static_analysis,
)
from app.analysis.providers.static_source_provider import (
    run_static_source_analysis,
)
from app.analysis.static_pipeline import (
    run_static_proposal_pipeline,
)


SUPPORTED_PROVIDERS = {
    "mock",
    "static_source",
}


def run_static_analysis(
    *,
    source_path: str,
    original_filename: str,
    application_name: str,
) -> dict:
    """
    Run the configured static-analysis path.

    ANALYSIS_PROVIDER selects how source analysis is prepared.

    LLM_PROVIDER independently selects the proposer used by the real
    static-source pipeline.

    Example:

        ANALYSIS_PROVIDER=static_source
        LLM_PROVIDER=gemini

    The static-source path is:

        source archive
            ->
        safe extraction
            ->
        source collection
            ->
        bounded context construction
            ->
        LLM execution budget
            ->
        configured proposer
            ->
        proposal aggregation

    Candidate findings remain proposals only. This service does not
    verify vulnerabilities and does not promote findings to PROVED or
    REFUTED.
    """

    provider_name = os.getenv(
        "ANALYSIS_PROVIDER",
        "mock",
    ).strip().lower()

    if provider_name not in SUPPORTED_PROVIDERS:
        raise ValueError(
            f"Unsupported ANALYSIS_PROVIDER "
            f"'{provider_name}'. Supported providers: "
            f"{', '.join(sorted(SUPPORTED_PROVIDERS))}."
        )

    provider_arguments = {
        "source_path": source_path,
        "original_filename": original_filename,
        "application_name": application_name,
    }

    if provider_name == "mock":
        result = run_mock_static_analysis(
            **provider_arguments
        )

        # Mock proposals use the same aggregation boundary as real
        # proposals so the web layer receives a stable result contract.
        result = aggregate_analysis_result(
            result
        )

    elif provider_name == "static_source":
        prepared_analysis = (
            run_static_source_analysis(
                **provider_arguments
            )
        )

        # The real static pipeline applies the LLM execution budget,
        # invokes the configured proposer, and aggregates overlapping
        # proposals.
        #
        # With LLM_PROVIDER=none this path performs no external model
        # calls and returns zero candidate findings.
        result = run_static_proposal_pipeline(
            prepared_analysis=prepared_analysis
        )

    else:
        # Defensive fallback. SUPPORTED_PROVIDERS should make this
        # unreachable.
        raise ValueError(
            f"Provider '{provider_name}' is not implemented."
        )

    result["analysis_id"] = (
        f"A-{uuid4().hex[:8].upper()}"
    )

    return result