"""
Provider-independent static vulnerability proposal pipeline.

This module connects prepared static source context to the configured
LLM proposer while preserving separation between:

    source preparation
    execution budgeting
    vulnerability proposal
    proposal aggregation

Architecture principle:

    AI proposes -> Evidence verifies -> Human decides

This pipeline NEVER verifies vulnerabilities and NEVER promotes a
candidate beyond PROPOSED.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.analysis.proposal_aggregator import (
    ProposalAggregator,
)
from app.analysis.proposers.base import StaticProposer
from app.analysis.proposers.budget import (
    LLMExecutionBudget,
)
from app.analysis.proposers.factory import (
    create_static_proposer,
)


def run_static_proposal_pipeline(
    *,
    prepared_analysis: dict[str, Any],
    proposer: StaticProposer | None = None,
    budget: LLMExecutionBudget | None = None,
    provider_name: str | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    """
    Analyse prepared bounded source context using a configured proposer.

    Parameters
    ----------
    prepared_analysis:
        Result produced by the static source preparation provider.

    proposer:
        Optional injected proposer. Primarily useful for tests and
        deployments that construct providers externally.

    budget:
        Optional execution budget. When omitted, environment/default
        configuration is used.

    provider_name:
        Optional provider selection passed to the proposer factory.
        Ignored when an explicit proposer object is supplied.

    Returns
    -------
    dict
        A copy of the prepared analysis enriched with:

        - aggregated candidate findings;
        - LLM execution-budget metadata;
        - proposer metadata;
        - aggregation metadata.

    Important
    ---------
    Findings returned here are proposals only. No vulnerability is
    considered verified by this function.
    """

    if not isinstance(prepared_analysis, dict):
        raise TypeError(
            "prepared_analysis must be a dictionary."
        )

    result = deepcopy(
        prepared_analysis
    )

    source_context = result.get(
        "source_context",
        [],
    )

    if source_context is None:
        source_context = []

    if not isinstance(source_context, list):
        raise ValueError(
            "prepared_analysis['source_context'] "
            "must be a list."
        )

    application_name = result.get(
        "application_name",
        "Not specified",
    )

    if not isinstance(application_name, str):
        application_name = str(
            application_name
        )

    execution_budget = (
        budget
        if budget is not None
        else LLMExecutionBudget()
    )

    budget_result = execution_budget.apply(
        source_context
    )

    selected_proposer = (
        proposer
        if proposer is not None
        else create_static_proposer(
            provider_name=provider_name,
            api_key=api_key,
        )
    )

    raw_proposals = selected_proposer.propose(
        application_name=application_name,
        chunks=budget_result.selected_chunks,
    )

    if raw_proposals is None:
        raw_proposals = []

    if not isinstance(raw_proposals, list):
        raise TypeError(
            "Static proposer must return a list "
            "of proposal dictionaries."
        )

    aggregation = ProposalAggregator().aggregate(
        raw_proposals
    )

    result["findings"] = (
        aggregation.findings
    )

    llm_execution = {
        **budget_result.to_dict(),
        "provider": selected_proposer.provider_name,
    }

    # Proposers may optionally expose provider-local execution metadata.
    # The pipeline remains provider-independent and does not import or
    # depend on Gemini, OpenAI, Azure OpenAI, or another implementation.
    proposer_execution_report = getattr(
        selected_proposer,
        "last_execution_report",
        None,
    )

    if isinstance(
        proposer_execution_report,
        dict,
    ):
        for field_name in (
            "chunks_attempted",
            "chunks_succeeded",
            "chunks_failed",
        ):
            field_value = proposer_execution_report.get(
                field_name
            )

            if (
                isinstance(field_value, int)
                and not isinstance(field_value, bool)
            ):
                llm_execution[field_name] = (
                    field_value
                )

        failed_chunks = proposer_execution_report.get(
            "failed_chunks"
        )

        if isinstance(failed_chunks, list):
            llm_execution["failed_chunks"] = deepcopy(
                failed_chunks
            )

    result["llm_execution"] = llm_execution

    result["aggregation"] = {
        "proposals_received":
            aggregation.proposals_received,

        "proposals_retained":
            aggregation.proposals_retained,

        "duplicates_merged":
            aggregation.duplicates_merged,
    }

    result["proposal_provider"] = (
        selected_proposer.provider_name
    )

    attempted = int(llm_execution.get("chunks_attempted", 0) or 0)
    succeeded = int(llm_execution.get("chunks_succeeded", 0) or 0)
    failed = int(llm_execution.get("chunks_failed", 0) or 0)

    if selected_proposer.provider_name == "NONE":
        proposal_status = "DISABLED"
    elif attempted > 0 and failed > 0 and succeeded == 0:
        proposal_status = "FAILED"
    elif failed > 0:
        proposal_status = "PARTIAL"
    else:
        proposal_status = "SUCCESS"

    result["proposal_status"] = proposal_status
    result["proposal_execution"] = deepcopy(llm_execution)

    return result