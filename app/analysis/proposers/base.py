"""
Provider-independent contracts for vulnerability proposers.

A proposer may use Gemini, OpenAI, Azure OpenAI, a private enterprise
model, a local model, or another implementation.

All proposers return candidate vulnerability proposals using the same
application-level contract.

The generic LLMProposer contract is intentionally independent of scan
type. Static and dynamic analysis may therefore share provider
implementations without coupling the provider layer to one analysis
strategy.

Architecture principle:

    Analysis context
        ->
    AI proposes
        ->
    Evidence verifies
        ->
    Human decides

A proposer NEVER verifies a vulnerability and NEVER changes a finding
to PROVED or REFUTED.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class LLMProposer(ABC):
    """
    Provider-independent vulnerability proposal contract.

    Implementations receive bounded analysis contexts prepared by an
    upstream analysis strategy.

    The upstream strategy may be static analysis, dynamic analysis, or
    another future analysis source.

    Proposers return raw candidate proposal dictionaries. Downstream
    components are responsible for aggregation, canonical Finding
    creation, evidence verification, and human review.

    Provider implementations must not assume that a candidate proposal
    is verified merely because the model returned it.
    """

    provider_name = "UNKNOWN"

    @abstractmethod
    def propose(
        self,
        *,
        application_name: str,
        contexts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Propose potential vulnerabilities from bounded analysis context.

        Implementations must:

        - analyse only the supplied contexts;
        - return candidate proposals only;
        - never claim deterministic verification;
        - preserve provenance where possible;
        - return an empty list when no reasonable proposal exists;
        - avoid mutating the supplied contexts.

        The exact context schema is defined by the upstream analysis
        strategy and its adapter.
        """

        raise NotImplementedError


class StaticProposer(LLMProposer):
    """
    Backward-compatible static-analysis proposer contract.

    Existing static proposer implementations use ``chunks`` rather than
    the generic ``contexts`` argument. This compatibility layer preserves
    that public contract while the provider layer is migrated
    incrementally.

    New provider-independent functionality should target LLMProposer.

    This class can be removed only after all static callers and tests
    have migrated to the generic context contract.
    """

    @abstractmethod
    def propose(
        self,
        *,
        application_name: str,
        chunks: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Propose potential vulnerabilities from bounded source chunks.

        Implementations must:

        - analyse only the supplied chunks;
        - return candidate proposals only;
        - never claim deterministic verification;
        - preserve source provenance where possible;
        - return an empty list when no reasonable proposal exists;
        - avoid mutating the supplied chunks.
        """

        raise NotImplementedError