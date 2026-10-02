"""
Generic dynamic-analysis orchestration pipeline.

This module coordinates the dynamic-analysis stages without detecting
or verifying vulnerabilities itself.

Pipeline:

    User target
        ->
    DynamicTarget validation
        ->
    Bounded read-only discovery
        ->
    Dynamic context construction
        ->
    AnalysisContext adaptation
        ->
    Selected LLM proposer
        ->
    Candidate vulnerability proposals

Security principle:

    AI proposes -> Evidence verifies -> Human decides
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from app.analysis.proposers.adapters import adapt_dynamic_contexts
from app.analysis.proposers.factory import create_static_proposer
from app.dynamic_analysis.context_builder import DynamicContextBuilder
from app.dynamic_analysis.discovery import DynamicDiscovery
from app.dynamic_analysis.target import DynamicTarget, build_dynamic_target


@dataclass
class DynamicPipelineResult:
    """
    Result of one dynamic-analysis orchestration run.

    Candidate proposals are intentionally kept separate from
    verification. Nothing returned here is automatically proven.
    """

    target: dict[str, Any]
    discovery: dict[str, Any]
    context_build: dict[str, Any]
    proposal_provider: str
    proposals: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DynamicAnalysisPipeline:
    """
    Coordinate generic dynamic analysis.

    Dependencies may be injected for deterministic testing and future
    extension.

    No target, vulnerability type, LLM provider, or application type
    is hardcoded here.
    """

    def __init__(
        self,
        *,
        discovery: DynamicDiscovery | None = None,
        context_builder: DynamicContextBuilder | None = None,
        proposer: Any | None = None,
    ) -> None:
        self.discovery = (
            discovery
            if discovery is not None
            else DynamicDiscovery()
        )

        self.context_builder = (
            context_builder
            if context_builder is not None
            else DynamicContextBuilder()
        )

        self.proposer = (
            proposer
            if proposer is not None
            else create_static_proposer()
        )

    def run(
        self,
        *,
        target_url: str,
        application_name: str,
    ) -> DynamicPipelineResult:
        """
        Run one bounded dynamic-analysis pass.

        This method performs discovery and candidate generation only.
        It does not execute vulnerability payloads and does not mark
        proposals as verified.
        """

        if not isinstance(application_name, str):
            raise TypeError(
                "application_name must be a string."
            )

        application_name = application_name.strip()

        if not application_name:
            raise ValueError(
                "application_name must not be empty."
            )

        target = build_dynamic_target(target_url)

        discovery_result = self.discovery.discover(target)

        context_result = self.context_builder.build(
            discovery_result
        )

        analysis_contexts = adapt_dynamic_contexts(
            context_result.contexts
        )

        proposals = self._propose(
            application_name=application_name,
            contexts=analysis_contexts,
        )

        return DynamicPipelineResult(
            target=self._target_to_dict(target),
            discovery=discovery_result.to_dict(),
            context_build=context_result.to_dict(),
            proposal_provider=self._provider_name(),
            proposals=proposals,
        )

    def _propose(
        self,
        *,
        application_name: str,
        contexts: list,
    ) -> list[dict[str, Any]]:
        """
        Generate candidate proposals through the generic context API.

        Dynamic analysis requires a proposer that implements
        propose_contexts(). Providers that have not yet migrated to
        the generic context interface fail explicitly.
        """

        propose_contexts = getattr(
            self.proposer,
            "propose_contexts",
            None,
        )

        if not callable(propose_contexts):
            raise TypeError(
                "The selected LLM proposer does not support "
                "generic AnalysisContext input. "
                "Implement propose_contexts() before using "
                "this provider for dynamic analysis."
            )

        proposals = propose_contexts(
            application_name=application_name,
            contexts=contexts,
        )

        if not isinstance(proposals, list):
            raise TypeError(
                "LLM proposer must return a list "
                "of candidate proposals."
            )

        return proposals

    @staticmethod
    def _target_to_dict(
        target: DynamicTarget,
    ) -> dict[str, Any]:
        """
        Serialize DynamicTarget without requiring a to_dict() method.

        DynamicTarget is intentionally kept focused on target
        validation and same-origin decisions.
        """

        return {
            "original_url": target.original_url,
            "base_url": target.base_url,
            "origin": target.origin,
            "scheme": target.scheme,
            "hostname": target.hostname,
            "port": target.port,
            "start_path": target.start_path,
        }

    def _provider_name(self) -> str:
        """
        Return a stable provider label for reporting.

        This is reporting metadata only and does not affect behaviour.
        """

        provider_name = getattr(
            self.proposer,
            "provider_name",
            None,
        )

        if (
            isinstance(provider_name, str)
            and provider_name.strip()
        ):
            return provider_name.strip().upper()

        return (
            self.proposer
            .__class__
            .__name__
            .upper()
        )


def run_dynamic_analysis(
    *,
    target_url: str,
    application_name: str,
    discovery: DynamicDiscovery | None = None,
    context_builder: DynamicContextBuilder | None = None,
    proposer: Any | None = None,
) -> dict[str, Any]:
    """
    Convenience entry point for web/API integration.

    Returning a plain dictionary keeps this boundary easy to consume
    from Flask, CLI tools, tests, and future API layers.
    """

    pipeline = DynamicAnalysisPipeline(
        discovery=discovery,
        context_builder=context_builder,
        proposer=proposer,
    )

    result = pipeline.run(
        target_url=target_url,
        application_name=application_name,
    )

    return result.to_dict()
