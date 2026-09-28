"""
Factory for configured static vulnerability proposers.

The rest of the application must not depend directly on Gemini,
OpenAI, Azure OpenAI, or another LLM implementation.

Provider-specific modules are imported lazily so optional SDK
dependencies are required only when that provider is selected.
"""

from __future__ import annotations

import os

from app.analysis.proposers.base import StaticProposer


SUPPORTED_LLM_PROVIDERS = {
    "none",
    "gemini",
    "openai",
    "azure_openai",
    "custom",
}


class NoOpStaticProposer(StaticProposer):
    """
    Proposer used when live LLM candidate generation is disabled.

    This is useful for:

    - development;
    - source-ingestion testing;
    - offline environments;
    - deployments where an LLM has not yet been configured.
    """

    provider_name = "NONE"

    def propose(
        self,
        *,
        application_name: str,
        chunks: list[dict],
    ) -> list[dict]:
        return []


def get_configured_llm_provider() -> str:
    """
    Return the configured LLM provider name.

    LLM_PROVIDER is intentionally independent from ANALYSIS_PROVIDER.

    Example:

        ANALYSIS_PROVIDER=static_source
        LLM_PROVIDER=gemini

    The first selects the analysis path. The second selects the model
    used to propose candidates within that path.
    """

    return os.getenv(
        "LLM_PROVIDER",
        "none",
    ).strip().lower()


def create_static_proposer(
    provider_name: str | None = None,
) -> StaticProposer:
    """
    Create the configured static proposer.

    Provider modules are imported only when required. This prevents a
    deployment using one provider from requiring every supported LLM
    SDK to be installed.

    Providers that are architecturally reserved but not implemented
    yet fail explicitly rather than silently falling back to another
    model.
    """

    selected_provider = (
        provider_name.strip().lower()
        if provider_name is not None
        else get_configured_llm_provider()
    )

    if selected_provider not in SUPPORTED_LLM_PROVIDERS:
        raise ValueError(
            f"Unsupported LLM_PROVIDER "
            f"'{selected_provider}'. Supported providers: "
            f"{', '.join(sorted(SUPPORTED_LLM_PROVIDERS))}."
        )

    if selected_provider == "none":
        return NoOpStaticProposer()

    if selected_provider == "gemini":
        try:
            from app.analysis.proposers.gemini import (
                GeminiStaticProposer,
            )
        except ImportError as exc:
            raise RuntimeError(
                "Gemini proposer dependencies are not available. "
                "Install the Gemini provider dependencies before "
                "using LLM_PROVIDER=gemini."
            ) from exc

        return GeminiStaticProposer()

    if selected_provider == "openai":
        try:
            from app.analysis.proposers.openai import (
                OpenAIStaticProposer,
            )
        except ImportError as exc:
            raise RuntimeError(
                "OpenAI proposer dependencies are not available. "
                "Install the OpenAI provider dependencies before "
                "using LLM_PROVIDER=openai."
            ) from exc

        return OpenAIStaticProposer()

    if selected_provider == "azure_openai":
        raise NotImplementedError(
            "The Azure OpenAI static proposer is reserved but has "
            "not been implemented yet."
        )

    if selected_provider == "custom":
        raise NotImplementedError(
            "The custom static proposer is reserved but has not "
            "been implemented yet."
        )

    # Defensive fallback.
    raise RuntimeError(
        f"Could not create LLM provider '{selected_provider}'."
    )