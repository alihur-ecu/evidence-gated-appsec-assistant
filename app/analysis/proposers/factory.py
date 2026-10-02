"""
Factory for configured static vulnerability proposers.

The rest of the application must not depend directly on Gemini,
OpenAI, Azure OpenAI, LM Studio, or another LLM implementation.

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
    "lmstudio",
    "azure_openai",
    "custom",
}


class NoOpStaticProposer(StaticProposer):
    """
    Proposer used when live LLM candidate generation is disabled.
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

    LLM_PROVIDER is independent from ANALYSIS_PROVIDER.
    """

    return os.getenv(
        "LLM_PROVIDER",
        "none",
    ).strip().lower()


def create_static_proposer(
    provider_name: str | None = None,
    api_key: str | None = None,
) -> StaticProposer:
    """
    Create the configured static proposer.
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

        return GeminiStaticProposer(api_key=api_key)

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

        return OpenAIStaticProposer(api_key=api_key)

    if selected_provider == "lmstudio":
        try:
            from app.analysis.proposers.lmstudio import (
                LMStudioStaticProposer,
            )
        except ImportError as exc:
            raise RuntimeError(
                "LM Studio proposer dependencies are not available. "
                "Install the OpenAI SDK before using "
                "LLM_PROVIDER=lmstudio."
            ) from exc

        return LMStudioStaticProposer(api_key=api_key)

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

    raise RuntimeError(
        f"Could not create LLM provider '{selected_provider}'."
    )