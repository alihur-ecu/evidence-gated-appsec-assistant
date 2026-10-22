
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
    llm_provider: str | None = None,
    llm_api_key: str | None = None,
) -> dict:
  

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

      
        result = aggregate_analysis_result(
            result
        )

    elif provider_name == "static_source":
        prepared_analysis = (
            run_static_source_analysis(
                **provider_arguments
            )
        )

    
        result = run_static_proposal_pipeline(
            prepared_analysis=prepared_analysis,
            provider_name=llm_provider,
            api_key=llm_api_key,
        )

    else:
        
        raise ValueError(
            f"Provider '{provider_name}' is not implemented."
        )

    result["analysis_id"] = (
        f"A-{uuid4().hex[:8].upper()}"
    )

    return result