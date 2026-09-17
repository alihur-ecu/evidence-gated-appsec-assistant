"""Provider-independent analysis service.

The web application calls this service instead of calling a mock or Hassan's
future implementation directly. Replacing the provider should not require the
frontend workflow to change.
"""

from __future__ import annotations

import os
from uuid import uuid4

from app.analysis.providers.mock_provider import run_mock_static_analysis


SUPPORTED_PROVIDERS = {"mock"}


def run_static_analysis(*, source_path: str, original_filename: str, application_name: str) -> dict:
    provider_name = os.getenv("ANALYSIS_PROVIDER", "mock").strip().lower()

    if provider_name not in SUPPORTED_PROVIDERS:
        raise ValueError(
            f"Unsupported ANALYSIS_PROVIDER '{provider_name}'. "
            "The current Gabriel branch supports 'mock'."
        )

    if provider_name == "mock":
        result = run_mock_static_analysis(
            source_path=source_path,
            original_filename=original_filename,
            application_name=application_name,
        )
    else:
        raise ValueError(f"Provider '{provider_name}' is not implemented.")

    result["analysis_id"] = f"A-{uuid4().hex[:8].upper()}"
    return result
