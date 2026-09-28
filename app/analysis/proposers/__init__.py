"""
Static vulnerability proposer abstractions.

Provider-specific implementations are intentionally isolated from the
rest of the analysis pipeline.
"""

from app.analysis.proposers.base import StaticProposer
from app.analysis.proposers.factory import (
    NoOpStaticProposer,
    create_static_proposer,
    get_configured_llm_provider,
)


__all__ = [
    "StaticProposer",
    "NoOpStaticProposer",
    "create_static_proposer",
    "get_configured_llm_provider",
]