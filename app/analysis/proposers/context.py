"""
Provider-independent analysis context.

AnalysisContext is the boundary between analysis strategies and LLM
providers.

Static analysis, dynamic analysis, and future analysis strategies may
produce different native observations. Before those observations reach
an LLM provider, they can be represented using this common contract.

This module deliberately knows nothing about specific vulnerability
types, CWE identifiers, LLM vendors, verification techniques, or
application targets.

Architecture principle:

    Native analysis observation
        ->
    AnalysisContext
        ->
    LLM proposer
        ->
    Candidate proposal
        ->
    Evidence verifies
        ->
    Human decides
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class AnalysisContext:
    """
    One bounded, provider-independent analysis context.

    ``content`` contains the material that may be analysed by an LLM.

    ``metadata`` preserves strategy-specific provenance without forcing
    the provider-independent contract to know every possible field used
    by static, dynamic, or future analysis strategies.

    The object represents observations and context only. It does not
    represent a vulnerability finding or verification result.
    """

    context_id: str
    scan_type: str
    content: str

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        context_id = self.context_id.strip()

        if not context_id:
            raise ValueError(
                "context_id must not be empty."
            )

        scan_type = self.scan_type.strip().upper()

        if not scan_type:
            raise ValueError(
                "scan_type must not be empty."
            )

        if not isinstance(self.content, str):
            raise TypeError(
                "content must be a string."
            )

        if not isinstance(self.metadata, dict):
            raise TypeError(
                "metadata must be a dictionary."
            )

        object.__setattr__(
            self,
            "context_id",
            context_id,
        )

        object.__setattr__(
            self,
            "scan_type",
            scan_type,
        )

        # Defensive copy prevents callers from later mutating the
        # dictionary originally supplied to this frozen context.
        object.__setattr__(
            self,
            "metadata",
            dict(self.metadata),
        )

    @property
    def char_count(self) -> int:
        """Return the exact size of provider-visible content."""

        return len(self.content)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""

        return asdict(self)