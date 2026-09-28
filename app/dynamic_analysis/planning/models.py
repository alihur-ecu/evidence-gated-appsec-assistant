"""Neutral planning models for dynamic active observation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProbeCandidate:
    """One discovered input surface eligible for later active observation.

    A candidate is not a vulnerability finding and contains no payload or
    verification conclusion.

    ``endpoint`` is the canonical request destination (query string removed).
    ``observed_value`` preserves a value seen during discovery when one is
    available. It is observational metadata only; it is not a payload.

    ``fixed_parameters`` preserves reproducible sibling form controls required
    to replay the observed request context while ``parameter`` is varied.
    """

    endpoint: str
    method: str
    parameter: str
    parameter_location: str
    input_type: str | None
    source: str
    observed_value: str | None = None
    fixed_parameters: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.endpoint.strip():
            raise ValueError("endpoint must not be empty.")
        if self.method.upper() not in {"GET", "POST"}:
            raise ValueError("method must be GET or POST.")
        if not self.parameter.strip():
            raise ValueError("parameter must not be empty.")
        if self.parameter_location not in {"query", "body"}:
            raise ValueError("parameter_location must be query or body.")
        if self.source not in {"ENDPOINT", "FORM"}:
            raise ValueError("source must be ENDPOINT or FORM.")
        if self.parameter in self.fixed_parameters:
            raise ValueError(
                "fixed_parameters must not contain the parameter under test."
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
