

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ProbeCandidate:


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
