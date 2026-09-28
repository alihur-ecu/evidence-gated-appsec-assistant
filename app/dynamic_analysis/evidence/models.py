"""Generic runtime-evidence models for dynamic security analysis.

These models deliberately contain no vulnerability-specific logic. They
represent observations, evidence bundles, and deterministic verification
results that can be shared by future probe and verifier capabilities.

Architecture principle:

    AI proposes -> Evidence verifies -> Human decides
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class VerificationDecision(str, Enum):
    """Deterministic outcome produced by an evidence verifier."""

    PROVED = "PROVED"
    REFUTED = "REFUTED"
    NEEDS_HUMAN = "NEEDS_HUMAN"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class RuntimeObservation:
    """One HTTP/runtime observation collected by a dynamic probe.

    The model stores facts, not a vulnerability conclusion. Probe-specific
    details may be placed in ``metadata`` without changing this shared model.
    Sensitive authentication material should never be stored here.
    """

    observation_id: str
    label: str
    method: str
    url: str
    status_code: int | None
    response_length: int | None
    elapsed_ms: float | None = None
    response_digest: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.observation_id.strip():
            raise ValueError("observation_id must not be empty.")
        if not self.label.strip():
            raise ValueError("label must not be empty.")
        if not self.method.strip():
            raise ValueError("method must not be empty.")
        if not self.url.strip():
            raise ValueError("url must not be empty.")
        if self.status_code is not None and not 100 <= self.status_code <= 599:
            raise ValueError("status_code must be between 100 and 599.")
        if self.response_length is not None and self.response_length < 0:
            raise ValueError("response_length must be zero or greater.")
        if self.elapsed_ms is not None and self.elapsed_ms < 0:
            raise ValueError("elapsed_ms must be zero or greater.")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvidenceBundle:
    """Evidence collected for one candidate/context by one probe capability.

    ``capability`` is intentionally generic (for example, a future capability
    may describe an injection, output-encoding, or access-control probe).
    Nothing in this class assumes SQL injection, DVWA, a specific parameter,
    or a particular authentication mechanism.
    """

    evidence_id: str
    capability: str
    endpoint: str
    method: str
    observations: tuple[RuntimeObservation, ...]

    finding_id: str | None = None
    context_id: str | None = None
    parameter: str | None = None
    baseline_observation_id: str | None = None
    signals: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    collected_at_utc: str = field(default_factory=_utc_now_iso)

    def __post_init__(self) -> None:
        if not self.evidence_id.strip():
            raise ValueError("evidence_id must not be empty.")
        if not self.capability.strip():
            raise ValueError("capability must not be empty.")
        if not self.endpoint.strip():
            raise ValueError("endpoint must not be empty.")
        if not self.method.strip():
            raise ValueError("method must not be empty.")
        if not self.observations:
            raise ValueError("observations must contain at least one observation.")

        observation_ids = {
            observation.observation_id
            for observation in self.observations
        }
        if len(observation_ids) != len(self.observations):
            raise ValueError("observation_id values must be unique within evidence.")

        if (
            self.baseline_observation_id is not None
            and self.baseline_observation_id not in observation_ids
        ):
            raise ValueError(
                "baseline_observation_id must reference an observation in the bundle."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "capability": self.capability,
            "endpoint": self.endpoint,
            "method": self.method,
            "finding_id": self.finding_id,
            "context_id": self.context_id,
            "parameter": self.parameter,
            "baseline_observation_id": self.baseline_observation_id,
            "observations": [
                observation.to_dict()
                for observation in self.observations
            ],
            "signals": dict(self.signals),
            "metadata": dict(self.metadata),
            "collected_at_utc": self.collected_at_utc,
        }


@dataclass(frozen=True)
class VerificationResult:
    """Deterministic verifier output kept separate from human review."""

    evidence_id: str
    verifier_id: str
    decision: VerificationDecision
    reasons: tuple[str, ...]
    signals_used: tuple[str, ...] = ()
    verified_at_utc: str = field(default_factory=_utc_now_iso)

    def __post_init__(self) -> None:
        if not self.evidence_id.strip():
            raise ValueError("evidence_id must not be empty.")
        if not self.verifier_id.strip():
            raise ValueError("verifier_id must not be empty.")
        if not self.reasons:
            raise ValueError("reasons must contain at least one explanation.")
        if any(not reason.strip() for reason in self.reasons):
            raise ValueError("reasons must not contain empty values.")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["decision"] = self.decision.value
        return data
