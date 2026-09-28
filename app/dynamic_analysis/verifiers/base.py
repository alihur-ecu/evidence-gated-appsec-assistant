"""Base contract for deterministic runtime-evidence verifiers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.dynamic_analysis.evidence import (
    EvidenceBundle,
    VerificationResult,
)


class EvidenceVerifier(ABC):
    """Verify evidence deterministically, independently of the LLM."""

    verifier_id: str

    @abstractmethod
    def supports(self, evidence: EvidenceBundle) -> bool:
        """Return whether this verifier understands the supplied evidence."""

    @abstractmethod
    def verify(self, evidence: EvidenceBundle) -> VerificationResult:
        """Return a deterministic verification result for ``evidence``."""
