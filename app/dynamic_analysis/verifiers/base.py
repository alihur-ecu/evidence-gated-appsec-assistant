

from __future__ import annotations

from abc import ABC, abstractmethod

from app.dynamic_analysis.evidence import (
    EvidenceBundle,
    VerificationResult,
)


class EvidenceVerifier(ABC):
   

    verifier_id: str

    @abstractmethod
    def supports(self, evidence: EvidenceBundle) -> bool:
        """"""

    @abstractmethod
    def verify(self, evidence: EvidenceBundle) -> VerificationResult:
        """"""
