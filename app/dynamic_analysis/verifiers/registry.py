"""Registry for deterministic evidence verifiers."""

from __future__ import annotations

from collections.abc import Iterable

from app.dynamic_analysis.evidence import EvidenceBundle
from app.dynamic_analysis.verifiers.base import EvidenceVerifier


class VerifierRegistry:
    """Maintain verifiers without vulnerability-specific pipeline branches."""

    def __init__(self, verifiers: Iterable[EvidenceVerifier] = ()) -> None:
        self._verifiers: dict[str, EvidenceVerifier] = {}
        for verifier in verifiers:
            self.register(verifier)

    def register(self, verifier: EvidenceVerifier) -> None:
        if not isinstance(verifier, EvidenceVerifier):
            raise TypeError("verifier must implement EvidenceVerifier.")

        verifier_id = getattr(verifier, "verifier_id", "")
        if not isinstance(verifier_id, str) or not verifier_id.strip():
            raise ValueError("verifier.verifier_id must be a non-empty string.")
        if verifier_id in self._verifiers:
            raise ValueError(
                f"verifier_id already registered: {verifier_id}"
            )

        self._verifiers[verifier_id] = verifier

    def get(self, verifier_id: str) -> EvidenceVerifier:
        try:
            return self._verifiers[verifier_id]
        except KeyError as exc:
            raise KeyError(
                f"Unknown verifier_id: {verifier_id}"
            ) from exc

    def applicable(
        self,
        evidence: EvidenceBundle,
    ) -> tuple[EvidenceVerifier, ...]:
        return tuple(
            verifier
            for verifier in self._verifiers.values()
            if verifier.supports(evidence)
        )

    def all(self) -> tuple[EvidenceVerifier, ...]:
        return tuple(self._verifiers.values())

    def __len__(self) -> int:
        return len(self._verifiers)
