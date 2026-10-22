import pytest

from app.dynamic_analysis.evidence import (
    EvidenceBundle,
    RuntimeObservation,
    VerificationDecision,
    VerificationResult,
)
from app.dynamic_analysis.verifiers import (
    EvidenceVerifier,
    VerifierRegistry,
)


def make_evidence(capability="fake-capability"):
    observation = RuntimeObservation(
        observation_id="obs-1",
        label="test",
        method="GET",
        url="https://example.test/",
        status_code=200,
        response_length=10,
    )
    return EvidenceBundle(
        evidence_id="evidence-1",
        capability=capability,
        endpoint="https://example.test/",
        method="GET",
        observations=(observation,),
    )


class FakeVerifier(EvidenceVerifier):
    verifier_id = "fake-verifier"

    def supports(self, evidence):
        return evidence.capability == "fake-capability"

    def verify(self, evidence):
        return VerificationResult(
            evidence_id=evidence.evidence_id,
            verifier_id=self.verifier_id,
            decision=VerificationDecision.NEEDS_HUMAN,
            reasons=("Test verifier does not prove or refute.",),
        )


class SecondVerifier(FakeVerifier):
    verifier_id = "second-verifier"


def test_registry_registers_and_returns_verifier():
    verifier = FakeVerifier()
    registry = VerifierRegistry([verifier])

    assert len(registry) == 1
    assert registry.get("fake-verifier") is verifier


def test_registry_selects_verifiers_by_evidence_support():
    registry = VerifierRegistry([
        FakeVerifier(),
        SecondVerifier(),
    ])

    assert len(registry.applicable(make_evidence())) == 2
    assert registry.applicable(make_evidence("other")) == ()


def test_registry_rejects_duplicate_verifier_ids():
    registry = VerifierRegistry([FakeVerifier()])

    with pytest.raises(ValueError, match="already registered"):
        registry.register(FakeVerifier())


def test_verifier_returns_deterministic_result_separate_from_human_review():
    evidence = make_evidence()
    result = FakeVerifier().verify(evidence)

    assert result.decision is VerificationDecision.NEEDS_HUMAN
    assert result.evidence_id == evidence.evidence_id
    assert result.verifier_id == "fake-verifier"
