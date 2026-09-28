import pytest

from app.dynamic_analysis.evidence import (
    EvidenceBundle,
    RuntimeObservation,
    VerificationDecision,
    VerificationResult,
)


def make_observation(observation_id="obs-1"):
    return RuntimeObservation(
        observation_id=observation_id,
        label="baseline",
        method="GET",
        url="https://example.test/search?q=test",
        status_code=200,
        response_length=123,
        elapsed_ms=12.5,
        metadata={"result_count": 1},
    )


def test_runtime_observation_serialises_without_conclusion():
    observation = make_observation()
    data = observation.to_dict()

    assert data["observation_id"] == "obs-1"
    assert data["status_code"] == 200
    assert "decision" not in data
    assert "vulnerability" not in data


def test_evidence_bundle_is_generic_and_preserves_observations():
    observation = make_observation()
    evidence = EvidenceBundle(
        evidence_id="evidence-1",
        capability="example-runtime-capability",
        endpoint="https://example.test/search",
        method="GET",
        parameter="q",
        observations=(observation,),
        baseline_observation_id="obs-1",
        signals={"behaviour_changed": False},
    )

    data = evidence.to_dict()

    assert data["capability"] == "example-runtime-capability"
    assert data["parameter"] == "q"
    assert data["observations"][0]["observation_id"] == "obs-1"
    assert data["signals"] == {"behaviour_changed": False}


def test_evidence_rejects_unknown_baseline_observation():
    with pytest.raises(ValueError, match="baseline_observation_id"):
        EvidenceBundle(
            evidence_id="evidence-1",
            capability="example",
            endpoint="https://example.test/",
            method="GET",
            observations=(make_observation(),),
            baseline_observation_id="missing",
        )


def test_evidence_requires_at_least_one_observation():
    with pytest.raises(ValueError, match="at least one"):
        EvidenceBundle(
            evidence_id="evidence-1",
            capability="example",
            endpoint="https://example.test/",
            method="GET",
            observations=(),
        )


def test_verification_result_keeps_machine_decision_and_reason():
    result = VerificationResult(
        evidence_id="evidence-1",
        verifier_id="test-verifier",
        decision=VerificationDecision.NEEDS_HUMAN,
        reasons=("Evidence is incomplete.",),
        signals_used=("all_requests_successful",),
    )

    data = result.to_dict()

    assert data["decision"] == "NEEDS_HUMAN"
    assert data["reasons"] == ("Evidence is incomplete.",)
