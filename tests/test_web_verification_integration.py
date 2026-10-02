from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from app.dynamic_analysis.evidence.models import (
    EvidenceBundle,
    RuntimeObservation,
    VerificationDecision,
    VerificationResult,
)
from app.models.finding import Finding, FindingStatus, FindingType
from app.web import server


def _finding() -> Finding:
    return Finding(
        finding_id="WEB-PHASE3E-001",
        finding_type=FindingType.SQL_INJECTION,
        endpoint="https://example.test/search",
        method="GET",
        parameter="q",
        explanation="Candidate SQL injection proposal.",
        status=FindingStatus.PROPOSED,
    )


def _service_result(finding: Finding):
    baseline = RuntimeObservation(
        observation_id="obs-baseline",
        label="BASELINE",
        method="GET",
        url=finding.endpoint,
        status_code=200,
        response_length=120,
        response_digest="baseline-digest",
        metadata={"error_detected": False},
    )
    test = RuntimeObservation(
        observation_id="obs-test",
        label="TEST_1",
        method="GET",
        url=finding.endpoint,
        status_code=200,
        response_length=80,
        response_digest="test-digest",
        metadata={
            "error_detected": True,
            "error_family": "SQL_SYNTAX",
            "error_signature": "sql_syntax_error",
        },
    )
    evidence = EvidenceBundle(
        evidence_id="evidence-web-phase3e",
        capability="INJECTION_DIFFERENTIAL",
        endpoint=finding.endpoint,
        method=finding.method,
        parameter=finding.parameter,
        baseline_observation_id="obs-baseline",
        observations=(baseline, test),
    )
    verification = VerificationResult(
        evidence_id=evidence.evidence_id,
        verifier_id="injection-differential-verifier",
        decision=VerificationDecision.PROVED,
        reasons=("Deterministic runtime evidence proved the candidate.",),
        signals_used=("error_detected", "error_family"),
    )
    return SimpleNamespace(
        finding_id=finding.finding_id,
        finding_status=FindingStatus.PROVED,
        candidate=SimpleNamespace(),
        evidence=evidence,
        verification=verification,
    )


def test_verify_route_uses_phase3e_service_and_preserves_web_contract(monkeypatch):
    finding = _finding()
    result = _service_result(finding)

    server.FINDINGS.clear()
    server.FINDING_METADATA.clear()
    server.EVIDENCE_BY_FINDING.clear()
    server.REVIEW_BY_FINDING.clear()

    server.FINDINGS[finding.finding_id] = finding
    server.REVIEW_BY_FINDING[finding.finding_id] = {
        "final_severity": "",
        "reviewer_comment": "",
        "human_decision": None,
    }

    class FakeService:
        def __init__(self, session=None):
            self.session = session

        def verify(self, received_finding):
            assert received_finding is finding
            return result

    monkeypatch.setattr(server, "DynamicVerificationService", FakeService)
    monkeypatch.setattr(
        server,
        "save_web_evidence",
        lambda evidence: (
            Path("artifacts/test.json"),
            Path("artifacts/test.csv"),
        ),
    )

    client = server.app.test_client()
    response = client.post(f"/findings/{finding.finding_id}/verify")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["verification_status"] == "COMPLETED"
    assert payload["evidence_gate_result"] == "PROVED"
    assert finding.status is FindingStatus.PROVED

    stored = server.EVIDENCE_BY_FINDING[finding.finding_id]
    assert stored["execution_status"] == "COMPLETED"
    assert stored["capability"] == "INJECTION_DIFFERENTIAL"
    assert stored["verification"]["decision"] == "PROVED"
    assert len(stored["observations"]) == 2

    view_model = server.build_view_model(finding)
    assert view_model["verification_status"] == "COMPLETED"
    assert view_model["evidence_gate_result"] == "PROVED"
    assert len(view_model["evidence"]) == 2


def test_verify_route_rejects_unsupported_finding_type():
    finding = Finding(
        finding_id="WEB-XSS-001",
        finding_type=FindingType.XSS,
        endpoint="https://example.test/search",
        method="GET",
        parameter="q",
        explanation="Candidate XSS proposal.",
        status=FindingStatus.PROPOSED,
    )

    server.FINDINGS.clear()
    server.EVIDENCE_BY_FINDING.clear()
    server.FINDINGS[finding.finding_id] = finding

    client = server.app.test_client()
    response = client.post(f"/findings/{finding.finding_id}/verify")

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["ok"] is False
    assert finding.status is FindingStatus.PROPOSED


def test_view_model_exposes_ready_verification_route():
    finding = _finding()

    server.EVIDENCE_BY_FINDING.clear()
    server.REVIEW_BY_FINDING.clear()

    view_model = server.build_view_model(finding)

    assert view_model["verification_supported"] is True
    assert view_model["verification_readiness"] == "READY"
    assert view_model["verification_capability"] == "INJECTION_DIFFERENTIAL"
    assert view_model["verification_verifier"] == "injection_differential"
    assert view_model["verification_mode"] == "RUNTIME"
    assert view_model["verification_missing_fields"] == []
    assert (
        view_model["verification_reason"]
        == "Independent verification capability is ready."
    )


def test_verify_route_reports_context_required_without_running_service(
    monkeypatch,
):
    finding = Finding(
        finding_id="WEB-SQL-CONTEXT-001",
        finding_type=FindingType.SQL_INJECTION,
        endpoint=None,
        method=None,
        parameter="id",
        explanation="Static SQL injection proposal without runtime route context.",
        status=FindingStatus.PROPOSED,
    )

    server.FINDINGS.clear()
    server.FINDING_METADATA.clear()
    server.EVIDENCE_BY_FINDING.clear()
    server.REVIEW_BY_FINDING.clear()
    server.FINDINGS[finding.finding_id] = finding

    class ServiceMustNotRun:
        def __init__(self, *args, **kwargs):
            raise AssertionError(
                "DynamicVerificationService must not run when context is missing."
            )

    monkeypatch.setattr(
        server,
        "DynamicVerificationService",
        ServiceMustNotRun,
    )

    client = server.app.test_client()
    response = client.post(
        f"/findings/{finding.finding_id}/verify"
    )

    assert response.status_code == 409
    payload = response.get_json()

    assert payload["ok"] is False
    assert payload["code"] == "VERIFICATION_CONTEXT_REQUIRED"
    assert payload["verification_readiness"] == "CONTEXT_REQUIRED"
    assert payload["capability"] == "INJECTION_DIFFERENTIAL"
    assert payload["verifier"] == "injection_differential"
    assert payload["missing_fields"] == ["endpoint", "method"]
    assert finding.status is FindingStatus.PROPOSED
    assert finding.finding_id not in server.EVIDENCE_BY_FINDING


def test_verify_route_reports_unsupported_xss_without_fabricating_evidence(
    monkeypatch,
):
    finding = Finding(
        finding_id="WEB-XSS-ROUTER-001",
        finding_type=FindingType.XSS,
        endpoint="https://example.test/profile",
        method="POST",
        parameter="bio",
        explanation="Candidate XSS proposal.",
        status=FindingStatus.PROPOSED,
    )

    server.FINDINGS.clear()
    server.FINDING_METADATA.clear()
    server.EVIDENCE_BY_FINDING.clear()
    server.REVIEW_BY_FINDING.clear()
    server.FINDINGS[finding.finding_id] = finding

    class ServiceMustNotRun:
        def __init__(self, *args, **kwargs):
            raise AssertionError(
                "DynamicVerificationService must not run for an unsupported capability."
            )

    monkeypatch.setattr(
        server,
        "DynamicVerificationService",
        ServiceMustNotRun,
    )

    client = server.app.test_client()
    response = client.post(
        f"/findings/{finding.finding_id}/verify"
    )

    assert response.status_code == 400
    payload = response.get_json()

    assert payload["ok"] is False
    assert payload["code"] == "VERIFICATION_UNSUPPORTED"
    assert payload["verification_readiness"] == "UNSUPPORTED"
    assert finding.status is FindingStatus.PROPOSED
    assert finding.finding_id not in server.EVIDENCE_BY_FINDING

    view_model = server.build_view_model(finding)

    assert view_model["verification_supported"] is False
    assert view_model["verification_readiness"] == "UNSUPPORTED"
    assert view_model["verification_capability"] is None
    assert view_model["verification_verifier"] is None
    assert view_model["verification_missing_fields"] == []


def test_verify_route_rejects_non_proposed_finding_as_not_eligible(
    monkeypatch,
):
    finding = Finding(
        finding_id="WEB-NOT-ELIGIBLE-001",
        finding_type=FindingType.SQL_INJECTION,
        endpoint="https://example.test/search",
        method="GET",
        parameter="q",
        explanation="Already verified candidate.",
        status=FindingStatus.PROVED,
    )

    server.FINDINGS.clear()
    server.FINDING_METADATA.clear()
    server.EVIDENCE_BY_FINDING.clear()
    server.REVIEW_BY_FINDING.clear()
    server.FINDINGS[finding.finding_id] = finding

    class ServiceMustNotRun:
        def __init__(self, *args, **kwargs):
            raise AssertionError(
                "DynamicVerificationService must not re-run a non-PROPOSED finding."
            )

    monkeypatch.setattr(
        server,
        "DynamicVerificationService",
        ServiceMustNotRun,
    )

    client = server.app.test_client()
    response = client.post(
        f"/findings/{finding.finding_id}/verify"
    )

    assert response.status_code == 409
    payload = response.get_json()

    assert payload["ok"] is False
    assert payload["code"] == "VERIFICATION_NOT_ELIGIBLE"
    assert payload["verification_readiness"] == "NOT_ELIGIBLE"
    assert finding.status is FindingStatus.PROVED
    assert finding.finding_id not in server.EVIDENCE_BY_FINDING

