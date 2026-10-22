from __future__ import annotations

import requests
import pytest

from app.dynamic_analysis.discovery import (
    DiscoveredEndpoint,
    DiscoveredForm,
    DiscoveredParameter,
    DiscoveryResult,
)
from app.dynamic_analysis.evidence.models import (
    EvidenceBundle,
    RuntimeObservation,
    VerificationDecision,
    VerificationResult,
)
from app.dynamic_analysis.planning.candidate_builder import ProbeCandidateBuilder
from app.dynamic_analysis.probes.injection.probe import (
    InjectionProbeInput,
)
from app.dynamic_analysis.target import build_dynamic_target
from app.dynamic_analysis.verification_service import (
    CandidateNotFoundError,
    DynamicVerificationError,
    DynamicVerificationService,
    UnsupportedFindingError,
    verify_dynamic_finding,
)
from app.models.finding import (
    Finding,
    FindingStatus,
    FindingType,
    ScanType,
)


ENDPOINT = (
    "http://localhost:4280/vulnerabilities/sqli/"
)


def _finding(**overrides):
    values = {
        "finding_type": FindingType.SQL_INJECTION,
        "explanation": (
            "Candidate SQL injection proposed by analysis."
        ),
        "scan_type": ScanType.DYNAMIC,
        "endpoint": ENDPOINT,
        "method": "GET",
        "parameter": "id",
        "status": FindingStatus.PROPOSED,
    }

    values.update(overrides)

    return Finding(**values)


def _discovery_result():
    target = build_dynamic_target(
        ENDPOINT
    )

    return DiscoveryResult(
        target=target,
        endpoints=[
            DiscoveredEndpoint(
                url=ENDPOINT,
                method="GET",
                parameters=(
                    DiscoveredParameter(
                        name="id",
                        location="query",
                        input_type="text",
                        observed_value="",
                    ),
                ),
            )
        ],
        forms=[
            DiscoveredForm(
                source_url=ENDPOINT,
                action_url=ENDPOINT,
                method="GET",
                parameters=(
                    DiscoveredParameter(
                        name="id",
                        location="query",
                        input_type="text",
                        observed_value="",
                    ),
                    DiscoveredParameter(
                        name="Submit",
                        location="query",
                        input_type="submit",
                        observed_value="Submit",
                    ),
                ),
            )
        ],
    )


class FakeDiscovery:

    def __init__(
        self,
        result,
    ):
        self.result = result
        self.targets = []

    def discover(
        self,
        target,
    ):
        self.targets.append(
            target
        )

        return self.result


class FakeInputFactory:

    def __init__(self):
        self.candidate = None
        self.session = None

    def build_with_resolved_baseline(
        self,
        candidate,
        *,
        session,
    ):
        self.candidate = candidate
        self.session = session

        return InjectionProbeInput(
            endpoint=candidate.endpoint,
            method=candidate.method,
            parameter=candidate.parameter,
            baseline_value="1",
            test_values=(
                "test-a",
                "test-b",
            ),
            fixed_parameters=(
                candidate.fixed_parameters
            ),
        )


class FakeProbe:

    def __init__(
        self,
        evidence,
    ):
        self.evidence = evidence
        self.context = None
        self.session = None

    def collect(
        self,
        *,
        context,
        session,
    ):
        self.context = context
        self.session = session

        return self.evidence


class FakeVerifier:

    def __init__(
        self,
        result,
    ):
        self.result = result
        self.evidence = None

    def verify(
        self,
        evidence,
    ):
        self.evidence = evidence

        return self.result


def _evidence():
    baseline = RuntimeObservation(
        observation_id="baseline-1",
        label="BASELINE",
        method="GET",
        url=ENDPOINT,
        status_code=200,
        response_length=100,
        response_digest="baseline-digest",
        metadata={
            "error_detected": False,
        },
    )

    test = RuntimeObservation(
        observation_id="test-1",
        label="TEST_1",
        method="GET",
        url=ENDPOINT,
        status_code=200,
        response_length=50,
        response_digest="test-digest",
        metadata={
            "error_detected": True,
            "error_family": "SQL_SYNTAX",
            "error_signature": (
                "sql_syntax_error"
            ),
        },
    )

    return EvidenceBundle(
        evidence_id="evidence-1",
        capability="INJECTION_DIFFERENTIAL",
        endpoint=ENDPOINT,
        method="GET",
        parameter="id",
        baseline_observation_id="baseline-1",
        observations=(
            baseline,
            test,
        ),
    )


def _verification(
    decision=VerificationDecision.PROVED,
):
    return VerificationResult(
        evidence_id="evidence-1",
        verifier_id=(
            "injection-differential-verifier"
        ),
        decision=decision,
        reasons=(
            "Deterministic test result.",
        ),
        signals_used=(
            "error_detected",
        ),
    )


def test_service_orchestrates_existing_verification_components():
    session = requests.Session()

    discovery = FakeDiscovery(
        _discovery_result()
    )

    input_factory = FakeInputFactory()

    evidence = _evidence()

    probe = FakeProbe(
        evidence
    )

    verifier = FakeVerifier(
        _verification()
    )

    service = DynamicVerificationService(
        session=session,
        discovery=discovery,
        input_factory=input_factory,
        probe=probe,
        verifier=verifier,
    )

    finding = _finding()

    result = service.verify(
        finding
    )

    assert (
        result.finding_id
        == finding.finding_id
    )

    assert (
        result.finding_status
        is FindingStatus.PROVED
    )

    assert (
        result.evidence
        is evidence
    )

    assert (
        result.verification.decision
        is VerificationDecision.PROVED
    )

    assert (
        result.candidate.endpoint
        == ENDPOINT
    )

    assert (
        result.candidate.parameter
        == "id"
    )

    assert (
        result.candidate.fixed_parameters
        == {
            "Submit": "Submit",
        }
    )

    assert (
        discovery.targets[0].base_url
        == ENDPOINT
    )

    assert (
        input_factory.session
        is session
    )

    assert (
        probe.session
        is session
    )

    assert (
        probe.context.baseline_value
        == "1"
    )

    assert (
        probe.context.fixed_parameters
        == {
            "Submit": "Submit",
        }
    )

    assert (
        verifier.evidence
        is evidence
    )

    # Verification produces a deterministic
    # result but does not perform human review
    # or mutate the finding lifecycle here.
    assert (
        finding.status
        is FindingStatus.PROPOSED
    )


def test_service_maps_verifier_decision_to_canonical_finding_status():
    service = DynamicVerificationService(
        discovery=FakeDiscovery(
            _discovery_result()
        ),
        input_factory=FakeInputFactory(),
        probe=FakeProbe(
            _evidence()
        ),
        verifier=FakeVerifier(
            _verification(
                VerificationDecision.NEEDS_HUMAN
            )
        ),
    )

    result = service.verify(
        _finding()
    )

    assert (
        result.finding_status
        is FindingStatus.NEEDS_HUMAN
    )

    assert (
        result.verification.decision
        is VerificationDecision.NEEDS_HUMAN
    )


def test_service_rejects_unsupported_finding_family_before_discovery():
    discovery = FakeDiscovery(
        _discovery_result()
    )

    service = DynamicVerificationService(
        discovery=discovery
    )

    with pytest.raises(
        UnsupportedFindingError
    ):
        service.verify(
            _finding(
                finding_type=FindingType.XSS
            )
        )

    assert discovery.targets == []


def test_service_requires_runtime_location_fields():
    service = DynamicVerificationService(
        discovery=FakeDiscovery(
            _discovery_result()
        )
    )

    with pytest.raises(
        DynamicVerificationError,
        match="parameter",
    ):
        service.verify(
            _finding(
                parameter=None
            )
        )


def test_service_rejects_non_proposed_finding():
    service = DynamicVerificationService(
        discovery=FakeDiscovery(
            _discovery_result()
        )
    )

    with pytest.raises(
        DynamicVerificationError,
        match="PROPOSED",
    ):
        service.verify(
            _finding(
                status=FindingStatus.PROVED
            )
        )


def test_service_fails_closed_when_candidate_cannot_be_resolved():
    empty = DiscoveryResult(
        target=build_dynamic_target(
            ENDPOINT
        )
    )

    service = DynamicVerificationService(
        discovery=FakeDiscovery(
            empty
        )
    )

    with pytest.raises(
        CandidateNotFoundError
    ):
        service.verify(
            _finding()
        )


def test_convenience_boundary_returns_serializable_contract():
    result = verify_dynamic_finding(
        _finding(),
        discovery=FakeDiscovery(
            _discovery_result()
        ),
        input_factory=FakeInputFactory(),
        probe=FakeProbe(
            _evidence()
        ),
        verifier=FakeVerifier(
            _verification()
        ),
    )

    assert (
        result["finding_status"]
        == "PROVED"
    )

    assert (
        result["candidate"][
            "fixed_parameters"
        ]
        == {
            "Submit": "Submit",
        }
    )

    assert (
        result["evidence"]["capability"]
        == "INJECTION_DIFFERENTIAL"
    )

    assert (
        result["verification"][
            "verifier_id"
        ]
        == "injection-differential-verifier"
    )

def test_saved_candidates_reuse_original_discovery_without_new_crawl():
    class DiscoveryMustNotRun:
        def discover(self, target):
            raise AssertionError("Saved candidate path must not re-run discovery.")

    candidates = ProbeCandidateBuilder().build(_discovery_result())
    service = DynamicVerificationService(
        discovery=DiscoveryMustNotRun(),
        saved_candidates=candidates,
        input_factory=FakeInputFactory(),
        probe=FakeProbe(_evidence()),
        verifier=FakeVerifier(_verification()),
    )
    result = service.verify(_finding())
    assert result.finding_status is FindingStatus.PROVED
    assert result.candidate.fixed_parameters == {"Submit": "Submit"}
