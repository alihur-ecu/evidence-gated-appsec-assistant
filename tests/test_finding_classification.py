"""Presentation-only classification regression tests; no HTTP requests."""

import pytest

from app.analysis.finding_adapter import adapt_analysis_result
from app.models.finding import Finding, FindingStatus, FindingType


@pytest.mark.parametrize(
    "proposal, expected",
    [
        ({"finding_type": "OTHER", "proposed_cwe": "CWE-434"}, FindingType.FILE_UPLOAD),
        ({"finding_type": "Unrestricted File Upload"}, FindingType.FILE_UPLOAD),
        ({"finding_type": "OTHER", "cwe": "CWE-352"}, FindingType.CSRF),
        ({"finding_type": "Cross-Site Request Forgery"}, FindingType.CSRF),
        ({"finding_type": "OTHER", "cwe": "CWE-307"}, FindingType.AUTHENTICATION_RATE_LIMITING),
        ({"finding_type": "Brute Force"}, FindingType.AUTHENTICATION_RATE_LIMITING),
        ({"finding_type": "OTHER", "cwe": "CWE-94"}, FindingType.CODE_INJECTION),
        ({"finding_type": "Local File Inclusion"}, FindingType.FILE_INCLUSION),
        ({"finding_type": "LFI"}, FindingType.FILE_INCLUSION),
        ({"finding_type": "CWE-89"}, FindingType.SQL_INJECTION),
        ({"finding_type": "COMMAND_INJECTION"}, FindingType.COMMAND_INJECTION),
        ({"finding_type": "new_unknown_type", "cwe": "CWE-99999"}, FindingType.OTHER),
    ],
)
def test_classifies_proposals_without_changing_their_status(proposal, expected):
    proposals = [{**proposal, "description": "Unverified provider proposal."}]
    result = {
        "analysis_id": "D-CLASSIFY",
        "provider": "TEST",
        "analysis_type": "DYNAMIC",
        "findings": proposals,
    }
    [(finding, metadata)] = adapt_analysis_result(result)
    assert finding.finding_type == expected
    assert finding.status is FindingStatus.PROPOSED
    assert metadata["proposed_cwe"] == (
        proposal.get("proposed_cwe") or proposal.get("cwe") or "Not available"
    )
    assert finding.explanation == "Unverified provider proposal."


@pytest.mark.parametrize(
    "family",
    [FindingType.FILE_UPLOAD, FindingType.CSRF,
     FindingType.AUTHENTICATION_RATE_LIMITING,
     FindingType.CODE_INJECTION],
)
def test_new_families_round_trip_without_promotion(family):
    original = Finding(finding_type=family, explanation="Candidate only.")
    restored = Finding.from_dict(original.to_dict())
    assert restored.finding_type is family
    assert restored.status is FindingStatus.PROPOSED


def test_conflicting_explicit_known_label_not_overridden_by_cwe():
    result = {
        "analysis_id": "D-CONFLICT",
        "analysis_type": "DYNAMIC",
        "findings": [{
            "finding_type": "SQL_INJECTION",
            "proposed_cwe": "CWE-434",
            "description": "Provider label conflicts with its CWE.",
        }],
    }
    [(finding, _)] = adapt_analysis_result(result)
    assert finding.finding_type is FindingType.SQL_INJECTION
    assert finding.proposed_cwe == "CWE-434"
    assert finding.status is FindingStatus.PROPOSED


def test_runtime_verifier_is_not_enabled_for_new_families():
    from app.dynamic_analysis.verification_router import VerificationRouter
    from app.models.finding import ScanType
    router = VerificationRouter()
    for family in (FindingType.FILE_UPLOAD, FindingType.CSRF,
                   FindingType.AUTHENTICATION_RATE_LIMITING,
                   FindingType.CODE_INJECTION):
        f = Finding(finding_type=family, explanation="Candidate only.",
                    scan_type=ScanType.DYNAMIC,
                    endpoint="http://localhost:4280/test/",
                    method="GET", parameter="value")
        assert router.route(f).can_verify is False
