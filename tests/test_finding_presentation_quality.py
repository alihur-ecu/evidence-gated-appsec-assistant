"""Display-only classification: old snapshots, proposal quality, and CWE identity."""

import pytest

from app.analysis.finding_adapter import adapt_analysis_result
from app.analysis.finding_presentation import (
    finding_label, effective_cwe, proposal_quality_notes,
)
from app.models.finding import Finding, FindingStatus, FindingType, ScanType


@pytest.mark.parametrize("cwe,label", [
    ("CWE-434", "Potential Unrestricted File Upload"),
    ("CWE-307", "Potential Authentication Rate-Limiting Weakness"),
    ("CWE-352", "Potential Cross-Site Request Forgery"),
    ("CWE-200", "Potential Sensitive Information Exposure"),
    ("CWE-425", "Potential Forced Browsing (Direct Request)"),
    ("CWE-94", "Potential Code Injection"),
])
def test_historical_other_with_metadata_cwe_displays_correctly(cwe, label):
    # Historical scan record: canonical type OTHER, CWE retained in metadata.
    finding = Finding.from_dict(Finding(
        finding_type=FindingType.OTHER, explanation="Unverified",
        scan_type=ScanType.DYNAMIC, endpoint="http://localhost:4280/setup.php",
    ).to_dict())
    assert finding_label(finding, {"proposed_cwe": cwe}) == label
    assert effective_cwe(finding, {"proposed_cwe": cwe}) == cwe
    assert finding.finding_type is FindingType.OTHER  # nothing is rewritten
    assert finding.status is FindingStatus.PROPOSED


@pytest.mark.parametrize("cwe,family", [
    ("CWE-200", FindingType.INFORMATION_EXPOSURE),
    ("CWE-425", FindingType.FORCED_BROWSING),
])
def test_new_proposal_classified_from_cwe(cwe, family):
    [(finding, meta)] = adapt_analysis_result({
        "analysis_id": "D-NEW", "analysis_type": "DYNAMIC",
        "findings": [{"finding_type": "OTHER", "proposed_cwe": cwe,
                      "endpoint": "http://localhost:4280/setup.php",
                      "severity": "HIGH", "description": "Candidate only"}],
    })
    assert finding.finding_type is family
    assert finding_label(finding, meta) != "OTHER"
    assert finding.status is FindingStatus.PROPOSED
    assert Finding.from_dict(finding.to_dict()).finding_type is family


def test_different_cwe_same_endpoint_are_separate_unproved_candidates():
    findings = [Finding(finding_type=ft, explanation="Candidate",
                        scan_type=ScanType.DYNAMIC, endpoint="http://localhost:4280/setup.php",
                        method="GET", suggested_severity=severity, proposed_cwe=cwe)
                for ft,cwe,severity in [
                    (FindingType.XSS,"CWE-79","MEDIUM"),
                    (FindingType.SQL_INJECTION,"CWE-89","HIGH"),
                    (FindingType.INFORMATION_EXPOSURE,"CWE-200","LOW"),
                ]]
    assert len({f.endpoint for f in findings}) == 1
    assert len({finding_label(f) for f in findings}) == 3
    assert all(f.status is FindingStatus.PROPOSED for f in findings)
    assert all(finding_label(f).startswith("Potential") for f in findings)
    assert len(proposal_quality_notes(findings[0])) == 1
    assert len(proposal_quality_notes(findings[1])) == 1
    assert proposal_quality_notes(findings[2]) == []


def test_parameter_is_not_required_for_non_injection_endpoint_findings():
    f = Finding(finding_type=FindingType.FORCED_BROWSING,
                explanation="Candidate", scan_type=ScanType.DYNAMIC,
                endpoint="http://localhost:4280/setup.php", parameter=None)
    assert proposal_quality_notes(f) == []


def test_conflicting_explicit_type_and_cwe_is_flagged_not_reclassified():
    f = Finding(finding_type=FindingType.SQL_INJECTION, explanation="Candidate",
                scan_type=ScanType.DYNAMIC, proposed_cwe="CWE-434",
                parameter="id", endpoint="http://localhost:4280/vulnerabilities/sqli/")
    assert finding_label(f) == "Potential SQL Injection"
    notes = proposal_quality_notes(f)
    assert len(notes) == 1
    assert "different families" in notes[0]
    assert f.finding_type is FindingType.SQL_INJECTION


def test_unknown_cwe_falls_back_to_descriptive_hypothesis():
    f = Finding(finding_type=FindingType.OTHER,
                explanation="Candidate", proposed_cwe="CWE-99999")
    assert finding_label(f) == "Potential Security Weakness (CWE-99999)"


def test_no_parameter_in_static_findings_does_not_trigger_dynamic_warning():
    f = Finding(finding_type=FindingType.SQL_INJECTION,
                explanation="Candidate", scan_type=ScanType.STATIC)
    assert proposal_quality_notes(f) == []
