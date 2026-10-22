from app.models.finding import Finding, FindingType, FindingStatus, ScanType
from app.static_verification_service import StaticVerificationService


def test_xss_observations_are_inconclusive_even_with_input_and_sink():
    finding = Finding(finding_type=FindingType.XSS, scan_type=ScanType.STATIC,
                      explanation="Potential XSS", parameter="bio")
    result = StaticVerificationService().verify(
        finding, analysis_result={"source_context": [{
            "source_file": "profile.php", "source_code": "<?php $bio = $_GET['bio']; echo $bio; ?>",
            "start_line": 1,
        }]})
    assert result.finding_status is FindingStatus.NEEDS_HUMAN
    assert result.evidence["signals"]["input_source_observed"] is True
    assert result.evidence["signals"]["html_output_observed"] is True
    assert result.evidence["evidence_gate_result"] == "NEEDS_HUMAN"


def test_xss_no_matching_patterns_stays_inconclusive():
    finding = Finding(finding_type=FindingType.XSS, scan_type=ScanType.STATIC,
                      explanation="Potential XSS")
    result = StaticVerificationService().verify(
        finding, analysis_result={"source_context": [{"source_code": "let value = 42;"}]})
    assert result.finding_status is FindingStatus.NEEDS_HUMAN
    assert not result.evidence["signals"]["input_source_observed"]
