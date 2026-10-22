"""Offline regressions for the discovered-candidate Oracle readiness gate."""
from __future__ import annotations

from app.dynamic_analysis.verification_readiness import (
    preflight_saved_candidate, candidates_from_saved_discovery,
)
from app.models.finding import Finding, FindingStatus, FindingType, ScanType

ORIGIN = "http://localhost:4280/"
SQL = ORIGIN + "vulnerabilities/sqli/"
SETUP = ORIGIN + "setup.php"


def finding(endpoint=SQL, method="GET", parameter="id"):
    return Finding(
        finding_type=FindingType.SQL_INJECTION,
        scan_type=ScanType.DYNAMIC,
        explanation="LLM proposal; not verified.",
        endpoint=endpoint, method=method, parameter=parameter,
        status=FindingStatus.PROPOSED,
    )


def snapshot():
    return {
        "endpoints": [
            {"url": SQL, "method": "GET", "parameters": [
                {"name": "id", "location": "query", "input_type": "text", "observed_value": ""},
            ]}
        ],
        "forms": [{
            "source_url": SQL, "action_url": SQL, "method": "GET",
            "parameters": [
                {"name": "id", "location": "query", "input_type": "text", "observed_value": ""},
                {"name": "Submit", "location": "query", "input_type": "submit", "observed_value": "Submit"},
            ],
        }],
    }


def test_setup_database_proposal_has_no_verified_request_candidate():
    outcome = preflight_saved_candidate(finding(SETUP, "POST", "create_db"), snapshot(), ORIGIN)
    assert not outcome.ready
    assert outcome.status == "CANDIDATE_NOT_DISCOVERED"
    assert outcome.candidate is None


def test_sqli_request_remains_ready_preserving_submit_context():
    outcome = preflight_saved_candidate(finding(), snapshot(), ORIGIN)
    assert outcome.ready
    assert outcome.candidate.method == "GET"
    assert outcome.candidate.parameter == "id"
    assert outcome.candidate.fixed_parameters == {"Submit": "Submit"}


def test_case_uses_exact_method_and_parameter():
    assert not preflight_saved_candidate(finding(method="POST"), snapshot(), ORIGIN).ready
    assert not preflight_saved_candidate(finding(parameter="create_db"), snapshot(), ORIGIN).ready


def test_out_of_scope_candidate_is_rejected():
    out_of_scope = dict(snapshot())
    out_of_scope["endpoints"] = [{
        "url": "https://external.test/private", "method": "GET",
        "parameters": [{"name": "id", "location": "query", "observed_value": "1"}],
    }]
    assert candidates_from_saved_discovery(out_of_scope, ORIGIN) == () or all(
        c.endpoint.startswith(ORIGIN) for c in candidates_from_saved_discovery(out_of_scope, ORIGIN)
    )
    result = preflight_saved_candidate(finding("https://external.test/private"), snapshot(), ORIGIN)
    assert result.status == "CANDIDATE_NOT_DISCOVERED"


def test_uneditable_submit_is_not_accepted_as_target():
    outcome = preflight_saved_candidate(finding(SQL, "GET", "Submit"), snapshot(), ORIGIN)
    assert outcome.status == "CANDIDATE_NOT_DISCOVERED"
