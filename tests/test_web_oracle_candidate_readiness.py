"""Web preflight: do not advertise Oracle readiness for unobserved requests."""
from __future__ import annotations

from app.models.finding import Finding, FindingStatus, FindingType, ScanType
from app.web import server

BASE = "http://localhost:4280/"
SQL = BASE + "vulnerabilities/sqli/"


def _finding(endpoint, method, parameter):
    return Finding(
        finding_id="F-TEST-CANDIDATE",
        finding_type=FindingType.SQL_INJECTION,
        scan_type=ScanType.DYNAMIC,
        explanation="LLM candidate only",
        endpoint=endpoint, method=method, parameter=parameter,
        status=FindingStatus.PROPOSED,
    )


def _setup(monkeypatch, finding):
    analysis_id = "D-TEST-CANDIDATE"
    snapshot = {
        "endpoints": [{"url": SQL, "method": "GET", "parameters": [
            {"name": "id", "location": "query", "input_type": "text", "observed_value": ""},
        ]}],
        "forms": [{"source_url": SQL, "action_url": SQL, "method": "GET", "parameters": [
            {"name": "id", "location": "query", "input_type": "text", "observed_value": ""},
            {"name": "Submit", "location": "query", "input_type": "submit", "observed_value": "Submit"},
        ]}],
    }
    monkeypatch.setattr(server, "FINDINGS", {finding.finding_id: finding})
    monkeypatch.setattr(server, "FINDING_METADATA", {finding.finding_id: {"analysis_id": analysis_id}})
    monkeypatch.setattr(server, "ANALYSES", {analysis_id: {
        "analysis_id": analysis_id, "target": BASE,
        "authentication_mode": "NONE", "discovery": snapshot,
    }})
    monkeypatch.setattr(server, "ANALYSIS_SESSIONS", {analysis_id: object()})
    monkeypatch.setattr(server, "EVIDENCE_BY_FINDING", {})
    monkeypatch.setattr(server, "REVIEW_BY_FINDING", {})


def test_setup_findings_are_not_advertised_as_oracle_ready(monkeypatch):
    f = _finding(BASE + "setup.php", "POST", "create_db")
    _setup(monkeypatch, f)
    view = server.build_view_model(f)
    assert view["verification_readiness"] == "CANDIDATE_NOT_DISCOVERED"
    assert view["runtime_verification_supported"] is False
    assert view["verification_supported"] is False
    response = server.app.test_client().post(f"/findings/{f.finding_id}/verify")
    assert response.status_code == 409
    assert response.get_json()["code"] == "CANDIDATE_NOT_DISCOVERED"
    assert f.status is FindingStatus.PROPOSED
    assert f.finding_id not in server.EVIDENCE_BY_FINDING


def test_observed_sqli_request_remains_ready(monkeypatch):
    f = _finding(SQL, "GET", "id")
    _setup(monkeypatch, f)
    view = server.build_view_model(f)
    assert view["verification_readiness"] == "READY"
    assert view["runtime_verification_supported"] is True


def test_root_relative_target_resolves_correctly(monkeypatch):
    f = _finding("/vulnerabilities/sqli/", "GET", "id")
    _setup(monkeypatch, f)
    view = server.build_view_model(f)
    assert view["verification_readiness"] == "READY"
    resolved = server._resolve_runtime_finding_endpoint(f, SQL)
    assert resolved.endpoint == SQL


def test_authenticated_history_without_session_is_not_ready(monkeypatch):
    f = _finding(SQL, "GET", "id")
    _setup(monkeypatch, f)
    server.ANALYSES["D-TEST-CANDIDATE"]["authentication_mode"] = "FORM"
    server.ANALYSIS_SESSIONS.clear()
    view = server.build_view_model(f)
    assert view["verification_readiness"] == "AUTH_SESSION_MISSING"
    assert view["runtime_verification_supported"] is False
    response = server.app.test_client().post(f"/findings/{f.finding_id}/verify")
    assert response.status_code == 409
    assert response.get_json()["code"] == "AUTH_SESSION_MISSING"
