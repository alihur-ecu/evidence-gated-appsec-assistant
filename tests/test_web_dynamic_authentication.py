from __future__ import annotations

from types import SimpleNamespace

from app.web import server


def _dynamic_result():
    return {
        "target": {
            "base_url": "https://example.test/",
            "original_url": "https://example.test/",
        },
        "proposal_provider": "TEST",
        "discovery": {
            "pages": [],
            "endpoints": [],
            "forms": [],
            "errors": [],
        },
        "context_build": {},
        "proposals": [],
    }


def test_dynamic_route_defaults_to_unauthenticated_and_passes_session(monkeypatch):
    session = object()
    captured = {}

    monkeypatch.setattr(
        server,
        "create_analysis_session",
        lambda **kwargs: (
            session,
            SimpleNamespace(
                mode="NONE",
                authenticated=False,
                to_dict=lambda: {
                    "mode": "NONE",
                    "authenticated": False,
                    "login_url": None,
                },
            ),
        ),
    )

    class FakeDiscovery:
        def __init__(self, *, session):
            captured["session"] = session

    monkeypatch.setattr(server, "DynamicDiscovery", FakeDiscovery)
    monkeypatch.setattr(server, "run_dynamic_analysis", lambda **kwargs: _dynamic_result())

    client = server.app.test_client()
    response = client.post(
        "/analysis/dynamic",
        data={
            "target_url": "https://example.test/",
            "application_name": "Example",
            "analysis_scope": "Public surface",
            "authentication_mode": "NONE",
            "authorised": "true",
        },
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["authentication_mode"] == "NONE"
    assert payload["authenticated"] is False
    assert captured["session"] is session
    assert server.ANALYSIS_SESSIONS[payload["analysis_id"]] is session


def test_dynamic_route_requires_credentials_for_form_authentication():
    client = server.app.test_client()
    response = client.post(
        "/analysis/dynamic",
        data={
            "target_url": "https://example.test/",
            "application_name": "Example",
            "analysis_scope": "Authenticated surface",
            "authentication_mode": "FORM",
            "authorised": "true",
        },
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert "Username and password" in payload["error"]


def test_dynamic_route_reports_llm_rate_limit_without_registering_zero_findings(monkeypatch):
    session = object()
    monkeypatch.setattr(
        server,
        "create_analysis_session",
        lambda **kwargs: (
            session,
            SimpleNamespace(
                mode="NONE",
                authenticated=False,
                to_dict=lambda: {"mode": "NONE", "authenticated": False, "login_url": None},
            ),
        ),
    )

    class FakeDiscovery:
        def __init__(self, *, session):
            self.session = session

    monkeypatch.setattr(server, "DynamicDiscovery", FakeDiscovery)
    result = _dynamic_result()
    result["proposal_status"] = "FAILED"
    result["proposal_execution"] = {
        "chunks_attempted": 1,
        "chunks_succeeded": 0,
        "chunks_failed": 1,
        "failed_chunks": [{"status_code": 429, "error_type": "RateLimitError"}],
    }
    monkeypatch.setattr(server, "run_dynamic_analysis", lambda **kwargs: result)

    client = server.app.test_client()
    response = client.post(
        "/analysis/dynamic",
        data={
            "target_url": "https://example.test/",
            "application_name": "Example",
            "analysis_scope": "Public surface",
            "authentication_mode": "NONE",
            "authorised": "true",
        },
    )

    assert response.status_code == 429
    payload = response.get_json()
    assert payload["ok"] is False
    assert payload["stage"] == "PROPOSAL_FAILED"
    assert payload["code"] == "LLM_RATE_LIMITED"
    assert payload["discovery_completed"] is True
    assert "No security conclusion has been made" in payload["error"]
