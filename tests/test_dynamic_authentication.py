from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.dynamic_analysis import authentication
from app.dynamic_analysis.authentication import (
    AUTH_FORM,
    AUTH_NONE,
    DynamicAuthenticationError,
    create_analysis_session,
)


class FakeResponse:
    def __init__(self, *, url, text, status_code=200):
        self.url = url
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP error")


class FakeSession:
    def __init__(self):
        self.get_calls = []
        self.post_calls = []

    def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))

        if len(self.get_calls) > 1:
            return FakeResponse(
                url="https://example.test",
                text="<html><body>Authenticated target</body></html>",
            )

        return FakeResponse(
            url="https://example.test/login",
            text=(
                '<form method="post" action="/session">'
                '<input type="hidden" name="csrf" value="token-1">'
                '<input type="text" name="email">'
                '<input type="password" name="password">'
                '<input type="submit" name="Login" value="Login">'
                '</form>'
            ),
        )

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        return FakeResponse(
            url="https://example.test/dashboard",
            text="<html><body>Dashboard</body></html>",
        )


def test_unauthenticated_mode_creates_session_without_credentials(monkeypatch):
    fake = FakeSession()
    monkeypatch.setattr(authentication.requests, "Session", lambda: fake)

    session, result = create_analysis_session(
        target_url="https://example.test",
        authentication_mode=AUTH_NONE,
    )

    assert session is fake
    assert result.mode == AUTH_NONE
    assert result.authenticated is False
    assert fake.get_calls == []
    assert fake.post_calls == []


def test_form_authentication_preserves_hidden_and_submit_fields(monkeypatch):
    fake = FakeSession()
    monkeypatch.setattr(authentication.requests, "Session", lambda: fake)

    session, result = create_analysis_session(
        target_url="https://example.test",
        authentication_mode=AUTH_FORM,
        username="analyst@example.test",
        password="secret-value",
    )

    assert session is fake
    assert result.mode == AUTH_FORM
    assert result.authenticated is True
    assert result.login_url == "https://example.test/session"
    assert result.final_url == "https://example.test"
    assert len(fake.get_calls) == 2

    url, kwargs = fake.post_calls[0]
    assert url == "https://example.test/session"
    assert kwargs["data"] == {
        "csrf": "token-1",
        "Login": "Login",
        "email": "analyst@example.test",
        "password": "secret-value",
    }


def test_form_authentication_requires_credentials():
    with pytest.raises(DynamicAuthenticationError):
        create_analysis_session(
            target_url="https://example.test",
            authentication_mode=AUTH_FORM,
            username="",
            password="",
        )
