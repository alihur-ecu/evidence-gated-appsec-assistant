"""Generic authentication support for authorised dynamic analysis.

Authentication is an optional coverage extension. Unauthenticated analysis
remains a first-class mode and requires no credentials.

The current authenticated MVP supports conventional HTML username/password
forms. Credentials are used only to establish an in-memory requests.Session;
they are never returned in analysis results or evidence artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup


AUTH_NONE = "NONE"
AUTH_FORM = "FORM"
SUPPORTED_AUTH_MODES = {AUTH_NONE, AUTH_FORM}


class DynamicAuthenticationError(RuntimeError):
    """Raised when an authenticated analysis session cannot be established."""


@dataclass(frozen=True)
class AuthenticationResult:
    """Non-secret metadata describing the session preparation outcome."""

    mode: str
    authenticated: bool
    login_url: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "authenticated": self.authenticated,
            "login_url": self.login_url,
        }


def normalise_authentication_mode(value: str | None) -> str:
    mode = str(value or AUTH_NONE).strip().upper()
    if mode not in SUPPORTED_AUTH_MODES:
        raise DynamicAuthenticationError(
            f"Unsupported authentication mode '{mode}'. "
            f"Supported modes: {', '.join(sorted(SUPPORTED_AUTH_MODES))}."
        )
    return mode


def create_analysis_session(
    *,
    target_url: str,
    authentication_mode: str = AUTH_NONE,
    username: str | None = None,
    password: str | None = None,
    request_timeout: int = 10,
) -> tuple[requests.Session, AuthenticationResult]:
    """Create the session used by discovery and later deterministic verification.

    FORM mode intentionally targets ordinary server-rendered HTML login forms.
    SSO, MFA, bearer tokens, API keys and imported browser sessions are future
    authentication adapters rather than special cases in this function.
    """

    mode = normalise_authentication_mode(authentication_mode)
    session = requests.Session()

    if mode == AUTH_NONE:
        return session, AuthenticationResult(
            mode=AUTH_NONE,
            authenticated=False,
            login_url=None,
        )

    username = str(username or "").strip()
    password = str(password or "")

    if not username or not password:
        raise DynamicAuthenticationError(
            "Username and password are required for authenticated analysis."
        )

    try:
        landing_response = session.get(
            target_url,
            timeout=request_timeout,
            allow_redirects=True,
        )
        landing_response.raise_for_status()
    except requests.RequestException as exc:
        raise DynamicAuthenticationError(
            "Unable to load the target before authentication."
        ) from exc

    form = _find_login_form(landing_response.text)
    if form is None:
        raise DynamicAuthenticationError(
            "No conventional HTML username/password login form was found. "
            "Use unauthenticated analysis for public coverage or a supported "
            "authentication adapter for this application."
        )

    payload, username_field, password_field = _build_login_payload(form)
    payload[username_field] = username
    payload[password_field] = password

    action = form.get("action") or landing_response.url
    login_url = urljoin(landing_response.url, action)
    method = str(form.get("method") or "GET").strip().upper()

    try:
        if method == "POST":
            login_response = session.post(
                login_url,
                data=payload,
                timeout=request_timeout,
                allow_redirects=True,
            )
        elif method == "GET":
            login_response = session.get(
                login_url,
                params=payload,
                timeout=request_timeout,
                allow_redirects=True,
            )
        else:
            raise DynamicAuthenticationError(
                f"Unsupported login form method '{method}'."
            )

        login_response.raise_for_status()
    except requests.RequestException as exc:
        raise DynamicAuthenticationError(
            "The authentication request could not be completed."
        ) from exc

    # A conventional login page that still exposes the same password field
    # after submission is a strong fail-closed signal for this MVP adapter.
    remaining_form = _find_login_form(login_response.text)
    if remaining_form is not None:
        remaining_password = remaining_form.find(
            "input",
            attrs={"type": lambda value: str(value or "").lower() == "password"},
        )
        if remaining_password is not None:
            raise DynamicAuthenticationError(
                "Authentication did not leave the login form. Check the "
                "credentials or use another supported authentication method."
            )

    return session, AuthenticationResult(
        mode=AUTH_FORM,
        authenticated=True,
        login_url=login_url,
    )


def _find_login_form(html: str):
    soup = BeautifulSoup(html or "", "html.parser")
    for form in soup.find_all("form"):
        password_input = form.find(
            "input",
            attrs={"type": lambda value: str(value or "").lower() == "password"},
        )
        if password_input is not None and password_input.get("name"):
            return form
    return None


def _build_login_payload(form) -> tuple[dict[str, str], str, str]:
    payload: dict[str, str] = {}
    password_field: str | None = None
    username_field: str | None = None

    username_candidates: list[str] = []

    for element in form.find_all("input"):
        name = element.get("name")
        if not name:
            continue

        input_type = str(element.get("type") or "text").lower()
        value = str(element.get("value") or "")

        if input_type == "password":
            password_field = name
            continue

        if input_type in {"hidden", "submit"}:
            payload[name] = value
            continue

        if input_type in {"text", "email", "username"}:
            username_candidates.append(name)
            continue

        if input_type in {"checkbox", "radio"} and element.has_attr("checked"):
            payload[name] = value or "on"

    if password_field is None:
        raise DynamicAuthenticationError(
            "The login form does not expose a named password field."
        )

    if not username_candidates:
        raise DynamicAuthenticationError(
            "The login form does not expose a username/email field."
        )

    preferred = (
        "username",
        "user",
        "email",
        "login",
        "account",
    )

    for candidate in username_candidates:
        lowered = candidate.lower()
        if any(token in lowered for token in preferred):
            username_field = candidate
            break

    if username_field is None:
        username_field = username_candidates[0]

    return payload, username_field, password_field
