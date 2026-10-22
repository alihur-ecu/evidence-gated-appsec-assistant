from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup


AUTH_NONE = "NONE"
AUTH_FORM = "FORM"

SUPPORTED_AUTH_MODES = {
    AUTH_NONE,
    AUTH_FORM,
}

DEFAULT_AUTH_TIMEOUT = 10


class DynamicAuthenticationError(RuntimeError):
    """"""


@dataclass(frozen=True)
class AuthenticationResult:
    """"""

    mode: str
    authenticated: bool
    login_url: str | None = None
    final_url: str | None = None

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "authenticated": self.authenticated,
            "login_url": self.login_url,
            "final_url": self.final_url,
        }


def normalise_authentication_mode(
    value: str | None,
) -> str:
    """"""

    mode = str(
        value or AUTH_NONE
    ).strip().upper()

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
    request_timeout: int = DEFAULT_AUTH_TIMEOUT,
) -> tuple[requests.Session, AuthenticationResult]:

    mode = normalise_authentication_mode(
        authentication_mode
    )

    session = requests.Session()

    if mode == AUTH_NONE:
        return (
            session,
            AuthenticationResult(
                mode=AUTH_NONE,
                authenticated=False,
                login_url=None,
                final_url=None,
            ),
        )

    username = str(
        username or ""
    ).strip()

    password = str(
        password or ""
    )

    if not username or not password:
        raise DynamicAuthenticationError(
            "Username and password are required for authenticated analysis."
        )

    if request_timeout <= 0:
        raise ValueError(
            "request_timeout must be greater than zero."
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

   
    form = _find_login_form(
        landing_response.text
    )

    if form is None:
        raise DynamicAuthenticationError(
            "No conventional HTML username/password login form was found. "
            "Use unauthenticated analysis for public coverage or a supported "
            "authentication adapter for this application."
        )

    payload, username_field, password_field = (
        _build_login_payload(
            form
        )
    )

    payload[username_field] = username
    payload[password_field] = password

    action = (
        form.get("action")
        or landing_response.url
    )

    login_url = urljoin(
        landing_response.url,
        action,
    )

    method = str(
        form.get("method", "GET")
    ).strip().upper()


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

    except DynamicAuthenticationError:
        raise

    except requests.RequestException as exc:
        raise DynamicAuthenticationError(
            "The authentication request could not be completed."
        ) from exc


    if _find_login_form(
        login_response.text
    ) is not None:
        raise DynamicAuthenticationError(
            "Authentication did not leave the login form. "
            "Check the username and password."
        )


    try:
        validation_response = session.get(
            target_url,
            timeout=request_timeout,
            allow_redirects=True,
        )

        validation_response.raise_for_status()

    except requests.RequestException as exc:
        raise DynamicAuthenticationError(
            "Authentication completed, but the original target could not "
            "be loaded with the authenticated session."
        ) from exc


    validation_login_form = _find_login_form(
        validation_response.text
    )

    if validation_login_form is not None:
        raise DynamicAuthenticationError(
            "Authentication could not be confirmed. "
            "The protected target still resolves to a login form."
        )

    if (
        _normalise_url_for_comparison(
            validation_response.url
        )
        == _normalise_url_for_comparison(
            login_url
        )
        and
        _normalise_url_for_comparison(
            target_url
        )
        != _normalise_url_for_comparison(
            login_url
        )
    ):
        raise DynamicAuthenticationError(
            "Authentication could not be confirmed. "
            "The protected target redirected back to the login page."
        )



    return (
        session,
        AuthenticationResult(
            mode=AUTH_FORM,
            authenticated=True,
            login_url=login_url,
            final_url=validation_response.url,
        ),
    )


def _find_login_form(
    html: str,
):

    soup = BeautifulSoup(
        html or "",
        "html.parser",
    )

    for form in soup.find_all("form"):
        password_field = form.find(
            "input",
            attrs={
                "type": lambda value: (
                    str(value or "").lower()
                    == "password"
                )
            },
        )

        if password_field is not None:
            return form

    return None


def _build_login_payload(
    form,
) -> tuple[
    dict[str, str],
    str,
    str,
]:

    payload: dict[str, str] = {}

    username_field: str | None = None
    password_field: str | None = None

    username_candidates: list[str] = []

    for element in form.find_all(
        ["input", "textarea", "select", "button"]
    ):
        raw_name = element.get("name")

        if raw_name is None:
            continue

        name = str(
            raw_name
        ).strip()

        if not name:
            continue

        tag_name = str(
            getattr(
                element,
                "name",
                "",
            )
        ).lower()

        input_type = str(
            element.get(
                "type",
                tag_name,
            )
        ).strip().lower()


        if (
            tag_name == "input"
            and input_type == "password"
        ):
            password_field = name
            payload.setdefault(
                name,
                "",
            )
            continue


        if (
            tag_name == "input"
            and input_type
            in {
                "",
                "text",
                "email",
                "username",
            }
        ):
            username_candidates.append(
                name
            )


        value = _form_control_value(
            element
        )

        if value is not None:
            payload[name] = value

    if password_field is None:
        raise DynamicAuthenticationError(
            "The login form does not expose a named password field."
        )

    username_field = _choose_username_field(
        username_candidates
    )

    if username_field is None:
        raise DynamicAuthenticationError(
            "The login form does not expose a username/email field."
        )

    payload.setdefault(
        username_field,
        "",
    )

    payload.setdefault(
        password_field,
        "",
    )

    return (
        payload,
        username_field,
        password_field,
    )


def _choose_username_field(
    candidates: list[str],
) -> str | None:
    """"""

    if not candidates:
        return None

    preferred_tokens = (
        "username",
        "user",
        "email",
        "login",
        "account",
    )

    lowered = {
        candidate: candidate.lower()
        for candidate in candidates
    }

    # Exact conventional names first.
    for token in preferred_tokens:
        for candidate in candidates:
            if lowered[candidate] == token:
                return candidate

    # Then names containing conventional tokens.
    for token in preferred_tokens:
        for candidate in candidates:
            if token in lowered[candidate]:
                return candidate

    # A conventional form with exactly one text/email input is
    # unambiguous enough for the generic MVP.
    if len(candidates) == 1:
        return candidates[0]

    return candidates[0]


def _form_control_value(
    element,
) -> str | None:
    """"""

    tag_name = str(
        getattr(
            element,
            "name",
            "",
        )
    ).lower()

    input_type = str(
        element.get(
            "type",
            tag_name,
        )
    ).strip().lower()

    if tag_name == "textarea":
        return element.get_text()

    if tag_name == "select":
        selected = element.find(
            "option",
            selected=True,
        )

        if selected is None:
            selected = element.find(
                "option"
            )

        if selected is None:
            return None

        raw_value = selected.get(
            "value"
        )

        if raw_value is not None:
            return str(
                raw_value
            )

        return selected.get_text()

    if input_type in {
        "checkbox",
        "radio",
    }:
        if not element.has_attr(
            "checked"
        ):
            return None

        return str(
            element.get(
                "value",
                "on",
            )
        )

    if input_type == "file":
        return None

    raw_value = element.get(
        "value"
    )

    if raw_value is not None:
        return str(
            raw_value
        )

    if tag_name in {
        "input",
        "button",
    }:
        return ""

    return None


def _normalise_url_for_comparison(
    url: str,
) -> str:


    parsed = urlsplit(
        str(url or "")
    )

    path = parsed.path or "/"

    if path != "/":
        path = path.rstrip("/")

    return (
        f"{parsed.scheme.lower()}://"
        f"{parsed.netloc.lower()}"
        f"{path}"
    )