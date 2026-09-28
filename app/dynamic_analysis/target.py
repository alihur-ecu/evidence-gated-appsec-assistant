"""
Generic target model for dynamic application analysis.

This module is responsible only for validating and normalising a
user-supplied target.

It does not:

- crawl the application;
- generate attack payloads;
- perform vulnerability verification;
- depend on a specific application such as DVWA or Juice Shop.

Architecture principle:

    User target
        ->
    Validated DynamicTarget
        ->
    Discovery
        ->
    Dynamic context
        ->
    Candidate proposals
        ->
    Evidence verifies
        ->
    Human decides
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


SUPPORTED_SCHEMES = {
    "http",
    "https",
}


class InvalidDynamicTarget(ValueError):
    """Raised when a dynamic-analysis target is invalid."""


@dataclass(frozen=True)
class DynamicTarget:
    """
    Normalised target for dynamic application analysis.

    origin identifies the network origin that discovery starts from.

    base_url preserves the user-supplied path so an analysis may begin
    from either an application root or a specific application path.
    """

    original_url: str
    base_url: str
    origin: str
    scheme: str
    hostname: str
    port: int | None
    start_path: str

    def is_same_origin(
        self,
        candidate_url: str,
    ) -> bool:
        """
        Return True when candidate_url belongs to this target's origin.

        Relative URLs are considered part of the current target because
        they resolve against the target during discovery.
        """

        if not isinstance(candidate_url, str):
            return False

        candidate_url = candidate_url.strip()

        if not candidate_url:
            return False

        parsed = urlsplit(candidate_url)

        if not parsed.scheme and not parsed.netloc:
            return True

        if parsed.scheme.lower() not in SUPPORTED_SCHEMES:
            return False

        try:
            candidate_port = parsed.port
        except ValueError:
            return False

        candidate_hostname = (
            parsed.hostname.lower()
            if parsed.hostname
            else ""
        )

        return (
            parsed.scheme.lower() == self.scheme
            and candidate_hostname == self.hostname
            and _effective_port(
                parsed.scheme.lower(),
                candidate_port,
            )
            == _effective_port(
                self.scheme,
                self.port,
            )
        )


def build_dynamic_target(
    target_url: str,
) -> DynamicTarget:
    """
    Validate and normalise a user-supplied HTTP(S) target.

    A scheme may be omitted. In that case HTTPS is preferred as the
    safe default.

    Examples:

        example.com
            -> https://example.com/

        https://example.com/app
            -> https://example.com/app

        http://localhost:8080
            -> http://localhost:8080/
    """

    if not isinstance(target_url, str):
        raise InvalidDynamicTarget(
            "Target URL must be a string."
        )

    original_url = target_url.strip()

    if not original_url:
        raise InvalidDynamicTarget(
            "Target URL is required."
        )

    candidate = original_url

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise InvalidDynamicTarget(
            "Target URL is invalid."
        ) from exc

    scheme = parsed.scheme.lower()

    if scheme not in SUPPORTED_SCHEMES:
        raise InvalidDynamicTarget(
            "Dynamic analysis supports only HTTP and HTTPS targets."
        )

    if not parsed.hostname:
        raise InvalidDynamicTarget(
            "Target URL must contain a hostname."
        )

    if parsed.username is not None or parsed.password is not None:
        raise InvalidDynamicTarget(
            "Credentials must not be embedded in the target URL."
        )

    try:
        port = parsed.port
    except ValueError as exc:
        raise InvalidDynamicTarget(
            "Target URL contains an invalid port."
        ) from exc

    hostname = parsed.hostname.lower()

    host_for_url = _format_host_for_url(
        hostname
    )

    netloc = host_for_url

    if port is not None:
        netloc = f"{host_for_url}:{port}"

    path = parsed.path or "/"

    base_url = urlunsplit(
        (
            scheme,
            netloc,
            path,
            parsed.query,
            "",
        )
    )

    origin = urlunsplit(
        (
            scheme,
            netloc,
            "",
            "",
            "",
        )
    )

    return DynamicTarget(
        original_url=original_url,
        base_url=base_url,
        origin=origin,
        scheme=scheme,
        hostname=hostname,
        port=port,
        start_path=path,
    )


def _effective_port(
    scheme: str,
    port: int | None,
) -> int | None:
    """Return the effective network port for an HTTP(S) URL."""

    if port is not None:
        return port

    if scheme == "http":
        return 80

    if scheme == "https":
        return 443

    return None


def _format_host_for_url(
    hostname: str,
) -> str:
    """Return a hostname formatted safely for URL reconstruction."""

    if ":" in hostname:
        return f"[{hostname}]"

    return hostname