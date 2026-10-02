"""
Generic read-only discovery for dynamic application analysis.

Discovery observes an authorised HTTP(S) application and builds a
structured representation of its reachable attack surface.

This module does NOT:

- decide whether a vulnerability exists;
- generate vulnerability findings;
- execute attack payloads;
- submit discovered forms;
- depend on DVWA, Juice Shop, or another specific application.

Architecture principle:

    DynamicTarget
        ->
    Read-only discovery
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

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import (
    parse_qsl,
    urldefrag,
    urljoin,
    urlsplit,
    urlunsplit,
)

import requests
from bs4 import BeautifulSoup

from app.dynamic_analysis.target import DynamicTarget


DEFAULT_REQUEST_TIMEOUT = 10
DEFAULT_MAX_PAGES = 10
DEFAULT_MAX_RESPONSE_BYTES = 1_000_000

DISCOVERY_USER_AGENT = "Evidence-Gated-AppSec/0.1 Discovery"


@dataclass(frozen=True)
class DiscoveredParameter:
    """One observable input parameter."""

    name: str
    location: str
    input_type: str | None = None
    observed_value: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location,
            "input_type": self.input_type,
            "observed_value": self.observed_value,
        }


@dataclass(frozen=True)
class DiscoveredForm:
    """One HTML form observed during discovery."""

    source_url: str
    action_url: str
    method: str
    parameters: tuple[DiscoveredParameter, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_url": self.source_url,
            "action_url": self.action_url,
            "method": self.method,
            "parameters": [
                parameter.to_dict()
                for parameter in self.parameters
            ],
        }


@dataclass(frozen=True)
class DiscoveredEndpoint:
    """One HTTP endpoint observed during discovery."""

    url: str
    method: str
    parameters: tuple[DiscoveredParameter, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": [
                parameter.to_dict()
                for parameter in self.parameters
            ],
        }


@dataclass(frozen=True)
class DiscoveredPage:
    """One page fetched successfully enough to inspect."""

    requested_url: str
    final_url: str
    status_code: int
    content_type: str | None
    response_length: int
    title: str | None
    response_header_names: tuple[str, ...] = ()
    cookie_names: tuple[str, ...] = ()
    redirect_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_url": self.requested_url,
            "final_url": self.final_url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "response_length": self.response_length,
            "title": self.title,
            "response_header_names": list(
                self.response_header_names
            ),
            "cookie_names": list(
                self.cookie_names
            ),
            "redirect_count": self.redirect_count,
        }


@dataclass
class DiscoveryResult:
    """Structured output produced by read-only discovery."""

    target: DynamicTarget
    pages: list[DiscoveredPage] = field(default_factory=list)
    endpoints: list[DiscoveredEndpoint] = field(default_factory=list)
    forms: list[DiscoveredForm] = field(default_factory=list)
    external_links: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    @property
    def parameters(self) -> list[DiscoveredParameter]:
        """
        Return unique parameters observed across endpoints and forms.
        """

        unique: dict[
            tuple[str, str, str | None],
            DiscoveredParameter,
        ] = {}

        for endpoint in self.endpoints:
            for parameter in endpoint.parameters:
                key = (
                    parameter.name,
                    parameter.location,
                    parameter.input_type,
                )
                unique[key] = parameter

        for form in self.forms:
            for parameter in form.parameters:
                key = (
                    parameter.name,
                    parameter.location,
                    parameter.input_type,
                )
                unique[key] = parameter

        return list(unique.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": {
                "original_url": self.target.original_url,
                "base_url": self.target.base_url,
                "origin": self.target.origin,
                "scheme": self.target.scheme,
                "hostname": self.target.hostname,
                "port": self.target.port,
                "start_path": self.target.start_path,
            },
            "pages": [
                page.to_dict()
                for page in self.pages
            ],
            "endpoints": [
                endpoint.to_dict()
                for endpoint in self.endpoints
            ],
            "forms": [
                form.to_dict()
                for form in self.forms
            ],
            "parameters": [
                parameter.to_dict()
                for parameter in self.parameters
            ],
            "external_links": list(self.external_links),
            "errors": list(self.errors),
            "summary": {
                "pages_discovered": len(self.pages),
                "endpoints_discovered": len(self.endpoints),
                "forms_discovered": len(self.forms),
                "parameters_discovered": len(self.parameters),
                "external_links_observed": len(self.external_links),
                "errors": len(self.errors),
            },
        }


class DynamicDiscovery:
    """
    Bounded same-origin crawler for generic application discovery.

    Only GET requests are performed.

    Forms are observed but never submitted by this component.
    """

    def __init__(
        self,
        *,
        session: requests.Session | None = None,
        request_timeout: int = DEFAULT_REQUEST_TIMEOUT,
        max_pages: int = DEFAULT_MAX_PAGES,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        if request_timeout <= 0:
            raise ValueError(
                "request_timeout must be greater than zero."
            )

        if max_pages <= 0:
            raise ValueError(
                "max_pages must be greater than zero."
            )

        if max_response_bytes <= 0:
            raise ValueError(
                "max_response_bytes must be greater than zero."
            )

        self.session = session or requests.Session()

        self.session.headers.update({
            "User-Agent": DISCOVERY_USER_AGENT,
        })

        self.request_timeout = request_timeout
        self.max_pages = max_pages
        self.max_response_bytes = max_response_bytes

    def discover(
        self,
        target: DynamicTarget,
    ) -> DiscoveryResult:
        """Discover a bounded same-origin application surface."""

        if not isinstance(target, DynamicTarget):
            raise TypeError(
                "target must be a DynamicTarget."
            )

        result = DiscoveryResult(
            target=target,
        )

        queue = [
            _normalise_discovery_url(
                target.base_url
            )
        ]

        queued = set(queue)
        visited: set[str] = set()

        endpoint_keys: set[
            tuple[str, str, tuple[tuple[str, str], ...]]
        ] = set()

        form_keys: set[
            tuple[str, str, tuple[str, ...]]
        ] = set()

        external_seen: set[str] = set()

        while queue and len(visited) < self.max_pages:
            current_url = queue.pop(0)
            queued.discard(current_url)

            if current_url in visited:
                continue

            visited.add(current_url)

            try:
                response = self.session.get(
                    current_url,
                    timeout=self.request_timeout,
                    allow_redirects=True,
                )

            except requests.RequestException as exc:
                result.errors.append({
                    "url": current_url,
                    "error": str(exc),
                })
                continue

            final_url = _normalise_discovery_url(
                response.url
            )

            # A redirect may leave the authorised origin.
            # Record the observation, but do not inspect/crawl it.
            if not target.is_same_origin(final_url):
                if final_url not in external_seen:
                    result.external_links.append(
                        final_url
                    )
                    external_seen.add(final_url)

                continue

            content_type = response.headers.get(
                "Content-Type"
            )

            response_length = len(
                response.content
            )

            title = None

            is_html = _is_html_response(
                content_type
            )

            within_body_budget = (
                response_length
                <= self.max_response_bytes
            )

            soup = None

            if is_html and within_body_budget:
                soup = BeautifulSoup(
                    response.text,
                    "html.parser",
                )

                if soup.title:
                    title_text = soup.title.get_text(
                        strip=True
                    )

                    if title_text:
                        title = title_text

            response_header_names = tuple(
                sorted(
                    {
                        str(name).strip()
                        for name in response.headers.keys()
                        if str(name).strip()
                    },
                    key=str.lower,
                )
            )

            cookie_names = tuple(
                sorted(
                    {
                        str(cookie.name).strip()
                        for cookie in response.cookies
                        if str(cookie.name).strip()
                    },
                    key=str.lower,
                )
            )

            redirect_count = len(
                getattr(
                    response,
                    "history",
                    (),
                )
            )

            result.pages.append(
                DiscoveredPage(
                    requested_url=current_url,
                    final_url=final_url,
                    status_code=response.status_code,
                    content_type=content_type,
                    response_length=response_length,
                    title=title,
                    response_header_names=(
                        response_header_names
                    ),
                    cookie_names=cookie_names,
                    redirect_count=redirect_count,
                )
            )

            query_parameters = (
                _extract_query_parameters(
                    final_url
                )
            )

            _append_endpoint(
                result=result,
                endpoint_keys=endpoint_keys,
                endpoint=DiscoveredEndpoint(
                    url=final_url,
                    method="GET",
                    parameters=tuple(
                        query_parameters
                    ),
                ),
            )

            if soup is None:
                continue

            for anchor in soup.find_all(
                "a",
                href=True,
            ):
                href = str(
                    anchor.get("href", "")
                ).strip()

                resolved = _resolve_http_url(
                    base_url=final_url,
                    candidate=href,
                )

                if resolved is None:
                    continue

                if target.is_same_origin(resolved):
                    link_parameters = (
                        _extract_query_parameters(
                            resolved
                        )
                    )

                    _append_endpoint(
                        result=result,
                        endpoint_keys=endpoint_keys,
                        endpoint=DiscoveredEndpoint(
                            url=resolved,
                            method="GET",
                            parameters=tuple(
                                link_parameters
                            ),
                        ),
                    )

                    crawl_url = (
                        _normalise_discovery_url(
                            resolved
                        )
                    )

                    if (
                        crawl_url not in visited
                        and crawl_url not in queued
                    ):
                        queue.append(
                            crawl_url
                        )
                        queued.add(
                            crawl_url
                        )

                elif resolved not in external_seen:
                    result.external_links.append(
                        resolved
                    )
                    external_seen.add(
                        resolved
                    )

            for form_element in soup.find_all(
                "form"
            ):
                form = _parse_form(
                    source_url=final_url,
                    form_element=form_element,
                )

                if not target.is_same_origin(
                    form.action_url
                ):
                    if (
                        form.action_url
                        not in external_seen
                    ):
                        result.external_links.append(
                            form.action_url
                        )
                        external_seen.add(
                            form.action_url
                        )

                    continue

                form_key = (
                    form.action_url,
                    form.method,
                    tuple(
                        parameter.name
                        for parameter in form.parameters
                    ),
                )

                if form_key not in form_keys:
                    result.forms.append(
                        form
                    )
                    form_keys.add(
                        form_key
                    )

                _append_endpoint(
                    result=result,
                    endpoint_keys=endpoint_keys,
                    endpoint=DiscoveredEndpoint(
                        url=form.action_url,
                        method=form.method,
                        parameters=form.parameters,
                    ),
                )

        return result


def _parse_form(
    *,
    source_url: str,
    form_element: Any,
) -> DiscoveredForm:
    """Convert an HTML form into a structured observation."""

    raw_action = str(
        form_element.get(
            "action",
            "",
        )
    ).strip()

    action_url = (
        _resolve_http_url(
            base_url=source_url,
            candidate=raw_action,
        )
        or source_url
    )

    raw_method = str(
        form_element.get(
            "method",
            "GET",
        )
    ).strip().upper()

    method = (
        raw_method
        if raw_method in {"GET", "POST"}
        else "GET"
    )

    parameter_location = (
        "query"
        if method == "GET"
        else "body"
    )

    parameters: list[
        DiscoveredParameter
    ] = []

    seen_names: set[str] = set()

    field_elements = form_element.find_all(
        ["input", "textarea", "select", "button"]
    )

    for field_element in field_elements:
        raw_name = field_element.get(
            "name"
        )

        if raw_name is None:
            continue

        name = str(raw_name).strip()

        if not name or name in seen_names:
            continue

        input_type = (
            str(
                field_element.get(
                    "type",
                    field_element.name,
                )
            )
            .strip()
            .lower()
        )

        observed_value = _extract_form_control_value(
            field_element
        )

        parameters.append(
            DiscoveredParameter(
                name=name,
                location=parameter_location,
                input_type=input_type,
                observed_value=observed_value,
            )
        )

        seen_names.add(
            name
        )

    return DiscoveredForm(
        source_url=source_url,
        action_url=_normalise_discovery_url(
            action_url
        ),
        method=method,
        parameters=tuple(parameters),
    )



def _extract_form_control_value(
    field_element: Any,
) -> str | None:
    """Return a reproducible default value for an observed HTML control.

    This is application-neutral discovery metadata. It does not submit the
    form, infer a vulnerability, or generate attack values.
    """

    tag_name = str(
        getattr(field_element, "name", "")
    ).strip().lower()

    input_type = str(
        field_element.get(
            "type",
            tag_name,
        )
    ).strip().lower()

    if tag_name == "textarea":
        return field_element.get_text()

    if tag_name == "select":
        selected = field_element.find(
            "option",
            selected=True,
        )

        if selected is None:
            selected = field_element.find("option")

        if selected is None:
            return None

        raw_value = selected.get("value")

        if raw_value is not None:
            return str(raw_value)

        return selected.get_text()

    if input_type in {"checkbox", "radio"}:
        if not field_element.has_attr("checked"):
            return None

        raw_value = field_element.get("value")

        return (
            str(raw_value)
            if raw_value is not None
            else "on"
        )

    if input_type == "file":
        return None

    raw_value = field_element.get("value")

    if raw_value is not None:
        return str(raw_value)

    # Text-like controls are successful controls even when their browser
    # default is the empty string. Submit/button controls without an explicit
    # value are also represented as empty rather than inventing a label.
    if tag_name in {"input", "button"}:
        return ""

    return None

def _extract_query_parameters(
    url: str,
) -> list[DiscoveredParameter]:
    """Extract unique query parameter names from a URL."""

    parsed = urlsplit(
        url
    )

    parameters: list[
        DiscoveredParameter
    ] = []

    seen: set[str] = set()

    for name, value in parse_qsl(
        parsed.query,
        keep_blank_values=True,
    ):
        if not name or name in seen:
            continue

        parameters.append(
            DiscoveredParameter(
                name=name,
                location="query",
                input_type=None,
                observed_value=value,
            )
        )

        seen.add(
            name
        )

    return parameters


def _resolve_http_url(
    *,
    base_url: str,
    candidate: str,
) -> str | None:
    """Resolve an HTTP(S) link and discard unsupported URL schemes."""

    candidate = candidate.strip()

    if not candidate:
        return _normalise_discovery_url(
            base_url
        )

    lowered = candidate.lower()

    if lowered.startswith(
        (
            "javascript:",
            "mailto:",
            "tel:",
            "data:",
        )
    ):
        return None

    resolved = urljoin(
        base_url,
        candidate,
    )

    resolved, _ = urldefrag(
        resolved
    )

    parsed = urlsplit(
        resolved
    )

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        return None

    return _normalise_discovery_url(
        resolved
    )


def _normalise_discovery_url(
    url: str,
) -> str:
    """Remove fragments while preserving path and query information."""

    clean_url, _ = urldefrag(
        url
    )

    parsed = urlsplit(
        clean_url
    )

    path = parsed.path or "/"

    return urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc,
            path,
            parsed.query,
            "",
        )
    )


def _is_html_response(
    content_type: str | None,
) -> bool:
    """Return True when a response appears to contain HTML."""

    if content_type is None:
        return False

    return "text/html" in content_type.lower()


def _append_endpoint(
    *,
    result: DiscoveryResult,
    endpoint_keys: set,
    endpoint: DiscoveredEndpoint,
) -> None:
    """Append an endpoint only when the observation is new."""

    key = (
        endpoint.url,
        endpoint.method,
        tuple(
            (
                parameter.name,
                parameter.location,
            )
            for parameter in endpoint.parameters
        ),
    )

    if key in endpoint_keys:
        return

    result.endpoints.append(
        endpoint
    )

    endpoint_keys.add(
        key
    )