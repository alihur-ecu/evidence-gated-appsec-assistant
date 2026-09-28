"""
Generic dynamic-analysis context builder.

Transforms deterministic discovery observations into bounded context
units suitable for downstream LLM analysis.

Responsibilities:

- preserve runtime observation provenance;
- keep endpoints and forms as meaningful analysis units;
- distinguish observed facts from future inferred metadata;
- enforce deterministic context budgets;
- report analysis coverage honestly.

This module does NOT:

- call an LLM;
- detect vulnerabilities;
- execute attack payloads;
- verify security findings;
- infer an application category.

Architecture principle:

    Dynamic discovery
        ->
    Dynamic context builder
        ->
    Bounded context units
        ->
    Selected LLM proposer
        ->
    Candidate proposals
        ->
    Evidence verifies
        ->
    Human decides
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from app.dynamic_analysis.discovery import (
    DiscoveryResult,
    DiscoveredEndpoint,
    DiscoveredForm,
    DiscoveredPage,
)


DEFAULT_MAX_CONTEXTS = 100
DEFAULT_MAX_CONTEXT_CHARS = 100_000


@dataclass(frozen=True)
class DynamicContext:
    """
    One deterministic unit of runtime context.

    A context describes an observed endpoint or form. It contains facts
    collected during discovery, not vulnerability conclusions.
    """

    context_id: str
    context_type: str

    source_url: str
    endpoint_url: str
    method: str

    parameters: tuple[dict[str, Any], ...]

    observed_from: str

    context_text: str
    char_count: int

    # Optional enriched HTTP metadata. Keeping this field optional preserves
    # compatibility with existing callers/tests that construct DynamicContext
    # without HTTP response observations.
    http_observation: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DynamicContextBuildResult:
    """Dynamic contexts plus transparent coverage information."""

    contexts: list[DynamicContext]

    endpoints_discovered: int
    forms_discovered: int

    contexts_created: int
    contexts_selected: int
    contexts_excluded_by_budget: int

    total_context_chars: int
    selected_chars: int

    truncated: bool
    truncation_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "contexts": [
                context.to_dict()
                for context in self.contexts
            ],
            "coverage": {
                "endpoints_discovered":
                    self.endpoints_discovered,
                "forms_discovered":
                    self.forms_discovered,
                "contexts_created":
                    self.contexts_created,
                "contexts_selected":
                    self.contexts_selected,
                "contexts_excluded_by_budget":
                    self.contexts_excluded_by_budget,
                "total_context_chars":
                    self.total_context_chars,
                "selected_chars":
                    self.selected_chars,
                "truncated":
                    self.truncated,
                "truncation_reason":
                    self.truncation_reason,
            },
        }


class DynamicContextBuilder:
    """
    Build deterministic LLM-ready context from discovery observations.

    Contexts are intentionally endpoint/form oriented rather than
    source-file oriented.

    Application-category inference is deliberately outside this class.
    A future classifier may enrich downstream analysis without changing
    the deterministic observations produced here.
    """

    def __init__(
        self,
        *,
        max_contexts: int = DEFAULT_MAX_CONTEXTS,
        max_context_chars: int = DEFAULT_MAX_CONTEXT_CHARS,
    ) -> None:
        if max_contexts <= 0:
            raise ValueError(
                "max_contexts must be greater than zero."
            )

        if max_context_chars <= 0:
            raise ValueError(
                "max_context_chars must be greater than zero."
            )

        self.max_contexts = max_contexts
        self.max_context_chars = max_context_chars

    def build(
        self,
        discovery: DiscoveryResult,
    ) -> DynamicContextBuildResult:
        """
        Convert discovery observations into bounded contexts.

        Forms are emitted first because they provide richer information
        about methods and input locations. Remaining endpoint
        observations are then emitted deterministically.
        """

        if not isinstance(
            discovery,
            DiscoveryResult,
        ):
            raise TypeError(
                "discovery must be a DiscoveryResult."
            )

        candidate_contexts = (
            self._build_candidate_contexts(
                discovery
            )
        )

        total_context_chars = sum(
            context.char_count
            for context in candidate_contexts
        )

        selected_contexts: list[
            DynamicContext
        ] = []

        selected_chars = 0

        truncated = False
        truncation_reason: str | None = None

        for context in candidate_contexts:
            if (
                len(selected_contexts)
                >= self.max_contexts
            ):
                truncated = True
                truncation_reason = (
                    "Maximum number of dynamic contexts "
                    "selected for analysis was reached."
                )
                break

            if (
                selected_chars
                + context.char_count
                > self.max_context_chars
            ):
                truncated = True
                truncation_reason = (
                    "Maximum dynamic-context character "
                    "analysis budget was reached."
                )
                break

            selected_contexts.append(
                context
            )

            selected_chars += (
                context.char_count
            )

        contexts_created = len(
            candidate_contexts
        )

        contexts_selected = len(
            selected_contexts
        )

        contexts_excluded_by_budget = max(
            0,
            contexts_created
            - contexts_selected,
        )

        return DynamicContextBuildResult(
            contexts=selected_contexts,
            endpoints_discovered=len(
                discovery.endpoints
            ),
            forms_discovered=len(
                discovery.forms
            ),
            contexts_created=contexts_created,
            contexts_selected=contexts_selected,
            contexts_excluded_by_budget=(
                contexts_excluded_by_budget
            ),
            total_context_chars=(
                total_context_chars
            ),
            selected_chars=selected_chars,
            truncated=truncated,
            truncation_reason=(
                truncation_reason
            ),
        )

    def _build_candidate_contexts(
        self,
        discovery: DiscoveryResult,
    ) -> list[DynamicContext]:
        """
        Build deterministic contexts without duplicating form endpoints.

        A form contains richer information than its corresponding
        generic endpoint observation, so the form representation wins.
        """

        contexts: list[
            DynamicContext
        ] = []

        represented_endpoint_keys: set[
            tuple[str, str]
        ] = set()

        sorted_forms = sorted(
            discovery.forms,
            key=lambda form: (
                form.action_url.lower(),
                form.method,
                form.source_url.lower(),
            ),
        )

        for index, form in enumerate(
            sorted_forms,
            start=1,
        ):
            contexts.append(
                self._context_from_form(
                    form=form,
                    index=index,
                    page=_find_page_for_url(
                        discovery.pages,
                        form.source_url,
                    ),
                )
            )

            represented_endpoint_keys.add(
                (
                    form.action_url,
                    form.method,
                )
            )

        remaining_endpoints = sorted(
            discovery.endpoints,
            key=lambda endpoint: (
                endpoint.url.lower(),
                endpoint.method,
            ),
        )

        endpoint_index = 1

        for endpoint in remaining_endpoints:
            endpoint_key = (
                endpoint.url,
                endpoint.method,
            )

            if (
                endpoint_key
                in represented_endpoint_keys
            ):
                continue

            contexts.append(
                self._context_from_endpoint(
                    endpoint=endpoint,
                    index=endpoint_index,
                    page=_find_page_for_url(
                        discovery.pages,
                        endpoint.url,
                    ),
                )
            )

            endpoint_index += 1

        return contexts

    @staticmethod
    def _context_from_form(
        *,
        form: DiscoveredForm,
        index: int,
        page: DiscoveredPage | None = None,
    ) -> DynamicContext:
        """Create context from an observed HTML form."""

        parameters = tuple(
            parameter.to_dict()
            for parameter in form.parameters
        )

        http_observation = _page_observation(
            page
        )

        context_text = (
            _render_context_text(
                context_type="FORM",
                source_url=form.source_url,
                endpoint_url=form.action_url,
                method=form.method,
                parameters=parameters,
                observed_from="HTML_FORM",
                http_observation=http_observation,
            )
        )

        return DynamicContext(
            context_id=(
                f"dynamic-form-{index:04d}"
            ),
            context_type="FORM",
            source_url=form.source_url,
            endpoint_url=form.action_url,
            method=form.method,
            parameters=parameters,
            observed_from="HTML_FORM",
            http_observation=http_observation,
            context_text=context_text,
            char_count=len(
                context_text
            ),
        )

    @staticmethod
    def _context_from_endpoint(
        *,
        endpoint: DiscoveredEndpoint,
        index: int,
        page: DiscoveredPage | None = None,
    ) -> DynamicContext:
        """Create context from an observed endpoint."""

        parameters = tuple(
            parameter.to_dict()
            for parameter in endpoint.parameters
        )

        http_observation = _page_observation(
            page
        )

        context_text = (
            _render_context_text(
                context_type="ENDPOINT",
                source_url=endpoint.url,
                endpoint_url=endpoint.url,
                method=endpoint.method,
                parameters=parameters,
                observed_from="DISCOVERY",
                http_observation=http_observation,
            )
        )

        return DynamicContext(
            context_id=(
                f"dynamic-endpoint-{index:04d}"
            ),
            context_type="ENDPOINT",
            source_url=endpoint.url,
            endpoint_url=endpoint.url,
            method=endpoint.method,
            parameters=parameters,
            observed_from="DISCOVERY",
            http_observation=http_observation,
            context_text=context_text,
            char_count=len(
                context_text
            ),
        )



def _find_page_for_url(
    pages: list[DiscoveredPage],
    url: str,
) -> DiscoveredPage | None:
    """Return the fetched page that exactly matches an observed URL."""

    for page in pages:
        if (
            page.final_url == url
            or page.requested_url == url
        ):
            return page

    return None


def _page_observation(
    page: DiscoveredPage | None,
) -> dict[str, Any] | None:
    """
    Convert fetched-page metadata into privacy-conscious LLM context.

    Header and cookie names are preserved, but values are not forwarded.
    """

    if page is None:
        return None

    return {
        "requested_url": page.requested_url,
        "final_url": page.final_url,
        "status_code": page.status_code,
        "content_type": page.content_type,
        "response_length": page.response_length,
        "title": page.title,
        "response_header_names": page.response_header_names,
        "cookie_names": page.cookie_names,
        "redirect_count": page.redirect_count,
    }

def _render_context_text(
    *,
    context_type: str,
    source_url: str,
    endpoint_url: str,
    method: str,
    parameters: tuple[
        dict[str, Any],
        ...
    ],
    observed_from: str,
    http_observation: dict[str, Any] | None = None,
) -> str:
    """
    Render deterministic plain-text context for a downstream proposer.

    The wording intentionally distinguishes observations from security
    conclusions.
    """

    lines = [
        "DYNAMIC APPLICATION OBSERVATION",
        "",
        f"Context type: {context_type}",
        f"Observed from: {observed_from}",
        f"Source URL: {source_url}",
        f"Endpoint URL: {endpoint_url}",
        f"HTTP method: {method}",
        "",
        "Observed parameters:",
    ]

    if parameters:
        for parameter in parameters:
            name = parameter.get(
                "name",
                "",
            )

            location = parameter.get(
                "location",
                "unknown",
            )

            input_type = parameter.get(
                "input_type"
            )

            description = (
                f"- {name} "
                f"[location={location}"
            )

            if input_type:
                description += (
                    f", type={input_type}"
                )

            description += "]"

            lines.append(
                description
            )

    else:
        lines.append(
            "- none observed"
        )

    lines.extend([
        "",
        "Observed HTTP response:",
    ])

    if http_observation:
        lines.extend([
            f"- Status code: {http_observation['status_code']}",
            (
                "- Content-Type: "
                f"{http_observation.get('content_type') or 'unknown'}"
            ),
            (
                "- Response length: "
                f"{http_observation['response_length']} bytes"
            ),
            (
                "- Page title: "
                f"{http_observation.get('title') or 'not observed'}"
            ),
            (
                "- Redirect count: "
                f"{http_observation['redirect_count']}"
            ),
        ])

        header_names = http_observation.get(
            "response_header_names",
            (),
        )
        lines.append(
            "- Response header names: "
            + (
                ", ".join(header_names)
                if header_names
                else "none observed"
            )
        )

        cookie_names = http_observation.get(
            "cookie_names",
            (),
        )
        lines.append(
            "- Cookie names: "
            + (
                ", ".join(cookie_names)
                if cookie_names
                else "none observed"
            )
        )
    else:
        lines.append(
            "- no fetched response associated with this context"
        )

    lines.extend([
        "",
        (
            "Security status: "
            "NOT VERIFIED"
        ),
        (
            "This context contains observations only. "
            "It is not evidence that a vulnerability exists."
        ),
    ])

    return "\n".join(
        lines
    )