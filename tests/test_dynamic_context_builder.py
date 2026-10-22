from app.dynamic_analysis.context_builder import (
    DynamicContextBuilder,
)
from app.dynamic_analysis.discovery import (
    DiscoveredEndpoint,
    DiscoveredForm,
    DiscoveredPage,
    DiscoveredParameter,
    DiscoveryResult,
)
from app.dynamic_analysis.target import (
    build_dynamic_target,
)


def make_discovery():
    target = build_dynamic_target(
        "https://example.test"
    )

    result = DiscoveryResult(
        target=target
    )

    result.pages.append(
        DiscoveredPage(
            requested_url="https://example.test/",
            final_url="https://example.test/",
            status_code=200,
            content_type="text/html; charset=utf-8",
            response_length=512,
            title="Example Login",
            response_header_names=(
                "Content-Type",
                "X-Test-Header",
            ),
            cookie_names=("session",),
            redirect_count=0,
        )
    )

    result.forms.append(
        DiscoveredForm(
            source_url="https://example.test/",
            action_url="https://example.test/login",
            method="POST",
            parameters=(
                DiscoveredParameter(
                    name="username",
                    location="body",
                    input_type="text",
                ),
                DiscoveredParameter(
                    name="password",
                    location="body",
                    input_type="password",
                ),
            ),
        )
    )

    result.endpoints.extend([
        DiscoveredEndpoint(
            url="https://example.test/login",
            method="POST",
            parameters=(
                DiscoveredParameter(
                    name="username",
                    location="body",
                    input_type="text",
                ),
                DiscoveredParameter(
                    name="password",
                    location="body",
                    input_type="password",
                ),
            ),
        ),
        DiscoveredEndpoint(
            url="https://example.test/search?q=test",
            method="GET",
            parameters=(
                DiscoveredParameter(
                    name="q",
                    location="query",
                ),
            ),
        ),
    ])

    return result


def test_builds_dynamic_contexts():
    result = DynamicContextBuilder().build(
        make_discovery()
    )

    assert result.contexts_created == 2
    assert result.contexts_selected == 2
    assert len(result.contexts) == 2


def test_form_context_is_created_first():
    result = DynamicContextBuilder().build(
        make_discovery()
    )

    context = result.contexts[0]

    assert context.context_type == "FORM"
    assert context.method == "POST"
    assert (
        context.endpoint_url
        == "https://example.test/login"
    )


def test_form_preserves_source_provenance():
    result = DynamicContextBuilder().build(
        make_discovery()
    )

    context = result.contexts[0]

    assert (
        context.source_url
        == "https://example.test/"
    )

    assert (
        context.observed_from
        == "HTML_FORM"
    )


def test_preserves_form_parameters():
    result = DynamicContextBuilder().build(
        make_discovery()
    )

    context = result.contexts[0]

    names = {
        parameter["name"]
        for parameter in context.parameters
    }

    assert names == {
        "username",
        "password",
    }


def test_does_not_duplicate_form_endpoint():
    result = DynamicContextBuilder().build(
        make_discovery()
    )

    login_contexts = [
        context
        for context in result.contexts
        if (
            context.endpoint_url
            == "https://example.test/login"
        )
    ]

    assert len(login_contexts) == 1


def test_creates_remaining_endpoint_context():
    result = DynamicContextBuilder().build(
        make_discovery()
    )

    search_contexts = [
        context
        for context in result.contexts
        if "search?q=test" in context.endpoint_url
    ]

    assert len(search_contexts) == 1
    assert search_contexts[0].method == "GET"


def test_context_explicitly_marks_not_verified():
    result = DynamicContextBuilder().build(
        make_discovery()
    )

    assert (
        "Security status: NOT VERIFIED"
        in result.contexts[0].context_text
    )


def test_context_does_not_claim_vulnerability():
    result = DynamicContextBuilder().build(
        make_discovery()
    )

    text = result.contexts[0].context_text.lower()

    assert "vulnerability exists" in text
    assert "not evidence" in text


def test_respects_context_count_budget():
    result = DynamicContextBuilder(
        max_contexts=1
    ).build(
        make_discovery()
    )

    assert result.contexts_created == 2
    assert result.contexts_selected == 1
    assert (
        result.contexts_excluded_by_budget
        == 1
    )

    assert result.truncated is True

    assert (
        "Maximum number"
        in result.truncation_reason
    )


def test_respects_character_budget():
    discovery = make_discovery()

    unrestricted = (
        DynamicContextBuilder().build(
            discovery
        )
    )

    first_size = (
        unrestricted.contexts[0].char_count
    )

    result = DynamicContextBuilder(
        max_context_chars=first_size
    ).build(
        discovery
    )

    assert result.contexts_selected == 1
    assert result.truncated is True


def test_reports_coverage():
    result = DynamicContextBuilder().build(
        make_discovery()
    )

    payload = result.to_dict()

    coverage = payload["coverage"]

    assert coverage[
        "endpoints_discovered"
    ] == 2

    assert coverage[
        "forms_discovered"
    ] == 1

    assert coverage[
        "contexts_created"
    ] == 2

    assert coverage[
        "contexts_selected"
    ] == 2


def test_empty_discovery_produces_empty_context():
    target = build_dynamic_target(
        "https://example.test"
    )

    discovery = DiscoveryResult(
        target=target
    )

    result = DynamicContextBuilder().build(
        discovery
    )

    assert result.contexts == []
    assert result.contexts_created == 0
    assert result.contexts_selected == 0
    assert result.truncated is False


def test_form_context_includes_associated_http_observation():
    result = DynamicContextBuilder().build(
        make_discovery()
    )

    context = result.contexts[0]

    assert context.http_observation is not None
    assert context.http_observation["status_code"] == 200
    assert context.http_observation["title"] == "Example Login"
    assert "Observed HTTP response:" in context.context_text
    assert "- Status code: 200" in context.context_text
    assert "X-Test-Header" in context.context_text
    assert "session" in context.context_text


def test_context_does_not_include_cookie_values():
    result = DynamicContextBuilder().build(
        make_discovery()
    )

    text = result.contexts[0].context_text

    assert "session" in text
    assert "secret-value" not in text


def test_unfetched_endpoint_remains_valid_without_http_observation():
    result = DynamicContextBuilder().build(
        make_discovery()
    )

    search_context = next(
        context
        for context in result.contexts
        if "search?q=test" in context.endpoint_url
    )

    assert search_context.http_observation is None
    assert (
        "no fetched response associated"
        in search_context.context_text
    )
