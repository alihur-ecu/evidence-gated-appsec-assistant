from bs4 import BeautifulSoup

from app.dynamic_analysis.discovery import (
    DiscoveredEndpoint,
    DiscoveredForm,
    DiscoveredParameter,
    DiscoveryResult,
    _parse_form,
)
from app.dynamic_analysis.planning import ProbeCandidateBuilder
from app.dynamic_analysis.target import build_dynamic_target


def _discovery(*, endpoints=(), forms=()):
    return DiscoveryResult(
        target=build_dynamic_target("https://example.test/"),
        endpoints=list(endpoints),
        forms=list(forms),
    )


def test_form_discovery_preserves_generic_default_values():
    html = """
    <form action="/search" method="get">
      <input name="q" type="text">
      <input name="scope" type="hidden" value="docs">
      <select name="category">
        <option value="all">All</option>
        <option value="books" selected>Books</option>
      </select>
      <textarea name="note">hello</textarea>
      <input name="action" type="submit" value="Search">
    </form>
    """
    form = _parse_form(
        source_url="https://example.test/",
        form_element=BeautifulSoup(html, "html.parser").form,
    )

    values = {p.name: p.observed_value for p in form.parameters}
    assert values == {
        "q": "",
        "scope": "docs",
        "category": "books",
        "note": "hello",
        "action": "Search",
    }


def test_unchecked_checkbox_is_not_invented_as_submitted_value():
    html = """
    <form action="/prefs" method="post">
      <input name="enabled" type="checkbox">
      <input name="mode" type="checkbox" checked>
    </form>
    """
    form = _parse_form(
        source_url="https://example.test/",
        form_element=BeautifulSoup(html, "html.parser").form,
    )
    values = {p.name: p.observed_value for p in form.parameters}
    assert values["enabled"] is None
    assert values["mode"] == "on"


def test_builder_preserves_sibling_request_context_without_probing_submit():
    form = DiscoveredForm(
        source_url="https://example.test/",
        action_url="https://example.test/search",
        method="GET",
        parameters=(
            DiscoveredParameter("q", "query", "text", ""),
            DiscoveredParameter("scope", "query", "hidden", "docs"),
            DiscoveredParameter("action", "query", "submit", "Search"),
        ),
    )

    candidates = ProbeCandidateBuilder().build(
        _discovery(forms=(form,))
    )

    assert [c.parameter for c in candidates] == ["q"]
    assert candidates[0].fixed_parameters == {
        "scope": "docs",
        "action": "Search",
    }


def test_endpoint_candidate_is_enriched_by_equivalent_form_context():
    parameter = DiscoveredParameter("q", "query", "text", "hello")
    result = _discovery(
        endpoints=(
            DiscoveredEndpoint(
                url="https://example.test/search?q=hello",
                method="GET",
                parameters=(parameter,),
            ),
        ),
        forms=(
            DiscoveredForm(
                source_url="https://example.test/",
                action_url="https://example.test/search",
                method="GET",
                parameters=(
                    DiscoveredParameter("q", "query", "text", ""),
                    DiscoveredParameter(
                        "action",
                        "query",
                        "submit",
                        "Search",
                    ),
                ),
            ),
        ),
    )

    candidates = ProbeCandidateBuilder().build(result)
    assert len(candidates) == 1
    assert candidates[0].source == "ENDPOINT"
    assert candidates[0].observed_value == "hello"
    assert candidates[0].fixed_parameters == {"action": "Search"}


def test_context_never_contains_parameter_under_test():
    form = DiscoveredForm(
        source_url="https://example.test/",
        action_url="https://example.test/search",
        method="POST",
        parameters=(
            DiscoveredParameter("query", "body", "text", "initial"),
            DiscoveredParameter("mode", "body", "hidden", "safe"),
        ),
    )

    candidate = ProbeCandidateBuilder().build(
        _discovery(forms=(form,))
    )[0]

    assert "query" not in candidate.fixed_parameters
    assert candidate.fixed_parameters == {"mode": "safe"}
