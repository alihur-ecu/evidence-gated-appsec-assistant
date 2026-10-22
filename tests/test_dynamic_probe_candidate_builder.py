from app.dynamic_analysis.discovery import (
    DiscoveredEndpoint,
    DiscoveredForm,
    DiscoveredParameter,
    DiscoveryResult,
)
from app.dynamic_analysis.planning import ProbeCandidateBuilder
from app.dynamic_analysis.target import build_dynamic_target


def discovery(*, endpoints=(), forms=()):
    return DiscoveryResult(
        target=build_dynamic_target("https://example.test/"),
        endpoints=list(endpoints),
        forms=list(forms),
    )


def test_builds_query_candidate_and_preserves_observed_value():
    result = discovery(
        endpoints=(
            DiscoveredEndpoint(
                url="https://example.test/products?id=1",
                method="GET",
                parameters=(DiscoveredParameter("id", "query", None),),
            ),
        )
    )

    candidates = ProbeCandidateBuilder().build(result)

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.endpoint == "https://example.test/products"
    assert candidate.method == "GET"
    assert candidate.parameter == "id"
    assert candidate.parameter_location == "query"
    assert candidate.observed_value == "1"
    assert candidate.source == "ENDPOINT"


def test_builds_text_body_candidate_without_inventing_value():
    result = discovery(
        forms=(
            DiscoveredForm(
                source_url="https://example.test/search",
                action_url="https://example.test/search",
                method="POST",
                parameters=(DiscoveredParameter("query", "body", "text"),),
            ),
        )
    )

    candidates = ProbeCandidateBuilder().build(result)

    assert len(candidates) == 1
    assert candidates[0].parameter == "query"
    assert candidates[0].parameter_location == "body"
    assert candidates[0].observed_value is None


def test_excludes_submit_and_hidden_controls():
    result = discovery(
        forms=(
            DiscoveredForm(
                source_url="https://example.test/login",
                action_url="https://example.test/login",
                method="POST",
                parameters=(
                    DiscoveredParameter("username", "body", "text"),
                    DiscoveredParameter("token", "body", "hidden"),
                    DiscoveredParameter("Login", "body", "submit"),
                ),
            ),
        )
    )

    candidates = ProbeCandidateBuilder().build(result)
    assert [item.parameter for item in candidates] == ["username"]


def test_password_is_not_silently_excluded_by_name_or_type():
    result = discovery(
        forms=(
            DiscoveredForm(
                source_url="https://example.test/login",
                action_url="https://example.test/login",
                method="POST",
                parameters=(DiscoveredParameter("password", "body", "password"),),
            ),
        )
    )

    candidates = ProbeCandidateBuilder().build(result)
    assert len(candidates) == 1
    assert candidates[0].input_type == "password"


def test_deduplicates_same_surface_across_different_query_values():
    result = discovery(
        endpoints=(
            DiscoveredEndpoint(
                url="https://example.test/file?page=include.php",
                method="GET",
                parameters=(DiscoveredParameter("page", "query", None),),
            ),
            DiscoveredEndpoint(
                url="https://example.test/file?page=file1.php",
                method="GET",
                parameters=(DiscoveredParameter("page", "query", None),),
            ),
            DiscoveredEndpoint(
                url="https://example.test/file?page=file2.php",
                method="GET",
                parameters=(DiscoveredParameter("page", "query", None),),
            ),
        )
    )

    candidates = ProbeCandidateBuilder().build(result)

    assert len(candidates) == 1
    assert candidates[0].endpoint == "https://example.test/file"
    assert candidates[0].parameter == "page"
    assert candidates[0].observed_value == "include.php"


def test_deduplicates_equivalent_endpoint_and_form_surface():
    parameter = DiscoveredParameter("q", "query", "text")
    result = discovery(
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
                parameters=(parameter,),
            ),
        ),
    )

    candidates = ProbeCandidateBuilder().build(result)

    assert len(candidates) == 1
    assert candidates[0].source == "ENDPOINT"
    assert candidates[0].observed_value == "hello"


def test_keeps_different_parameters_on_same_endpoint():
    result = discovery(
        endpoints=(
            DiscoveredEndpoint(
                url="https://example.test/search?q=hello&page=2",
                method="GET",
                parameters=(
                    DiscoveredParameter("q", "query", "text"),
                    DiscoveredParameter("page", "query", "number"),
                ),
            ),
        )
    )

    candidates = ProbeCandidateBuilder().build(result)

    assert [item.parameter for item in candidates] == ["q", "page"]
    assert [item.observed_value for item in candidates] == ["hello", "2"]


def test_decodes_observed_query_value():
    result = discovery(
        endpoints=(
            DiscoveredEndpoint(
                url="https://example.test/search?q=hello%20world",
                method="GET",
                parameters=(DiscoveredParameter("q", "query", "text"),),
            ),
        )
    )

    candidates = ProbeCandidateBuilder().build(result)
    assert candidates[0].observed_value == "hello world"


def test_blank_query_value_is_preserved():
    result = discovery(
        endpoints=(
            DiscoveredEndpoint(
                url="https://example.test/search?q=",
                method="GET",
                parameters=(DiscoveredParameter("q", "query", "text"),),
            ),
        )
    )

    candidates = ProbeCandidateBuilder().build(result)
    assert candidates[0].observed_value == ""


def test_builder_does_not_use_application_specific_parameter_names():
    result = discovery(
        endpoints=(
            DiscoveredEndpoint(
                url="https://example.test/action?totally_custom_field=value",
                method="GET",
                parameters=(
                    DiscoveredParameter(
                        "totally_custom_field",
                        "query",
                        None,
                    ),
                ),
            ),
        )
    )

    candidates = ProbeCandidateBuilder().build(result)
    assert len(candidates) == 1
    assert candidates[0].parameter == "totally_custom_field"
    assert candidates[0].observed_value == "value"


def test_empty_discovery_produces_no_candidates():
    assert ProbeCandidateBuilder().build(discovery()) == ()


def test_rejects_wrong_input_type():
    try:
        ProbeCandidateBuilder().build(object())
    except TypeError:
        return
    raise AssertionError("Expected TypeError")
