import pytest

from app.dynamic_analysis.planning import (
    InjectionObservationPolicy,
    ProbeCandidate,
)


def candidate(
    *,
    parameter="q",
    endpoint="https://example.test/search",
    input_type="text",
    observed_value=None,
):
    return ProbeCandidate(
        endpoint=endpoint,
        method="GET",
        parameter=parameter,
        parameter_location="query",
        input_type=input_type,
        source="ENDPOINT",
        observed_value=observed_value,
    )


def test_text_plan_has_baseline_controls_and_syntax_values():
    plan = InjectionObservationPolicy().plan(candidate())
    assert plan.baseline_value == "egaa-baseline"
    assert plan.control_values == ("egaa-control-a", "egaa-control-b")
    assert plan.syntax_values == ("'", '"', "\\")
    assert plan.test_values == (
        "egaa-control-a",
        "egaa-control-b",
        "'",
        '"',
        "\\",
    )


def test_observed_value_is_preserved_as_baseline():
    plan = InjectionObservationPolicy().plan(
        candidate(observed_value="original")
    )
    assert plan.baseline_value == "original"


def test_numeric_inputs_use_numeric_family():
    plan = InjectionObservationPolicy().plan(
        candidate(input_type="number")
    )
    assert plan.baseline_value == "1"
    assert plan.control_values == ("2", "3")
    assert plan.syntax_values == ("1'", '1"', "1\\")


def test_parameter_name_does_not_select_payload_family():
    policy = InjectionObservationPolicy()
    a = policy.plan(candidate(parameter="id"))
    b = policy.plan(candidate(parameter="custom_parameter"))
    assert a == b


def test_endpoint_name_does_not_select_payload_family():
    policy = InjectionObservationPolicy()
    a = policy.plan(candidate(endpoint="https://example.test/sqli/"))
    b = policy.plan(candidate(endpoint="https://example.test/normal/"))
    assert a == b


def test_baseline_is_removed_from_controls():
    policy = InjectionObservationPolicy(
        default_text_baseline="same",
        text_controls=("same", "different"),
    )
    plan = policy.plan(candidate())
    assert plan.control_values == ("different",)


def test_baseline_is_removed_from_syntax_values():
    policy = InjectionObservationPolicy(
        default_text_baseline="'",
        text_syntax_values=("'", '"'),
    )
    plan = policy.plan(candidate())
    assert plan.syntax_values == ('"',)


def test_wrong_candidate_type_is_rejected():
    with pytest.raises(TypeError):
        InjectionObservationPolicy().plan(object())


def test_empty_control_policy_is_rejected():
    with pytest.raises(ValueError):
        InjectionObservationPolicy(text_controls=())


def test_empty_syntax_policy_is_rejected():
    with pytest.raises(ValueError):
        InjectionObservationPolicy(text_syntax_values=())


def test_policy_rejects_when_baseline_removes_all_controls():
    policy = InjectionObservationPolicy(
        default_text_baseline="same",
        text_controls=("same",),
    )
    with pytest.raises(ValueError):
        policy.plan(candidate())


def test_policy_rejects_when_baseline_removes_all_syntax_values():
    policy = InjectionObservationPolicy(
        default_text_baseline="'",
        text_syntax_values=("'",),
    )
    with pytest.raises(ValueError):
        policy.plan(candidate())
