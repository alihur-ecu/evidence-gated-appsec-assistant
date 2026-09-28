import pytest
from unittest.mock import Mock

from app.dynamic_analysis.planning import (
    BaselineResolution,
    InjectionObservationPolicy,
    InjectionProbeInputFactory,
    ProbeCandidate,
)
from app.dynamic_analysis.probes.injection.probe import InjectionProbeInput


def candidate(
    *,
    endpoint="https://example.test/search",
    method="GET",
    parameter="q",
    location="query",
    input_type="text",
    observed_value=None,
):
    return ProbeCandidate(
        endpoint=endpoint,
        method=method,
        parameter=parameter,
        parameter_location=location,
        input_type=input_type,
        source="ENDPOINT",
        observed_value=observed_value,
    )


def test_returns_real_injection_probe_input():
    result = InjectionProbeInputFactory().build(candidate())
    assert isinstance(result, InjectionProbeInput)


def test_preserves_candidate_runtime_identity():
    result = InjectionProbeInputFactory().build(
        candidate(
            endpoint="https://example.test/products",
            method="POST",
            parameter="product",
            location="body",
        )
    )
    assert result.endpoint == "https://example.test/products"
    assert result.method == "POST"
    assert result.parameter == "product"


def test_uses_observed_value_as_baseline_when_available():
    result = InjectionProbeInputFactory().build(
        candidate(observed_value="include.php")
    )
    assert result.baseline_value == "include.php"


def test_text_plan_contains_controls_then_syntax_values():
    result = InjectionProbeInputFactory().build(candidate())
    assert result.baseline_value == "egaa-baseline"
    assert result.test_values == (
        "egaa-control-a",
        "egaa-control-b",
        "'",
        '"',
        "\\",
    )


def test_numeric_plan_uses_numeric_values():
    result = InjectionProbeInputFactory().build(
        candidate(input_type="number")
    )
    assert result.baseline_value == "1"
    assert result.test_values == ("2", "3", "1'", '1"', "1\\")


def test_preserves_fixed_parameters_without_mutating_input():
    fixed = {"page": "1", "mode": "view"}
    result = InjectionProbeInputFactory().build(
        candidate(parameter="q"),
        fixed_parameters=fixed,
    )
    assert result.fixed_parameters == fixed
    assert result.fixed_parameters is not fixed


def test_parameter_name_does_not_change_policy():
    factory = InjectionProbeInputFactory()
    first = factory.build(candidate(parameter="id"))
    second = factory.build(candidate(parameter="anything"))
    assert first.test_values == second.test_values


def test_endpoint_name_does_not_change_policy():
    factory = InjectionProbeInputFactory()
    first = factory.build(candidate(endpoint="https://example.test/sqli/"))
    second = factory.build(candidate(endpoint="https://example.test/normal/"))
    assert first.test_values == second.test_values


def test_custom_policy_is_honoured():
    policy = InjectionObservationPolicy(
        default_text_baseline="base",
        text_controls=("control",),
        text_syntax_values=("'",),
    )
    result = InjectionProbeInputFactory(policy=policy).build(candidate())
    assert result.baseline_value == "base"
    assert result.test_values == ("control", "'")


def test_runtime_builder_uses_resolved_baseline():
    resolver = Mock()
    resolver.resolve.return_value = BaselineResolution(
        value="42",
        source="SYNTHETIC",
        status_code=200,
        response_length=10,
        response_digest="abc",
        repeatable=True,
    )
    factory = InjectionProbeInputFactory(baseline_resolver=resolver)

    result = factory.build_with_resolved_baseline(
        candidate(),
        session=Mock(),
    )

    assert result.baseline_value == "42"
    resolver.resolve.assert_called_once()


def test_runtime_builder_preserves_fixed_parameters():
    resolver = Mock()
    resolver.resolve.return_value = BaselineResolution(
        value="known",
        source="OBSERVED",
        status_code=200,
        response_length=10,
        response_digest="abc",
        repeatable=True,
    )
    factory = InjectionProbeInputFactory(baseline_resolver=resolver)

    result = factory.build_with_resolved_baseline(
        candidate(),
        session=Mock(),
        fixed_parameters={"mode": "view"},
    )

    assert result.fixed_parameters == {"mode": "view"}


def test_wrong_candidate_type_is_rejected():
    with pytest.raises(TypeError):
        InjectionProbeInputFactory().build(object())
