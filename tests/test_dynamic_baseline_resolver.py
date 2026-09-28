from unittest.mock import Mock

import pytest
import requests

from app.dynamic_analysis.planning import (
    BaselineResolutionPolicy,
    BaselineResolver,
    ProbeCandidate,
)


def candidate(*, method="GET", input_type="text", observed_value=None):
    return ProbeCandidate(
        endpoint="https://example.test/item",
        method=method,
        parameter="q",
        parameter_location="query" if method == "GET" else "body",
        input_type=input_type,
        source="ENDPOINT",
        observed_value=observed_value,
    )


def response(body=b"stable", status=200):
    r = Mock()
    r.status_code = status
    r.content = body
    return r


def test_resolves_repeatable_synthetic_text_baseline():
    session = Mock(spec=requests.Session)
    session.get.side_effect = [response(), response()]

    result = BaselineResolver().resolve(candidate(), session=session)

    assert result.value == "1"
    assert result.source == "SYNTHETIC"
    assert result.status_code == 200
    assert result.response_length == 6
    assert result.repeatable is True
    assert session.get.call_count == 2


def test_observed_value_is_preferred_and_repeated():
    session = Mock(spec=requests.Session)
    session.get.side_effect = [response(), response()]

    result = BaselineResolver().resolve(
        candidate(observed_value="known"),
        session=session,
    )

    assert result.value == "known"
    assert result.source == "OBSERVED"
    assert result.repeatable is True
    for call in session.get.call_args_list:
        assert call.kwargs["params"]["q"] == "known"


def test_numeric_candidate_uses_numeric_policy():
    policy = BaselineResolutionPolicy(
        numeric_candidates=("7",),
        text_candidates=("text",),
    )
    session = Mock(spec=requests.Session)
    session.get.side_effect = [response(), response()]

    result = BaselineResolver(policy=policy).resolve(
        candidate(input_type="number"),
        session=session,
    )

    assert result.value == "7"


def test_post_candidate_uses_body_data():
    session = Mock(spec=requests.Session)
    session.post.side_effect = [response(), response()]

    result = BaselineResolver().resolve(
        candidate(method="POST"),
        session=session,
    )

    assert result.repeatable is True
    assert session.post.call_count == 2
    assert session.post.call_args.kwargs["data"]["q"] == "1"


def test_fixed_parameters_are_preserved():
    session = Mock(spec=requests.Session)
    session.get.side_effect = [response(), response()]

    BaselineResolver().resolve(
        candidate(),
        session=session,
        fixed_parameters={"mode": "view"},
    )

    assert session.get.call_args.kwargs["params"] == {
        "mode": "view",
        "q": "1",
    }


def test_unstable_first_value_moves_to_next_candidate():
    session = Mock(spec=requests.Session)
    session.get.side_effect = [
        response(b"a"),
        response(b"b"),
        response(b"stable"),
        response(b"stable"),
    ]

    policy = BaselineResolutionPolicy(
        text_candidates=("first", "second"),
    )
    result = BaselineResolver(policy=policy).resolve(
        candidate(),
        session=session,
    )

    assert result.value == "second"
    assert result.repeatable is True


def test_non_success_first_value_moves_to_next_candidate():
    session = Mock(spec=requests.Session)
    session.get.side_effect = [
        response(status=500),
        response(status=500),
        response(status=200),
        response(status=200),
    ]

    policy = BaselineResolutionPolicy(
        text_candidates=("first", "second"),
    )
    result = BaselineResolver(policy=policy).resolve(
        candidate(),
        session=session,
    )

    assert result.value == "second"
    assert result.status_code == 200


def test_returns_fallback_when_no_candidate_is_stable_success():
    session = Mock(spec=requests.Session)
    session.get.side_effect = [
        response(b"a", 500),
        response(b"a", 500),
        response(b"b", 500),
        response(b"b", 500),
    ]

    policy = BaselineResolutionPolicy(
        text_candidates=("first", "second"),
    )
    result = BaselineResolver(policy=policy).resolve(
        candidate(),
        session=session,
    )

    assert result.value == "first"
    assert result.status_code == 500


def test_wrong_candidate_type_is_rejected():
    with pytest.raises(TypeError):
        BaselineResolver().resolve(object(), session=Mock())


def test_policy_requires_repeat_count_of_at_least_two():
    with pytest.raises(ValueError):
        BaselineResolutionPolicy(repeat_count=1)


def test_policy_requires_positive_timeout():
    with pytest.raises(ValueError):
        BaselineResolutionPolicy(timeout_seconds=0)
