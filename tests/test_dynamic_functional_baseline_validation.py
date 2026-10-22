from dataclasses import dataclass

import requests

from app.dynamic_analysis.planning.baseline_resolver import (
    BaselineResolutionPolicy,
    BaselineResolver,
)
from app.dynamic_analysis.planning.models import ProbeCandidate


class FakeResponse:
    def __init__(self, body: bytes, status_code: int = 200):
        self.content = body
        self.status_code = status_code


class FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def _response(self, kwargs):
        params = kwargs.get("params") or kwargs.get("data") or {}
        value = params["q"]
        self.calls.append(dict(params))
        return self.responses[value]

    def get(self, url, **kwargs):
        return self._response(kwargs)

    def post(self, url, **kwargs):
        return self._response(kwargs)


def candidate(observed_value):
    return ProbeCandidate(
        endpoint="https://example.test/search",
        method="GET",
        parameter="q",
        parameter_location="query",
        input_type="text",
        source="FORM",
        observed_value=observed_value,
        fixed_parameters={"action": "Search"},
    )


def test_non_empty_stable_observed_value_remains_preferred():
    session = FakeSession({"known": FakeResponse(b"functional")})
    result = BaselineResolver().resolve(candidate("known"), session=session)
    assert result.value == "known"
    assert result.source == "OBSERVED"
    assert result.repeatable is True
    assert session.calls == [
        {"action": "Search", "q": "known"},
        {"action": "Search", "q": "known"},
    ]


def test_empty_observed_value_allows_stable_synthetic_baseline():
    session = FakeSession({
        "": FakeResponse(b"unprocessed-form"),
        "1": FakeResponse(b"functional-result"),
        "test": FakeResponse(b"other"),
        "0": FakeResponse(b"other-zero"),
    })
    result = BaselineResolver().resolve(candidate(""), session=session)
    assert result.value == "1"
    assert result.source == "SYNTHETIC"
    assert result.repeatable is True
    assert {"action": "Search", "q": ""} in session.calls
    assert {"action": "Search", "q": "1"} in session.calls


def test_empty_observed_value_is_preserved_as_fallback_when_synthetic_fails():
    session = FakeSession({
        "": FakeResponse(b"empty-ok"),
        "1": FakeResponse(b"bad", 500),
        "test": FakeResponse(b"bad", 500),
        "0": FakeResponse(b"bad", 500),
    })
    result = BaselineResolver().resolve(candidate(""), session=session)
    assert result.value == ""
    assert result.source == "OBSERVED"


def test_fixed_context_is_preserved_during_synthetic_resolution():
    session = FakeSession({
        "": FakeResponse(b"empty"),
        "1": FakeResponse(b"functional"),
        "test": FakeResponse(b"x"),
        "0": FakeResponse(b"y"),
    })
    result = BaselineResolver().resolve(candidate(""), session=session)
    assert result.value == "1"
    assert all(call["action"] == "Search" for call in session.calls)
