import json
from types import SimpleNamespace

import pytest

from app.analysis.proposers.openai import (
    DEFAULT_MODEL,
    OpenAIStaticProposer,
)


def make_chunk():
    return {
        "chunk_id": "app/example.py:10-20",
        "source_file": "app/example.py",
        "language": "Python",
        "start_line": 10,
        "end_line": 20,
        "source_code": (
            "def example(user_input):\n"
            "    return user_input\n"
        ),
    }


class FakeResponses:
    def __init__(
        self,
        *,
        responses=None,
        exception=None,
    ):
        self.responses = list(
            responses or []
        )
        self.exception = exception
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)

        if self.exception is not None:
            raise self.exception

        if not self.responses:
            return SimpleNamespace(
                output_text=json.dumps(
                    {
                        "findings": [],
                    }
                )
            )

        return self.responses.pop(0)


class FakeClient:
    def __init__(
        self,
        *,
        responses=None,
        exception=None,
    ):
        self.responses = FakeResponses(
            responses=responses,
            exception=exception,
        )


class FakeAPIError(Exception):
    def __init__(
        self,
        status_code,
        message="API error",
    ):
        super().__init__(message)
        self.status_code = (
            status_code
        )


def test_default_model_with_injected_client(
    monkeypatch,
):
    monkeypatch.delenv(
        "OPENAI_MODEL",
        raising=False,
    )

    proposer = OpenAIStaticProposer(
        client=FakeClient()
    )

    assert proposer.model == DEFAULT_MODEL


def test_model_can_be_configured_from_environment(
    monkeypatch,
):
    monkeypatch.setenv(
        "OPENAI_MODEL",
        "custom-model",
    )

    proposer = OpenAIStaticProposer(
        client=FakeClient()
    )

    assert proposer.model == "custom-model"


def test_explicit_model_overrides_environment(
    monkeypatch,
):
    monkeypatch.setenv(
        "OPENAI_MODEL",
        "environment-model",
    )

    proposer = OpenAIStaticProposer(
        client=FakeClient(),
        model="explicit-model",
    )

    assert proposer.model == "explicit-model"


def test_missing_api_key_fails_without_injected_client(
    monkeypatch,
):
    monkeypatch.delenv(
        "OPENAI_API_KEY",
        raising=False,
    )

    with pytest.raises(
        ValueError,
        match="OPENAI_API_KEY",
    ):
        OpenAIStaticProposer()


def test_negative_retry_count_is_rejected():
    with pytest.raises(
        ValueError,
        match="max_retries",
    ):
        OpenAIStaticProposer(
            client=FakeClient(),
            max_retries=-1,
        )


def test_negative_retry_delay_is_rejected():
    with pytest.raises(
        ValueError,
        match="retry_delay_seconds",
    ):
        OpenAIStaticProposer(
            client=FakeClient(),
            retry_delay_seconds=-1,
        )


def test_empty_findings_returns_empty_list():
    response = SimpleNamespace(
        output_text=json.dumps(
            {
                "findings": [],
            }
        )
    )

    client = FakeClient(
        responses=[response]
    )

    proposer = OpenAIStaticProposer(
        client=client
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[make_chunk()],
    )

    assert result == []

    assert (
        proposer.last_execution_report[
            "chunks_attempted"
        ]
        == 1
    )

    assert (
        proposer.last_execution_report[
            "chunks_succeeded"
        ]
        == 1
    )

    assert (
        proposer.last_execution_report[
            "chunks_failed"
        ]
        == 0
    )


def test_valid_finding_is_normalised():
    response = SimpleNamespace(
        output_text=json.dumps(
            {
                "findings": [
                    {
                        "finding_type":
                            "SQL_INJECTION",
                        "proposed_cwe":
                            "CWE-89",
                        "suggested_severity":
                            "HIGH",
                        "explanation":
                            "User input reaches a query.",
                        "line_number":
                            11,
                        "endpoint":
                            "/search",
                        "parameter":
                            "q",
                        "method":
                            "post",
                        "confidence":
                            0.8,
                    }
                ]
            }
        )
    )

    proposer = OpenAIStaticProposer(
        client=FakeClient(
            responses=[response]
        )
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[make_chunk()],
    )

    assert len(result) == 1

    finding = result[0]

    assert (
        finding["finding_type"]
        == "SQL_INJECTION"
    )

    assert (
        finding["proposal_source"]
        == "OPENAI"
    )

    assert (
        finding["source_file"]
        == "app/example.py"
    )

    assert finding["line_number"] == 11
    assert finding["method"] == "POST"
    assert finding["confidence"] == 0.8


def test_out_of_range_line_number_is_removed():
    response = SimpleNamespace(
        output_text=json.dumps(
            {
                "findings": [
                    {
                        "finding_type": "XSS",
                        "proposed_cwe":
                            "CWE-79",
                        "suggested_severity":
                            "MEDIUM",
                        "explanation":
                            "Candidate XSS.",
                        "line_number":
                            999,
                        "endpoint":
                            None,
                        "parameter":
                            None,
                        "method":
                            None,
                        "confidence":
                            0.5,
                    }
                ]
            }
        )
    )

    proposer = OpenAIStaticProposer(
        client=FakeClient(
            responses=[response]
        )
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[make_chunk()],
    )

    assert result[0]["line_number"] is None


def test_invalid_json_returns_no_findings():
    proposer = OpenAIStaticProposer(
        client=FakeClient(
            responses=[
                SimpleNamespace(
                    output_text="not-json"
                )
            ]
        )
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[make_chunk()],
    )

    assert result == []


def test_invalid_chunks_are_skipped():
    proposer = OpenAIStaticProposer(
        client=FakeClient()
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[
            {},
            {
                "chunk_id": "1",
                "source_file": "a.py",
                "source_code": "",
            },
        ],
    )

    assert result == []

    assert (
        proposer.last_execution_report[
            "chunks_attempted"
        ]
        == 0
    )


def test_responses_api_receives_structured_schema():
    client = FakeClient()

    proposer = OpenAIStaticProposer(
        client=client,
        model="test-model",
    )

    proposer.propose(
        application_name="Test",
        chunks=[make_chunk()],
    )

    assert len(
        client.responses.calls
    ) == 1

    call = client.responses.calls[0]

    assert call["model"] == "test-model"

    assert (
        call["text"]["format"]["type"]
        == "json_schema"
    )

    assert (
        call["text"]["format"]["strict"]
        is True
    )

    assert (
        call["text"]["format"]["schema"]
        is not None
    )


def test_non_retryable_api_error_fails_fast():
    proposer = OpenAIStaticProposer(
        client=FakeClient(
            exception=FakeAPIError(
                401,
                "unauthorised",
            )
        ),
        max_retries=2,
        retry_delay_seconds=0,
    )

    with pytest.raises(
        FakeAPIError
    ):
        proposer.propose(
            application_name="Test",
            chunks=[make_chunk()],
        )


def test_retryable_error_is_recorded_after_retries():
    client = FakeClient(
        exception=FakeAPIError(
            503,
            "temporary outage",
        )
    )

    proposer = OpenAIStaticProposer(
        client=client,
        max_retries=2,
        retry_delay_seconds=0,
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[make_chunk()],
    )

    assert result == []

    assert len(
        client.responses.calls
    ) == 3

    report = (
        proposer.last_execution_report
    )

    assert report["chunks_attempted"] == 1
    assert report["chunks_succeeded"] == 0
    assert report["chunks_failed"] == 1

    assert (
        report["failed_chunks"][0][
            "status_code"
        ]
        == 503
    )


def test_retryable_status_codes_are_recognised():
    for status_code in (
        408,
        409,
        429,
        500,
        502,
        503,
        504,
    ):
        assert (
            OpenAIStaticProposer.
            _is_retryable_exception(
                FakeAPIError(
                    status_code
                )
            )
            is True
        )


def test_permanent_status_codes_are_not_retryable():
    for status_code in (
        400,
        401,
        403,
        404,
        422,
    ):
        assert (
            OpenAIStaticProposer.
            _is_retryable_exception(
                FakeAPIError(
                    status_code
                )
            )
            is False
        )
