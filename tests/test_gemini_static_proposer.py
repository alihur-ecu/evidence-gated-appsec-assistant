import json

import pytest

from app.analysis.proposers.gemini import (
    GeminiStaticProposer,
)


class FakeResponse:
    def __init__(
        self,
        *,
        parsed=None,
        text=None,
    ):
        self.parsed = parsed
        self.text = text


class FakeModels:
    def __init__(
        self,
        responses=None,
        exceptions=None,
    ):
        self.responses = list(
            responses or []
        )

        self.exceptions = list(
            exceptions or []
        )

        self.calls = []

    def generate_content(
        self,
        *,
        model,
        contents,
        config,
    ):
        self.calls.append(
            {
                "model": model,
                "contents": contents,
                "config": config,
            }
        )

        if self.exceptions:
            exception = self.exceptions.pop(0)

            if exception is not None:
                raise exception

        if not self.responses:
            return FakeResponse(
                parsed={
                    "findings": [],
                }
            )

        return self.responses.pop(0)


class FakeClient:
    def __init__(
        self,
        *,
        responses=None,
        exceptions=None,
    ):
        self.models = FakeModels(
            responses=responses,
            exceptions=exceptions,
        )


def make_chunk():
    return {
        "chunk_id": "app/users.py:100-120",
        "source_file": "app/users.py",
        "language": "Python",
        "start_line": 100,
        "end_line": 120,
        "char_count": 100,
        "source_code": (
            "def get_user(user_id):\n"
            "    query = \"SELECT * FROM users \" "
            "+ \"WHERE id = \" + user_id\n"
            "    return db.execute(query)\n"
        ),
    }


def make_candidate(
    **overrides,
):
    candidate = {
        "finding_type": "SQL_INJECTION",
        "proposed_cwe": "CWE-89",
        "suggested_severity": "HIGH",
        "explanation": (
            "User-controlled input appears to be "
            "concatenated into a SQL query."
        ),
        "line_number": 102,
        "endpoint": None,
        "parameter": "user_id",
        "method": None,
        "confidence": 0.85,
    }

    candidate.update(overrides)

    return candidate


def test_requires_api_key_without_injected_client(
    monkeypatch,
):
    monkeypatch.delenv(
        "GEMINI_API_KEY",
        raising=False,
    )

    with pytest.raises(
        ValueError,
        match="GEMINI_API_KEY",
    ):
        GeminiStaticProposer()


def test_injected_client_does_not_require_api_key(
    monkeypatch,
):
    monkeypatch.delenv(
        "GEMINI_API_KEY",
        raising=False,
    )

    proposer = GeminiStaticProposer(
        client=FakeClient(),
    )

    assert proposer.provider_name == "GEMINI"


def test_empty_chunks_return_no_proposals():
    client = FakeClient()

    proposer = GeminiStaticProposer(
        client=client,
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[],
    )

    assert result == []
    assert client.models.calls == []


def test_invalid_or_empty_chunks_are_skipped():
    client = FakeClient()

    proposer = GeminiStaticProposer(
        client=client,
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[
            {},
            {
                "chunk_id": "x",
                "source_file": "x.py",
                "source_code": "",
            },
        ],
    )

    assert result == []
    assert client.models.calls == []


def test_valid_candidate_is_normalised():
    response = FakeResponse(
        parsed={
            "findings": [
                make_candidate()
            ]
        }
    )

    client = FakeClient(
        responses=[response]
    )

    proposer = GeminiStaticProposer(
        client=client,
        model="test-model",
    )

    result = proposer.propose(
        application_name="Generic Application",
        chunks=[
            make_chunk()
        ],
    )

    assert len(result) == 1

    proposal = result[0]

    assert (
        proposal["finding_type"]
        == "SQL_INJECTION"
    )

    assert (
        proposal["scan_type"]
        == "STATIC"
    )

    assert (
        proposal["source_file"]
        == "app/users.py"
    )

    assert (
        proposal["line_number"]
        == 102
    )

    assert (
        proposal["proposed_cwe"]
        == "CWE-89"
    )

    assert (
        proposal["suggested_severity"]
        == "HIGH"
    )

    assert (
        proposal["confidence"]
        == 0.85
    )

    assert (
        proposal["proposal_source"]
        == "GEMINI"
    )

    assert (
        proposal["chunk_id"]
        == "app/users.py:100-120"
    )

    assert len(
        client.models.calls
    ) == 1

    assert (
        client.models.calls[0]["model"]
        == "test-model"
    )


def test_prompt_is_generic_and_contains_provenance():
    client = FakeClient(
        responses=[
            FakeResponse(
                parsed={
                    "findings": [],
                }
            )
        ]
    )

    proposer = GeminiStaticProposer(
        client=client,
    )

    proposer.propose(
        application_name="Customer Portal",
        chunks=[
            make_chunk()
        ],
    )

    prompt = (
        client.models.calls[0][
            "contents"
        ]
    )

    assert "Customer Portal" in prompt
    assert "app/users.py" in prompt
    assert "100" in prompt
    assert "120" in prompt

    assert "DVWA" not in prompt
    assert "Juice Shop" not in prompt


def test_line_number_outside_chunk_is_rejected():
    response = FakeResponse(
        parsed={
            "findings": [
                make_candidate(
                    line_number=9999
                )
            ]
        }
    )

    proposer = GeminiStaticProposer(
        client=FakeClient(
            responses=[response]
        )
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[
            make_chunk()
        ],
    )

    assert len(result) == 1

    assert (
        result[0]["line_number"]
        is None
    )


def test_invalid_confidence_is_removed():
    response = FakeResponse(
        parsed={
            "findings": [
                make_candidate(
                    confidence=7.5
                )
            ]
        }
    )

    proposer = GeminiStaticProposer(
        client=FakeClient(
            responses=[response]
        )
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[
            make_chunk()
        ],
    )

    assert (
        result[0]["confidence"]
        is None
    )


def test_invalid_severity_is_removed():
    response = FakeResponse(
        parsed={
            "findings": [
                make_candidate(
                    suggested_severity="EXTREME"
                )
            ]
        }
    )

    proposer = GeminiStaticProposer(
        client=FakeClient(
            responses=[response]
        )
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[
            make_chunk()
        ],
    )

    assert (
        result[0][
            "suggested_severity"
        ]
        is None
    )


def test_invalid_candidate_without_type_is_discarded():
    candidate = make_candidate()
    candidate["finding_type"] = ""

    response = FakeResponse(
        parsed={
            "findings": [
                candidate
            ]
        }
    )

    proposer = GeminiStaticProposer(
        client=FakeClient(
            responses=[response]
        )
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[
            make_chunk()
        ],
    )

    assert result == []


def test_json_text_fallback_is_supported():
    payload = {
        "findings": [
            make_candidate()
        ]
    }

    response = FakeResponse(
        parsed=None,
        text=json.dumps(payload),
    )

    proposer = GeminiStaticProposer(
        client=FakeClient(
            responses=[response]
        )
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[
            make_chunk()
        ],
    )

    assert len(result) == 1

    assert (
        result[0]["finding_type"]
        == "SQL_INJECTION"
    )


def test_invalid_json_returns_no_proposals():
    response = FakeResponse(
        parsed=None,
        text="not-json",
    )

    proposer = GeminiStaticProposer(
        client=FakeClient(
            responses=[response]
        )
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[
            make_chunk()
        ],
    )

    assert result == []


def test_multiple_chunks_are_analysed_independently():
    first_chunk = make_chunk()

    second_chunk = dict(
        make_chunk()
    )

    second_chunk[
        "chunk_id"
    ] = "app/admin.py:1-20"

    second_chunk[
        "source_file"
    ] = "app/admin.py"

    second_chunk[
        "start_line"
    ] = 1

    second_chunk[
        "end_line"
    ] = 20

    first_response = FakeResponse(
        parsed={
            "findings": [
                make_candidate()
            ]
        }
    )

    second_response = FakeResponse(
        parsed={
            "findings": []
        }
    )

    client = FakeClient(
        responses=[
            first_response,
            second_response,
        ]
    )

    proposer = GeminiStaticProposer(
        client=client,
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[
            first_chunk,
            second_chunk,
        ],
    )

    assert len(result) == 1

    assert len(
        client.models.calls
    ) == 2


def test_transient_failure_is_retried():
    success_response = FakeResponse(
        parsed={
            "findings": []
        }
    )

    client = FakeClient(
        responses=[
            success_response
        ],
        exceptions=[
            RuntimeError(
                "temporary failure"
            ),
            None,
        ],
    )

    proposer = GeminiStaticProposer(
        client=client,
        max_retries=1,
        retry_delay_seconds=0,
    )

    result = proposer.propose(
        application_name="Test",
        chunks=[
            make_chunk()
        ],
    )

    assert result == []

    assert len(
        client.models.calls
    ) == 2


class FakeAPIError(RuntimeError):
    def __init__(self, status_code, message):
        super().__init__(message)
        self.status_code = status_code


def test_retryable_503_is_retried_then_succeeds():
    client = FakeClient(
        responses=[FakeResponse(parsed={"findings": []})],
        exceptions=[FakeAPIError(503, "temporary outage"), None],
    )
    proposer = GeminiStaticProposer(
        client=client, max_retries=1, retry_delay_seconds=0,
    )
    assert proposer.propose(application_name="Test", chunks=[make_chunk()]) == []
    assert len(client.models.calls) == 2
    assert proposer.last_execution_report["chunks_succeeded"] == 1


def test_permanent_404_fails_fast_without_retry():
    client = FakeClient(exceptions=[FakeAPIError(404, "model not found")])
    proposer = GeminiStaticProposer(
        client=client, max_retries=3, retry_delay_seconds=0,
    )
    with pytest.raises(FakeAPIError, match="model not found"):
        proposer.propose(application_name="Test", chunks=[make_chunk()])
    assert len(client.models.calls) == 1


def test_permanent_401_fails_fast_without_retry():
    client = FakeClient(exceptions=[FakeAPIError(401, "invalid API key")])
    proposer = GeminiStaticProposer(
        client=client, max_retries=3, retry_delay_seconds=0,
    )
    with pytest.raises(FakeAPIError, match="invalid API key"):
        proposer.propose(application_name="Test", chunks=[make_chunk()])
    assert len(client.models.calls) == 1


def test_exhausted_transient_failure_is_recorded_and_chunk_is_skipped():
    client = FakeClient(exceptions=[
        FakeAPIError(503, "failure 1"),
        FakeAPIError(503, "failure 2"),
    ])
    proposer = GeminiStaticProposer(
        client=client, max_retries=1, retry_delay_seconds=0,
    )
    assert proposer.propose(application_name="Test", chunks=[make_chunk()]) == []
    report = proposer.last_execution_report
    assert len(client.models.calls) == 2
    assert report["chunks_attempted"] == 1
    assert report["chunks_succeeded"] == 0
    assert report["chunks_failed"] == 1
    assert report["failed_chunks"][0]["status_code"] == 503
    assert report["failed_chunks"][0]["chunk_id"] == "app/users.py:100-120"


def test_transient_failure_in_one_chunk_does_not_discard_later_chunk():
    first_chunk = make_chunk()
    second_chunk = dict(make_chunk())
    second_chunk["chunk_id"] = "app/admin.py:100-120"
    second_chunk["source_file"] = "app/admin.py"

    client = FakeClient(
        responses=[FakeResponse(parsed={"findings": [make_candidate()]})],
        exceptions=[FakeAPIError(503, "temporary outage"), None],
    )
    proposer = GeminiStaticProposer(
        client=client, max_retries=0, retry_delay_seconds=0,
    )
    result = proposer.propose(
        application_name="Test", chunks=[first_chunk, second_chunk],
    )
    assert len(result) == 1
    assert result[0]["source_file"] == "app/admin.py"
    report = proposer.last_execution_report
    assert report["chunks_attempted"] == 2
    assert report["chunks_succeeded"] == 1
    assert report["chunks_failed"] == 1


def test_negative_retry_configuration_is_rejected():
    with pytest.raises(
        ValueError,
        match="max_retries",
    ):
        GeminiStaticProposer(
            client=FakeClient(),
            max_retries=-1,
        )

    with pytest.raises(
        ValueError,
        match="retry_delay_seconds",
    ):
        GeminiStaticProposer(
            client=FakeClient(),
            retry_delay_seconds=-1,
        )