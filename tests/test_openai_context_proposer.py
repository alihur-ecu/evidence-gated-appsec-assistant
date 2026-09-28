import json

from app.analysis.proposers.context import AnalysisContext
from app.analysis.proposers.openai import OpenAIStaticProposer


class FakeResponse:
    def __init__(self, payload):
        self.output_text = json.dumps(payload)


class FakeResponsesAPI:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return FakeResponse(self.payload)


class FakeClient:
    def __init__(self, payload):
        self.responses = FakeResponsesAPI(payload)


def make_dynamic_context():
    return AnalysisContext(
        context_id="dynamic-form-0001",
        scan_type="DYNAMIC",
        content=(
            "DYNAMIC APPLICATION OBSERVATION\n"
            "Context type: FORM\n"
            "Source URL: https://example.test/login\n"
            "Endpoint URL: https://example.test/login\n"
            "HTTP method: POST\n"
            "Parameters:\n"
            "- username | location=body | type=text\n"
            "- password | location=body | type=password\n"
        ),
        metadata={
            "context_type": "FORM",
            "source_url": "https://example.test/login",
            "endpoint_url": "https://example.test/login",
            "method": "POST",
            "parameters": [
                {
                    "name": "username",
                    "location": "body",
                    "input_type": "text",
                },
                {
                    "name": "password",
                    "location": "body",
                    "input_type": "password",
                },
            ],
            "observed_from": "DISCOVERY",
        },
    )


def make_static_context():
    return AnalysisContext(
        context_id="app/example.py:10-20",
        scan_type="STATIC",
        content=(
            "value = request.args.get('id')\n"
            "query = 'SELECT * FROM users WHERE id=' + value\n"
        ),
        metadata={
            "source_file": "app/example.py",
            "language": "python",
            "start_line": 10,
            "end_line": 20,
        },
    )


def make_proposer(payload):
    return OpenAIStaticProposer(
        client=FakeClient(payload),
        model="test-model",
        max_retries=0,
        retry_delay_seconds=0,
    )


def test_dynamic_context_produces_dynamic_proposal():
    proposer = make_proposer(
        {
            "findings": [
                {
                    "finding_type": "Potential SQL injection",
                    "explanation": (
                        "The observed login form exposes user-controlled "
                        "parameters that may reach a server-side query."
                    ),
                    "line_number": None,
                    "endpoint": None,
                    "parameter": "username",
                    "method": None,
                    "proposed_cwe": "CWE-89",
                    "suggested_severity": "HIGH",
                    "confidence": 0.75,
                }
            ]
        }
    )

    results = proposer.propose_contexts(
        application_name="Example Application",
        contexts=[make_dynamic_context()],
    )

    assert len(results) == 1

    finding = results[0]

    assert finding["scan_type"] == "DYNAMIC"
    assert finding["proposal_source"] == "OPENAI"
    assert finding["context_id"] == "dynamic-form-0001"

    # Missing model values should fall back to trusted context metadata.
    assert finding["endpoint"] == "https://example.test/login"
    assert finding["method"] == "POST"

    assert finding["parameter"] == "username"
    assert finding["proposed_cwe"] == "CWE-89"
    assert finding["suggested_severity"] == "HIGH"

    # Dynamic contexts are not static chunks.
    assert "chunk_id" not in finding
    assert "chunk_start_line" not in finding
    assert "chunk_end_line" not in finding


def test_dynamic_context_does_not_become_verified():
    proposer = make_proposer(
        {
            "findings": [
                {
                    "finding_type": "Candidate vulnerability",
                    "explanation": "Candidate only.",
                    "line_number": None,
                    "endpoint": None,
                    "parameter": None,
                    "method": None,
                    "proposed_cwe": None,
                    "suggested_severity": "MEDIUM",
                    "confidence": 0.5,
                }
            ]
        }
    )

    results = proposer.propose_contexts(
        application_name="Example Application",
        contexts=[make_dynamic_context()],
    )

    finding = results[0]

    assert "verified" not in finding
    assert "verification_status" not in finding
    assert "oracle_result" not in finding
    assert "human_decision" not in finding


def test_static_generic_context_preserves_static_provenance():
    proposer = make_proposer(
        {
            "findings": [
                {
                    "finding_type": "SQL injection",
                    "explanation": "User input is concatenated into SQL.",
                    "line_number": 11,
                    "endpoint": None,
                    "parameter": "id",
                    "method": None,
                    "proposed_cwe": "CWE-89",
                    "suggested_severity": "HIGH",
                    "confidence": 0.95,
                }
            ]
        }
    )

    results = proposer.propose_contexts(
        application_name="Example Application",
        contexts=[make_static_context()],
    )

    finding = results[0]

    assert finding["scan_type"] == "STATIC"
    assert finding["source_file"] == "app/example.py"
    assert finding["line_number"] == 11

    assert finding["chunk_id"] == "app/example.py:10-20"
    assert finding["chunk_start_line"] == 10
    assert finding["chunk_end_line"] == 20


def test_empty_context_is_not_sent_to_provider():
    proposer = make_proposer(
        {
            "findings": []
        }
    )

    context = AnalysisContext(
        context_id="dynamic-empty-0001",
        scan_type="DYNAMIC",
        content="   ",
        metadata={},
    )

    results = proposer.propose_contexts(
        application_name="Example Application",
        contexts=[context],
    )

    assert results == []
    assert (
        proposer.last_execution_report["chunks_attempted"]
        == 0
    )

    assert len(proposer.client.responses.calls) == 0


def test_invalid_context_object_is_skipped():
    proposer = make_proposer(
        {
            "findings": []
        }
    )

    results = proposer.propose_contexts(
        application_name="Example Application",
        contexts=[{"not": "an AnalysisContext"}],
    )

    assert results == []
    assert len(proposer.client.responses.calls) == 0


def test_no_findings_is_valid_result():
    proposer = make_proposer(
        {
            "findings": []
        }
    )

    results = proposer.propose_contexts(
        application_name="Example Application",
        contexts=[make_dynamic_context()],
    )

    assert results == []

    report = proposer.last_execution_report

    assert report["chunks_attempted"] == 1
    assert report["chunks_succeeded"] == 1
    assert report["chunks_failed"] == 0


def test_generic_prompt_contains_dynamic_provenance():
    proposer = make_proposer(
        {
            "findings": []
        }
    )

    proposer.propose_contexts(
        application_name="Example Application",
        contexts=[make_dynamic_context()],
    )

    assert len(proposer.client.responses.calls) == 1

    call = proposer.client.responses.calls[0]
    prompt = call["input"]

    assert "Example Application" in prompt
    assert "DYNAMIC" in prompt
    assert "dynamic-form-0001" in prompt
    assert "https://example.test/login" in prompt
    assert '"method": "POST"' in prompt


def test_generic_prompt_is_not_sql_injection_specific():
    proposer = make_proposer(
        {
            "findings": []
        }
    )

    proposer.propose_contexts(
        application_name="Example Application",
        contexts=[make_dynamic_context()],
    )

    call = proposer.client.responses.calls[0]

    instructions = call["instructions"]

    assert "SQL injection" not in instructions
    assert "CWE-89" not in instructions

    assert (
        "application-security vulnerability proposer"
        in instructions
    )


def test_multiple_contexts_are_processed_independently():
    proposer = make_proposer(
        {
            "findings": []
        }
    )

    first = make_dynamic_context()

    second = AnalysisContext(
        context_id="dynamic-endpoint-0002",
        scan_type="DYNAMIC",
        content=(
            "DYNAMIC APPLICATION OBSERVATION\n"
            "Endpoint URL: https://example.test/search\n"
            "HTTP method: GET\n"
            "Parameter: q\n"
        ),
        metadata={
            "context_type": "ENDPOINT",
            "source_url": "https://example.test/search",
            "endpoint_url": "https://example.test/search",
            "method": "GET",
            "parameters": [
                {
                    "name": "q",
                    "location": "query",
                    "input_type": None,
                }
            ],
            "observed_from": "DISCOVERY",
        },
    )

    results = proposer.propose_contexts(
        application_name="Example Application",
        contexts=[first, second],
    )

    assert results == []

    assert len(
        proposer.client.responses.calls
    ) == 2

    report = proposer.last_execution_report

    assert report["chunks_attempted"] == 2
    assert report["chunks_succeeded"] == 2
    assert report["chunks_failed"] == 0