import pytest

from app.analysis.proposers.adapters import (
    adapt_dynamic_context,
    adapt_dynamic_contexts,
    adapt_static_context,
    adapt_static_contexts,
)
from app.dynamic_analysis.context_builder import DynamicContext
from app.static_analysis.context_builder import ContextChunk


def make_static_chunk() -> ContextChunk:
    return ContextChunk(
        chunk_id="app/example.py:10-20",
        source_file="app/example.py",
        language="python",
        start_line=10,
        end_line=20,
        source_code="value = request.args.get('value')\n",
        char_count=34,
    )


def make_dynamic_context() -> DynamicContext:
    text = (
        "DYNAMIC APPLICATION OBSERVATION\n"
        "Endpoint URL: https://example.test/search\n"
        "HTTP method: GET"
    )

    return DynamicContext(
        context_id="dynamic-endpoint-0001",
        context_type="ENDPOINT",
        source_url="https://example.test/search",
        endpoint_url="https://example.test/search",
        method="GET",
        parameters=(
            {
                "name": "q",
                "location": "query",
                "input_type": None,
            },
        ),
        observed_from="DISCOVERY",
        context_text=text,
        char_count=len(text),
    )


def test_adapt_static_context():
    result = adapt_static_context(
        make_static_chunk()
    )

    assert result.context_id == "app/example.py:10-20"
    assert result.scan_type == "STATIC"
    assert result.content == (
        "value = request.args.get('value')\n"
    )

    assert result.metadata == {
        "source_file": "app/example.py",
        "language": "python",
        "start_line": 10,
        "end_line": 20,
    }


def test_adapt_dynamic_context():
    source = make_dynamic_context()

    result = adapt_dynamic_context(source)

    assert result.context_id == "dynamic-endpoint-0001"
    assert result.scan_type == "DYNAMIC"
    assert result.content == source.context_text

    assert result.metadata == {
        "context_type": "ENDPOINT",
        "source_url": "https://example.test/search",
        "endpoint_url": "https://example.test/search",
        "method": "GET",
        "parameters": [
            {
                "name": "q",
                "location": "query",
                "input_type": None,
            },
        ],
        "observed_from": "DISCOVERY",
    }


def test_static_adapter_preserves_actual_content_size():
    source = make_static_chunk()

    result = adapt_static_context(source)

    assert result.char_count == len(
        source.source_code
    )


def test_dynamic_adapter_preserves_actual_content_size():
    source = make_dynamic_context()

    result = adapt_dynamic_context(source)

    assert result.char_count == len(
        source.context_text
    )


def test_dynamic_parameter_metadata_is_copied():
    source = make_dynamic_context()

    result = adapt_dynamic_context(source)

    assert (
        result.metadata["parameters"]
        is not source.parameters
    )


def test_adapt_static_contexts_preserves_order():
    first = make_static_chunk()

    second = ContextChunk(
        chunk_id="app/second.py:1-2",
        source_file="app/second.py",
        language="python",
        start_line=1,
        end_line=2,
        source_code="print('second')",
        char_count=15,
    )

    results = adapt_static_contexts(
        [first, second]
    )

    assert [
        item.context_id
        for item in results
    ] == [
        "app/example.py:10-20",
        "app/second.py:1-2",
    ]


def test_adapt_dynamic_contexts_preserves_order():
    first = make_dynamic_context()

    second = DynamicContext(
        context_id="dynamic-endpoint-0002",
        context_type="ENDPOINT",
        source_url="https://example.test/about",
        endpoint_url="https://example.test/about",
        method="GET",
        parameters=(),
        observed_from="DISCOVERY",
        context_text="GET /about",
        char_count=10,
    )

    results = adapt_dynamic_contexts(
        [first, second]
    )

    assert [
        item.context_id
        for item in results
    ] == [
        "dynamic-endpoint-0001",
        "dynamic-endpoint-0002",
    ]


def test_static_adapter_rejects_wrong_type():
    with pytest.raises(
        TypeError,
        match="ContextChunk",
    ):
        adapt_static_context({})


def test_dynamic_adapter_rejects_wrong_type():
    with pytest.raises(
        TypeError,
        match="DynamicContext",
    ):
        adapt_dynamic_context({})


def test_static_collection_rejects_non_list():
    with pytest.raises(
        TypeError,
        match="list",
    ):
        adapt_static_contexts(())


def test_dynamic_collection_rejects_non_list():
    with pytest.raises(
        TypeError,
        match="list",
    ):
        adapt_dynamic_contexts(())


def test_adapters_do_not_add_vulnerability_conclusions():
    static_result = adapt_static_context(
        make_static_chunk()
    )

    dynamic_result = adapt_dynamic_context(
        make_dynamic_context()
    )

    for result in (
        static_result,
        dynamic_result,
    ):
        payload = result.to_dict()

        assert "cwe" not in payload
        assert "severity" not in payload
        assert "finding_type" not in payload
        assert "verified" not in payload

        assert "cwe" not in result.metadata
        assert "severity" not in result.metadata
        assert "finding_type" not in result.metadata
        assert "verified" not in result.metadata