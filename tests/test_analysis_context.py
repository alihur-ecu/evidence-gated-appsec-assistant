import pytest

from app.analysis.proposers.context import (
    AnalysisContext,
)


def test_creates_generic_static_context():
    context = AnalysisContext(
        context_id="app.py:1-20",
        scan_type="STATIC",
        content="print('hello')",
        metadata={
            "source_file": "app.py",
            "start_line": 1,
            "end_line": 20,
        },
    )

    assert context.context_id == "app.py:1-20"
    assert context.scan_type == "STATIC"
    assert context.content == "print('hello')"


def test_creates_generic_dynamic_context():
    context = AnalysisContext(
        context_id="dynamic-form-0001",
        scan_type="DYNAMIC",
        content="POST /login",
        metadata={
            "endpoint_url":
                "https://example.test/login",
            "method": "POST",
        },
    )

    assert context.scan_type == "DYNAMIC"

    assert (
        context.metadata["method"]
        == "POST"
    )


def test_scan_type_is_normalised():
    context = AnalysisContext(
        context_id="example",
        scan_type=" dynamic ",
        content="observation",
    )

    assert context.scan_type == "DYNAMIC"


def test_context_id_is_trimmed():
    context = AnalysisContext(
        context_id="  example-context  ",
        scan_type="STATIC",
        content="source",
    )

    assert (
        context.context_id
        == "example-context"
    )


def test_scan_type_is_not_hardcoded():
    context = AnalysisContext(
        context_id="future-context",
        scan_type="container",
        content="future observation",
    )

    assert context.scan_type == "CONTAINER"


def test_empty_context_id_is_rejected():
    with pytest.raises(
        ValueError,
        match="context_id",
    ):
        AnalysisContext(
            context_id="   ",
            scan_type="STATIC",
            content="source",
        )


def test_empty_scan_type_is_rejected():
    with pytest.raises(
        ValueError,
        match="scan_type",
    ):
        AnalysisContext(
            context_id="example",
            scan_type="   ",
            content="source",
        )


def test_content_must_be_string():
    with pytest.raises(
        TypeError,
        match="content",
    ):
        AnalysisContext(
            context_id="example",
            scan_type="STATIC",
            content=123,
        )


def test_metadata_must_be_dictionary():
    with pytest.raises(
        TypeError,
        match="metadata",
    ):
        AnalysisContext(
            context_id="example",
            scan_type="STATIC",
            content="source",
            metadata=[],
        )


def test_metadata_is_defensively_copied():
    metadata = {
        "endpoint": "/login"
    }

    context = AnalysisContext(
        context_id="example",
        scan_type="DYNAMIC",
        content="observation",
        metadata=metadata,
    )

    metadata["endpoint"] = "/changed"

    assert (
        context.metadata["endpoint"]
        == "/login"
    )


def test_char_count_uses_actual_content():
    context = AnalysisContext(
        context_id="example",
        scan_type="STATIC",
        content="abcdef",
    )

    assert context.char_count == 6


def test_to_dict_preserves_generic_contract():
    context = AnalysisContext(
        context_id="dynamic-1",
        scan_type="DYNAMIC",
        content="GET /search?q=test",
        metadata={
            "method": "GET",
            "parameter": "q",
        },
    )

    payload = context.to_dict()

    assert payload == {
        "context_id": "dynamic-1",
        "scan_type": "DYNAMIC",
        "content": "GET /search?q=test",
        "metadata": {
            "method": "GET",
            "parameter": "q",
        },
    }


def test_context_has_no_vulnerability_specific_fields():
    context = AnalysisContext(
        context_id="generic",
        scan_type="DYNAMIC",
        content="observation",
    )

    payload = context.to_dict()

    assert "cwe" not in payload
    assert "severity" not in payload
    assert "vulnerability_type" not in payload
    assert "sql_injection" not in payload