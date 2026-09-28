import pytest

from app.analysis.proposers.budget import (
    DEFAULT_MAX_CHUNKS,
    DEFAULT_MAX_SOURCE_CHARS,
    LLMExecutionBudget,
)


def make_chunk(
    chunk_id: str,
    source_code: str,
) -> dict:
    return {
        "chunk_id": chunk_id,
        "source_file": "app/example.py",
        "language": "Python",
        "start_line": 1,
        "end_line": 1,
        "char_count": len(source_code),
        "source_code": source_code,
    }


def test_default_budget_values(
    monkeypatch,
):
    monkeypatch.delenv(
        "LLM_MAX_CHUNKS",
        raising=False,
    )

    monkeypatch.delenv(
        "LLM_MAX_SOURCE_CHARS",
        raising=False,
    )

    budget = LLMExecutionBudget()

    assert (
        budget.max_chunks
        == DEFAULT_MAX_CHUNKS
    )

    assert (
        budget.max_source_chars
        == DEFAULT_MAX_SOURCE_CHARS
    )


def test_all_chunks_selected_when_within_budget():
    chunks = [
        make_chunk("1", "abc"),
        make_chunk("2", "defg"),
    ]

    result = LLMExecutionBudget(
        max_chunks=10,
        max_source_chars=100,
    ).apply(chunks)

    assert result.selected_chunks == chunks
    assert result.skipped_chunks == []

    assert result.chunks_received == 2
    assert result.chunks_selected == 2
    assert result.chunks_skipped == 0

    assert result.source_chars_received == 7
    assert result.source_chars_selected == 7

    assert result.truncated is False
    assert result.truncation_reason is None


def test_chunk_limit_is_enforced():
    chunks = [
        make_chunk("1", "aaa"),
        make_chunk("2", "bbb"),
        make_chunk("3", "ccc"),
    ]

    result = LLMExecutionBudget(
        max_chunks=2,
        max_source_chars=100,
    ).apply(chunks)

    assert result.selected_chunks == chunks[:2]
    assert result.skipped_chunks == chunks[2:]

    assert result.chunks_selected == 2
    assert result.chunks_skipped == 1

    assert result.source_chars_selected == 6

    assert result.truncated is True

    assert (
        "Maximum chunk budget reached"
        in result.truncation_reason
    )


def test_character_limit_is_enforced():
    chunks = [
        make_chunk("1", "aaaa"),
        make_chunk("2", "bbbb"),
        make_chunk("3", "cccc"),
    ]

    result = LLMExecutionBudget(
        max_chunks=10,
        max_source_chars=8,
    ).apply(chunks)

    assert result.selected_chunks == chunks[:2]
    assert result.skipped_chunks == chunks[2:]

    assert result.source_chars_received == 12
    assert result.source_chars_selected == 8

    assert result.chunks_selected == 2
    assert result.chunks_skipped == 1

    assert result.truncated is True

    assert (
        "Maximum source-character budget reached"
        in result.truncation_reason
    )


def test_single_oversized_chunk_is_not_partially_modified():
    chunks = [
        make_chunk(
            "large",
            "abcdefghij",
        )
    ]

    result = LLMExecutionBudget(
        max_chunks=10,
        max_source_chars=5,
    ).apply(chunks)

    assert result.selected_chunks == []
    assert result.skipped_chunks == chunks

    assert result.chunks_selected == 0
    assert result.chunks_skipped == 1

    assert result.source_chars_selected == 0
    assert result.source_chars_received == 10

    assert result.truncated is True


def test_exact_character_budget_is_allowed():
    chunks = [
        make_chunk("1", "abc"),
        make_chunk("2", "de"),
    ]

    result = LLMExecutionBudget(
        max_chunks=10,
        max_source_chars=5,
    ).apply(chunks)

    assert result.selected_chunks == chunks
    assert result.source_chars_selected == 5
    assert result.truncated is False


def test_actual_source_length_is_used_not_metadata():
    chunk = make_chunk(
        "1",
        "abcdefghij",
    )

    chunk["char_count"] = 1

    result = LLMExecutionBudget(
        max_chunks=10,
        max_source_chars=5,
    ).apply([chunk])

    assert result.selected_chunks == []
    assert result.source_chars_received == 10


def test_environment_configuration_is_supported(
    monkeypatch,
):
    monkeypatch.setenv(
        "LLM_MAX_CHUNKS",
        "7",
    )

    monkeypatch.setenv(
        "LLM_MAX_SOURCE_CHARS",
        "12345",
    )

    budget = LLMExecutionBudget()

    assert budget.max_chunks == 7
    assert budget.max_source_chars == 12345


def test_explicit_configuration_overrides_environment(
    monkeypatch,
):
    monkeypatch.setenv(
        "LLM_MAX_CHUNKS",
        "100",
    )

    monkeypatch.setenv(
        "LLM_MAX_SOURCE_CHARS",
        "999999",
    )

    budget = LLMExecutionBudget(
        max_chunks=3,
        max_source_chars=500,
    )

    assert budget.max_chunks == 3
    assert budget.max_source_chars == 500


@pytest.mark.parametrize(
    "environment_name,value",
    [
        ("LLM_MAX_CHUNKS", "0"),
        ("LLM_MAX_CHUNKS", "-1"),
        ("LLM_MAX_CHUNKS", "abc"),
        ("LLM_MAX_SOURCE_CHARS", "0"),
        ("LLM_MAX_SOURCE_CHARS", "-50"),
        ("LLM_MAX_SOURCE_CHARS", "abc"),
    ],
)
def test_invalid_environment_configuration_is_rejected(
    monkeypatch,
    environment_name,
    value,
):
    monkeypatch.setenv(
        environment_name,
        value,
    )

    other_environment_name = (
        "LLM_MAX_SOURCE_CHARS"
        if environment_name == "LLM_MAX_CHUNKS"
        else "LLM_MAX_CHUNKS"
    )

    monkeypatch.delenv(
        other_environment_name,
        raising=False,
    )

    with pytest.raises(
        ValueError,
        match=environment_name,
    ):
        LLMExecutionBudget()


@pytest.mark.parametrize(
    "max_chunks",
    [
        0,
        -1,
        True,
    ],
)
def test_invalid_explicit_chunk_limit_is_rejected(
    max_chunks,
):
    with pytest.raises(ValueError):
        LLMExecutionBudget(
            max_chunks=max_chunks,
        )


@pytest.mark.parametrize(
    "max_source_chars",
    [
        0,
        -1,
        True,
    ],
)
def test_invalid_explicit_character_limit_is_rejected(
    max_source_chars,
):
    with pytest.raises(ValueError):
        LLMExecutionBudget(
            max_source_chars=max_source_chars,
        )


def test_input_chunks_are_not_mutated():
    chunks = [
        make_chunk("1", "abc"),
        make_chunk("2", "def"),
    ]

    original = [
        dict(chunk)
        for chunk in chunks
    ]

    LLMExecutionBudget(
        max_chunks=1,
        max_source_chars=100,
    ).apply(chunks)

    assert chunks == original


def test_summary_is_json_friendly():
    chunks = [
        make_chunk("1", "abc"),
        make_chunk("2", "def"),
    ]

    result = LLMExecutionBudget(
        max_chunks=1,
        max_source_chars=100,
    ).apply(chunks)

    summary = result.to_dict()

    assert summary == {
        "chunks_received": 2,
        "chunks_selected": 1,
        "chunks_skipped": 1,
        "source_chars_received": 6,
        "source_chars_selected": 3,
        "truncated": True,
        "truncation_reason": (
            "Maximum chunk budget reached (1)."
        ),
    }


def test_non_list_input_is_rejected():
    budget = LLMExecutionBudget()

    with pytest.raises(
        TypeError,
        match="chunks must be a list",
    ):
        budget.apply(
            tuple()
        )