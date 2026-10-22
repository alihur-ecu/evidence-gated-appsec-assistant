import pytest

from app.analysis.proposers.base import StaticProposer
from app.analysis.proposers.factory import (
    NoOpStaticProposer,
    create_static_proposer,
    get_configured_llm_provider,
)


def test_default_provider_is_none(
    monkeypatch,
):
    monkeypatch.delenv(
        "LLM_PROVIDER",
        raising=False,
    )

    assert (
        get_configured_llm_provider()
        == "none"
    )


def test_environment_provider_is_normalised(
    monkeypatch,
):
    monkeypatch.setenv(
        "LLM_PROVIDER",
        "  GeMiNi  ",
    )

    assert (
        get_configured_llm_provider()
        == "gemini"
    )


def test_none_provider_creates_noop_proposer():
    proposer = create_static_proposer(
        "none"
    )

    assert isinstance(
        proposer,
        NoOpStaticProposer,
    )

    assert isinstance(
        proposer,
        StaticProposer,
    )

    assert proposer.provider_name == "NONE"


def test_noop_proposer_returns_no_findings():
    proposer = NoOpStaticProposer()

    chunks = [
        {
            "chunk_id": "app/test.py:1-10",
            "source_file": "app/test.py",
            "source_code": (
                "print('hello')"
            ),
        }
    ]

    result = proposer.propose(
        application_name="Test Application",
        chunks=chunks,
    )

    assert result == []


def test_noop_proposer_does_not_mutate_chunks():
    proposer = NoOpStaticProposer()

    chunks = [
        {
            "chunk_id": "test.py:1-1",
            "source_file": "test.py",
            "source_code": "pass",
        }
    ]

    original = [
        dict(chunk)
        for chunk in chunks
    ]

    proposer.propose(
        application_name="Test",
        chunks=chunks,
    )

    assert chunks == original


def test_explicit_provider_overrides_environment(
    monkeypatch,
):
    monkeypatch.setenv(
        "LLM_PROVIDER",
        "gemini",
    )

    proposer = create_static_proposer(
        "none"
    )

    assert isinstance(
        proposer,
        NoOpStaticProposer,
    )


def test_unknown_provider_fails_explicitly():
    with pytest.raises(
        ValueError,
        match="Unsupported LLM_PROVIDER",
    ):
        create_static_proposer(
            "unknown-provider"
        )


def test_openai_provider_creates_openai_proposer(
    monkeypatch,
):
    monkeypatch.setenv(
        "OPENAI_API_KEY",
        "test-key",
    )

    proposer = create_static_proposer(
        "openai"
    )

    from app.analysis.proposers.openai import (
        OpenAIStaticProposer,
    )

    assert isinstance(
        proposer,
        OpenAIStaticProposer,
    )

    assert isinstance(
        proposer,
        StaticProposer,
    )

    assert (
        proposer.provider_name
        == "OPENAI"
    )


def test_azure_reserved_provider_fails_explicitly():
    with pytest.raises(
        NotImplementedError,
        match="Azure OpenAI",
    ):
        create_static_proposer(
            "azure_openai"
        )


def test_custom_reserved_provider_fails_explicitly():
    with pytest.raises(
        NotImplementedError,
        match="custom",
    ):
        create_static_proposer(
            "custom"
        )