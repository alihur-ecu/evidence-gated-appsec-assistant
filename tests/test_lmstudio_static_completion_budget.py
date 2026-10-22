"""Local-model static output is independent of the dynamic budget."""
from types import SimpleNamespace

from app.analysis.proposers.lmstudio import LMStudioStaticProposer


class FakeChat:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(choices=[SimpleNamespace(
            message=SimpleNamespace(content='{"findings": []}'),
            finish_reason="stop"
        )])


def test_static_uses_larger_output_budget_without_changing_dynamic(monkeypatch):
    monkeypatch.delenv("LMSTUDIO_STATIC_MAX_TOKENS", raising=False)
    monkeypatch.delenv("LMSTUDIO_MAX_TOKENS", raising=False)
    model = LMStudioStaticProposer(max_retries=0)
    chat = FakeChat()
    model.client = SimpleNamespace(chat=SimpleNamespace(completions=chat))
    model._generate_with_retry("bounded source context")
    model._generate_context_with_retry("bounded runtime context")
    assert chat.calls[0]["max_tokens"] == 4096
    assert chat.calls[1]["max_tokens"] == 1024
    assert chat.calls[0]["temperature"] == 0.0


def test_static_output_budget_can_be_overridden(monkeypatch):
    monkeypatch.setenv("LMSTUDIO_STATIC_MAX_TOKENS", "2048")
    model = LMStudioStaticProposer(max_retries=0)
    chat = FakeChat()
    model.client = SimpleNamespace(chat=SimpleNamespace(completions=chat))
    model._generate_with_retry("bounded source context")
    assert chat.calls[0]["max_tokens"] == 2048


def test_truncated_model_response_does_not_masquerade_as_complete():
    import pytest
    model = LMStudioStaticProposer(max_retries=0)
    class Truncated:
        def create(self, **kwargs):
            return SimpleNamespace(choices=[SimpleNamespace(
                message=SimpleNamespace(content='{"findings": []}'), finish_reason="length"
            )])
    model.client = SimpleNamespace(chat=SimpleNamespace(completions=Truncated()))
    with pytest.raises(ValueError, match="truncated"):
        model._generate_with_retry("static prompt")
