"""
LM Studio provider for the static vulnerability proposer.

LM Studio runs a local model behind an OpenAI-compatible server, so this
class reuses almost all of OpenAIStaticProposer's logic (chunk validation,
retries, normalising proposals into findings, etc).

The one thing local models can't reliably be trusted with is OpenAI's
"strict JSON schema" structured-output feature - real OpenAI models obey
it, but a local model like Gemma running in LM Studio will happily ignore
it and answer in plain English instead. So this subclass overrides the
two methods responsible for asking for JSON and reading the answer back,
using a plainer, more compatible approach:

1. The prompt itself spells out the exact JSON shape to reply with.
2. The request goes to /v1/chat/completions (the most widely supported
   endpoint across local model servers) instead of /v1/responses.
3. The reply is parsed leniently, in case the model wraps its JSON in
   markdown code fences or adds a stray sentence around it.

It also relabels proposal_source as LMSTUDIO instead of the inherited
OPENAI label, since these findings come from a local model, not OpenAI.
"""

import json
import os
import re
import time
from typing import Any

from openai import OpenAI

from app.analysis.proposers.openai import (
    OpenAIStaticProposer,
    SYSTEM_INSTRUCTION,
)

DEFAULT_LMSTUDIO_MODEL = "google/gemma-4-e4b"
DEFAULT_LMSTUDIO_BASE_URL = "http://localhost:1234/v1"
DEFAULT_LMSTUDIO_API_KEY = "lm-studio"


class LMStudioStaticProposer(OpenAIStaticProposer):
    provider_name = "LMSTUDIO"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        max_retries: int = 2,
        retry_delay_seconds: float = 1.0,
    ) -> None:
        resolved_base_url = (
            base_url
            or os.getenv("LMSTUDIO_BASE_URL")
            or DEFAULT_LMSTUDIO_BASE_URL
        )

        resolved_api_key = (
            api_key
            or os.getenv("LMSTUDIO_API_KEY")
            or DEFAULT_LMSTUDIO_API_KEY
        )

        resolved_model = (
            model
            or os.getenv("LMSTUDIO_MODEL")
            or DEFAULT_LMSTUDIO_MODEL
        )

        client = OpenAI(
            api_key=resolved_api_key,
            base_url=resolved_base_url,
        )

        super().__init__(
            client=client,
            model=resolved_model,
            max_retries=max_retries,
            retry_delay_seconds=retry_delay_seconds,
        )

    def propose(
        self,
        *,
        application_name: str,
        chunks: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Same as the parent's propose(), but relabels proposal_source
        as LMSTUDIO instead of the inherited OPENAI label.
        """
        proposals = super().propose(
            application_name=application_name,
            chunks=chunks,
        )

        for proposal in proposals:
            if "proposal_source" in proposal:
                proposal["proposal_source"] = "LMSTUDIO"

        return proposals

    def _generate_with_retry(self, prompt: str) -> Any:
        json_instructions = (
            "\n\nRespond with ONLY a single JSON object and nothing "
            "else - no explanation, no markdown code fences, no text "
            "before or after it. The JSON object must have exactly "
            "this shape:\n"
            "{\n"
            '  "findings": [\n'
            "    {\n"
            '      "finding_type": string,\n'
            '      "proposed_cwe": string or null,\n'
            '      "suggested_severity": one of "LOW", "MEDIUM", '
            '"HIGH", "CRITICAL", or null,\n'
            '      "explanation": string,\n'
            '      "line_number": integer or null,\n'
            '      "endpoint": string or null,\n'
            '      "parameter": string or null,\n'
            '      "method": string or null,\n'
            '      "confidence": number between 0.0 and 1.0, or null\n'
            "    }\n"
            "  ]\n"
            "}\n"
            "If there are no findings, return exactly: "
            '{"findings": []}'
        )

        full_prompt = prompt + json_instructions

        attempt = 0
        while True:
            try:
                return self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": SYSTEM_INSTRUCTION,
                        },
                        {
                            "role": "user",
                            "content": full_prompt,
                        },
                    ],
                    temperature=0.2,
                )
            except Exception as exc:
                if not self._is_retryable_exception(exc):
                    raise

                if attempt >= self.max_retries:
                    raise

                attempt += 1

                if self.retry_delay_seconds > 0:
                    time.sleep(self.retry_delay_seconds)

    @staticmethod
    def _extract_payload(response: Any) -> dict[str, Any]:
        try:
            text = response.choices[0].message.content
        except (AttributeError, IndexError, TypeError):
            return {"findings": []}

        if not isinstance(text, str) or not text.strip():
            return {"findings": []}

        try:
            payload = json.loads(text)
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            pass

        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            try:
                payload = json.loads(match.group(0))
                if isinstance(payload, dict):
                    return payload
            except json.JSONDecodeError:
                pass

        return {"findings": []}