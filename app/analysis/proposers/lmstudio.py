"""
LM Studio provider for the vulnerability proposer.

LM Studio runs a local model behind an OpenAI-compatible server. This
subclass reuses OpenAIStaticProposer's validation and normalisation logic,
but uses /v1/chat/completions for both static chunks and generic analysis
contexts because local models do not reliably support OpenAI strict
structured-output responses.

Architecture principle:

    AI proposes -> Evidence verifies -> Human decides

This component proposes candidates only. It does not verify them.
"""

import json
import os
import re
import time
from typing import Any

from openai import OpenAI

from app.analysis.proposers.context import AnalysisContext
from app.analysis.proposers.openai import (
    GENERIC_SYSTEM_INSTRUCTION,
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

    @staticmethod
    def _json_instructions() -> str:
        return (
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

    def propose(
        self,
        *,
        application_name: str,
        chunks: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Static path. Keep the parent's behaviour and relabel proposals
        so the source accurately reflects LM Studio.
        """
        proposals = super().propose(
            application_name=application_name,
            chunks=chunks,
        )

        for proposal in proposals:
            if "proposal_source" in proposal:
                proposal["proposal_source"] = "LMSTUDIO"

        return proposals

    def propose_contexts(
        self,
        *,
        application_name: str,
        contexts: list[AnalysisContext],
    ) -> list[dict[str, Any]]:
        """
        Generic/dynamic path with per-context observability.

        Each context is still analysed independently, exactly as in the
        parent implementation. Logging exposes what was attempted, how
        long it took, and how many candidates survived parsing and
        normalisation. No vulnerability family or target is hardcoded.
        """
        proposals: list[dict[str, Any]] = []
        self.last_execution_report = self._empty_execution_report()

        valid_contexts = [
            context
            for context in contexts
            if isinstance(context, AnalysisContext)
            and context.content.strip()
        ]

        total = len(valid_contexts)

        print(
            "\n"
            "================ LM STUDIO PROPOSAL STAGE ================\n"
            f"Model: {self.model}\n"
            f"Application: {application_name}\n"
            f"Contexts selected for LLM: {total}\n"
            "==========================================================",
            flush=True,
        )

        stage_started = time.perf_counter()

        for index, context in enumerate(valid_contexts, start=1):
            self.last_execution_report["chunks_attempted"] += 1

            metadata = (
                context.metadata
                if isinstance(context.metadata, dict)
                else {}
            )

            endpoint = (
                metadata.get("endpoint_url")
                or metadata.get("url")
                or metadata.get("action")
                or "-"
            )
            method = metadata.get("method") or "-"
            parameter = (
                metadata.get("parameter")
                or metadata.get("parameter_name")
                or metadata.get("field_name")
                or "-"
            )

            print(
                "\n"
                f"[LMSTUDIO] Context {index}/{total} START\n"
                f"  context_id={context.context_id}\n"
                f"  scan_type={context.scan_type}\n"
                f"  endpoint={endpoint}\n"
                f"  method={method}\n"
                f"  parameter={parameter}\n"
                f"  content_chars={len(context.content)}",
                flush=True,
            )

            context_started = time.perf_counter()

            try:
                context_proposals = self._analyse_context(
                    application_name=application_name,
                    context=context,
                )

            except Exception as exc:
                elapsed = time.perf_counter() - context_started

                if not self._is_retryable_exception(exc):
                    print(
                        f"[LMSTUDIO] Context {index}/{total} FATAL "
                        f"after {elapsed:.2f}s: "
                        f"{type(exc).__name__}: {exc}",
                        flush=True,
                    )
                    raise

                self.last_execution_report["chunks_failed"] += 1

                status_code = self._extract_status_code(exc)
                self.last_execution_report["failed_chunks"].append(
                    {
                        "context_id": context.context_id,
                        "scan_type": context.scan_type,
                        "status_code": status_code,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    }
                )

                print(
                    f"[LMSTUDIO] Context {index}/{total} FAILED "
                    f"after {elapsed:.2f}s "
                    f"status={status_code} "
                    f"error={type(exc).__name__}: {exc}",
                    flush=True,
                )

                if status_code == 429:
                    print(
                        "[LMSTUDIO] Stopping remaining contexts because "
                        "the provider returned HTTP 429.",
                        flush=True,
                    )
                    break

                continue

            elapsed = time.perf_counter() - context_started

            self.last_execution_report["chunks_succeeded"] += 1

            for proposal in context_proposals:
                if "proposal_source" in proposal:
                    proposal["proposal_source"] = "LMSTUDIO"

            proposals.extend(context_proposals)

            print(
                f"[LMSTUDIO] Context {index}/{total} DONE "
                f"in {elapsed:.2f}s -> "
                f"{len(context_proposals)} finding(s)",
                flush=True,
            )

        stage_elapsed = time.perf_counter() - stage_started

        print(
            "\n"
            "=============== LM STUDIO PROPOSAL SUMMARY ===============\n"
            f"Attempted: {self.last_execution_report['chunks_attempted']}\n"
            f"Succeeded: {self.last_execution_report['chunks_succeeded']}\n"
            f"Failed: {self.last_execution_report['chunks_failed']}\n"
            f"Proposals: {len(proposals)}\n"
            f"Elapsed: {stage_elapsed:.2f}s\n"
            "==========================================================",
            flush=True,
        )

        return proposals

    def _chat_completion_with_retry(
        self,
        *,
        prompt: str,
        system_instruction: str,
    ) -> Any:
        """
        Shared LM Studio request path for both static and generic contexts.
        """
        full_prompt = prompt + self._json_instructions()

        attempt = 0

        while True:
            try:
                return self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "system",
                            "content": system_instruction,
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

                print(
                    f"[LMSTUDIO] Request retry "
                    f"{attempt}/{self.max_retries} "
                    f"after {type(exc).__name__}: {exc}",
                    flush=True,
                )

                if self.retry_delay_seconds > 0:
                    time.sleep(self.retry_delay_seconds)

    def _generate_with_retry(self, prompt: str) -> Any:
        """
        Static chunk request using LM Studio chat completions.
        """
        return self._chat_completion_with_retry(
            prompt=prompt,
            system_instruction=SYSTEM_INSTRUCTION,
        )

    def _generate_context_with_retry(self, prompt: str) -> Any:
        """
        Generic/dynamic context request using LM Studio chat completions.

        This override is essential: without it, the inherited OpenAI
        implementation uses the Responses API and strict JSON schema path
        intended for OpenAI models rather than LM Studio's compatible
        chat-completions path.
        """
        return self._chat_completion_with_retry(
            prompt=prompt,
            system_instruction=GENERIC_SYSTEM_INSTRUCTION,
        )

    @staticmethod
    def _extract_payload(response: Any) -> dict[str, Any]:
        try:
            text = response.choices[0].message.content
        except (AttributeError, IndexError, TypeError):
            print(
                "[LMSTUDIO] Response did not contain "
                "choices[0].message.content.",
                flush=True,
            )
            return {"findings": []}

        print(
            "\n"
            "================ LM STUDIO RAW RESPONSE ================\n"
            f"{text}\n"
            "========================================================",
            flush=True,
        )

        if not isinstance(text, str) or not text.strip():
            print(
                "[LMSTUDIO] Empty model response -> 0 findings.",
                flush=True,
            )
            return {"findings": []}

        try:
            payload = json.loads(text)

            if isinstance(payload, dict):
                return payload

        except json.JSONDecodeError as exc:
            print(
                f"[LMSTUDIO] Direct JSON parse failed: {exc}. "
                "Trying embedded JSON extraction.",
                flush=True,
            )

        match = re.search(r"\{.*\}", text, re.DOTALL)

        if match:
            try:
                payload = json.loads(match.group(0))

                if isinstance(payload, dict):
                    print(
                        "[LMSTUDIO] Embedded JSON extraction succeeded.",
                        flush=True,
                    )
                    return payload

            except json.JSONDecodeError as exc:
                print(
                    f"[LMSTUDIO] Embedded JSON parse failed: {exc}.",
                    flush=True,
                )

        print(
            "[LMSTUDIO] No valid JSON payload could be extracted "
            "-> 0 findings.",
            flush=True,
        )

        return {"findings": []}
