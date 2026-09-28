"""
Provider-independent execution budget for static LLM proposers.

The budget limits how much already-bounded source context may be sent
to an LLM during one analysis.

It is intentionally independent of Gemini, OpenAI, Azure OpenAI,
private enterprise models, and other proposer implementations.

The StaticContextBuilder controls source collection/chunking.
This component controls LLM execution exposure.

Architecture principle:

    Source context
        ->
    Execution budget
        ->
    Selected LLM proposer
        ->
    Candidate proposals
        ->
    Evidence verifies
        ->
    Human decides
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


DEFAULT_MAX_CHUNKS = 50
DEFAULT_MAX_SOURCE_CHARS = 500_000


@dataclass(frozen=True)
class BudgetResult:
    """
    Result of applying an LLM execution budget.

    selected_chunks contains the chunks that may be supplied to the
    configured proposer.

    skipped_chunks contains chunks that were not selected because the
    execution budget was exhausted.
    """

    selected_chunks: list[dict[str, Any]]
    skipped_chunks: list[dict[str, Any]]

    chunks_received: int
    chunks_selected: int
    chunks_skipped: int

    source_chars_received: int
    source_chars_selected: int

    truncated: bool
    truncation_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly execution summary."""

        return {
            "chunks_received": self.chunks_received,
            "chunks_selected": self.chunks_selected,
            "chunks_skipped": self.chunks_skipped,
            "source_chars_received": self.source_chars_received,
            "source_chars_selected": self.source_chars_selected,
            "truncated": self.truncated,
            "truncation_reason": self.truncation_reason,
        }


class LLMExecutionBudget:
    """
    Apply deterministic limits before source chunks reach an LLM.

    The budget does not modify chunks and does not estimate monetary
    cost. Its purpose is to provide a predictable upper bound on the
    amount of source context and number of model calls that a proposer
    can receive during one analysis.

    A proposer currently performs at most one model call per selected
    chunk. Therefore max_chunks also provides an upper bound on normal
    model calls before retries.
    """

    def __init__(
        self,
        *,
        max_chunks: int | None = None,
        max_source_chars: int | None = None,
    ) -> None:
        self.max_chunks = self._resolve_positive_int(
            explicit_value=max_chunks,
            environment_name="LLM_MAX_CHUNKS",
            default=DEFAULT_MAX_CHUNKS,
        )

        self.max_source_chars = self._resolve_positive_int(
            explicit_value=max_source_chars,
            environment_name="LLM_MAX_SOURCE_CHARS",
            default=DEFAULT_MAX_SOURCE_CHARS,
        )

    def apply(
        self,
        chunks: list[dict[str, Any]],
    ) -> BudgetResult:
        """
        Select chunks in their existing deterministic order.

        Selection stops when either:

        - max_chunks has been reached; or
        - adding the next chunk would exceed max_source_chars.

        A single chunk larger than the total character budget is
        skipped rather than partially modifying the chunk. Chunk
        boundaries remain the responsibility of StaticContextBuilder.
        """

        if not isinstance(chunks, list):
            raise TypeError(
                "chunks must be a list."
            )

        selected_chunks: list[dict[str, Any]] = []
        skipped_chunks: list[dict[str, Any]] = []

        source_chars_received = sum(
            self._chunk_char_count(chunk)
            for chunk in chunks
        )

        source_chars_selected = 0
        reasons: list[str] = []

        for index, chunk in enumerate(chunks):
            if len(selected_chunks) >= self.max_chunks:
                skipped_chunks.extend(chunks[index:])

                reasons.append(
                    f"Maximum chunk budget reached "
                    f"({self.max_chunks})."
                )
                break

            chunk_chars = self._chunk_char_count(chunk)

            if (
                source_chars_selected + chunk_chars
                > self.max_source_chars
            ):
                skipped_chunks.extend(chunks[index:])

                reasons.append(
                    f"Maximum source-character budget reached "
                    f"({self.max_source_chars})."
                )
                break

            selected_chunks.append(chunk)
            source_chars_selected += chunk_chars

        chunks_received = len(chunks)
        chunks_selected = len(selected_chunks)
        chunks_skipped = len(skipped_chunks)

        truncated = chunks_skipped > 0

        truncation_reason = (
            " ".join(reasons)
            if reasons
            else None
        )

        return BudgetResult(
            selected_chunks=list(selected_chunks),
            skipped_chunks=list(skipped_chunks),
            chunks_received=chunks_received,
            chunks_selected=chunks_selected,
            chunks_skipped=chunks_skipped,
            source_chars_received=source_chars_received,
            source_chars_selected=source_chars_selected,
            truncated=truncated,
            truncation_reason=truncation_reason,
        )

    @staticmethod
    def _chunk_char_count(
        chunk: dict[str, Any],
    ) -> int:
        """
        Return the actual source-code character count.

        We intentionally calculate this from source_code rather than
        trusting provider-supplied char_count metadata.
        """

        if not isinstance(chunk, dict):
            return 0

        source_code = chunk.get(
            "source_code",
            "",
        )

        if not isinstance(source_code, str):
            return 0

        return len(source_code)

    @staticmethod
    def _resolve_positive_int(
        *,
        explicit_value: int | None,
        environment_name: str,
        default: int,
    ) -> int:
        """
        Resolve a positive integer from an explicit argument or env var.

        Explicit configuration has priority over environment
        configuration.
        """

        if explicit_value is not None:
            value = explicit_value

        else:
            raw_environment_value = os.getenv(
                environment_name
            )

            if raw_environment_value is None:
                value = default

            else:
                try:
                    value = int(
                        raw_environment_value
                    )
                except ValueError as exc:
                    raise ValueError(
                        f"{environment_name} must be "
                        f"a positive integer."
                    ) from exc

        if isinstance(value, bool):
            raise ValueError(
                f"{environment_name} must be "
                f"a positive integer."
            )

        if not isinstance(value, int) or value <= 0:
            raise ValueError(
                f"{environment_name} must be "
                f"a positive integer."
            )

        return value
