"""
Generic static-analysis context builder.

Transforms collected source files into bounded context chunks suitable
for downstream LLM analysis.

Responsibilities:
- preserve source-file provenance
- preserve original line numbers
- split large files into bounded chunks
- provide controlled overlap between chunks
- enforce a global analysis budget
- report analysis coverage honestly
- distinguish empty files from files excluded by analysis limits

This module does NOT call an LLM and does NOT detect vulnerabilities.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from app.static_analysis.collector import SourceFile


DEFAULT_MAX_CHUNK_CHARS = 12_000
DEFAULT_OVERLAP_LINES = 20

# These limits control downstream analysis workload.
# They are intentionally independent from archive-ingestion limits.
DEFAULT_MAX_ANALYSIS_CHARS = 500_000
DEFAULT_MAX_ANALYSIS_FILES = 500


@dataclass(frozen=True)
class ContextChunk:
    """One bounded unit of source context for downstream analysis."""

    chunk_id: str
    source_file: str
    language: str
    start_line: int
    end_line: int
    source_code: str
    char_count: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ContextBuildResult:
    """Context chunks plus transparent coverage information."""

    chunks: list[ContextChunk]

    files_discovered: int
    files_selected: int
    empty_files: int
    files_excluded_by_budget: int

    total_source_chars: int
    selected_chars: int

    truncated: bool
    truncation_reason: str | None

    @property
    def chunk_count(self) -> int:
        return len(self.chunks)

    def to_dict(self) -> dict:
        return {
            "chunks": [
                chunk.to_dict()
                for chunk in self.chunks
            ],
            "coverage": {
                "files_discovered": self.files_discovered,
                "files_selected": self.files_selected,
                "empty_files": self.empty_files,
                "files_excluded_by_budget":
                    self.files_excluded_by_budget,
                "chunks_created": self.chunk_count,
                "total_source_chars":
                    self.total_source_chars,
                "selected_chars": self.selected_chars,
                "truncated": self.truncated,
                "truncation_reason":
                    self.truncation_reason,
            },
        }


class StaticContextBuilder:
    """
    Build deterministic LLM-ready chunks from collected source files.

    Chunks never combine multiple source files.

    Adjacent chunks can overlap by a configurable number of lines so
    code close to a chunk boundary retains useful local context.

    The builder also enforces a global analysis budget independently
    from ZIP extraction limits.
    """

    def __init__(
        self,
        *,
        max_chunk_chars: int = DEFAULT_MAX_CHUNK_CHARS,
        overlap_lines: int = DEFAULT_OVERLAP_LINES,
        max_analysis_chars: int = DEFAULT_MAX_ANALYSIS_CHARS,
        max_analysis_files: int = DEFAULT_MAX_ANALYSIS_FILES,
    ) -> None:
        if max_chunk_chars <= 0:
            raise ValueError(
                "max_chunk_chars must be greater than zero."
            )

        if overlap_lines < 0:
            raise ValueError(
                "overlap_lines cannot be negative."
            )

        if max_analysis_chars <= 0:
            raise ValueError(
                "max_analysis_chars must be greater than zero."
            )

        if max_analysis_files <= 0:
            raise ValueError(
                "max_analysis_files must be greater than zero."
            )

        self.max_chunk_chars = max_chunk_chars
        self.overlap_lines = overlap_lines
        self.max_analysis_chars = max_analysis_chars
        self.max_analysis_files = max_analysis_files

    def build(
        self,
        source_files: Iterable[SourceFile],
    ) -> ContextBuildResult:
        """
        Convert source files into bounded deterministic context chunks.

        Empty files are counted separately and are not treated as
        analysis exclusions.

        files_excluded_by_budget represents non-empty source files that
        could not be selected because a configured analysis limit was
        reached.
        """

        files = sorted(
            list(source_files),
            key=lambda item: item.relative_path.lower(),
        )

        files_discovered = len(files)

        empty_files = sum(
            1
            for item in files
            if not item.source_code
        )

        total_source_chars = sum(
            len(item.source_code)
            for item in files
        )

        chunks: list[ContextChunk] = []

        files_selected = 0
        selected_chars = 0

        truncated = False
        truncation_reason: str | None = None

        for source_file in files:
            # Empty files contain no source context to send downstream.
            # They are counted separately rather than being classified
            # as excluded by an analysis budget.
            if not source_file.source_code:
                continue

            if files_selected >= self.max_analysis_files:
                truncated = True
                truncation_reason = (
                    "Maximum number of source files selected "
                    "for analysis was reached."
                )
                break

            remaining_budget = (
                self.max_analysis_chars
                - selected_chars
            )

            if remaining_budget <= 0:
                truncated = True
                truncation_reason = (
                    "Maximum source-character analysis budget "
                    "was reached."
                )
                break

            file_chunks = self._chunk_source_file(
                source_file
            )

            selected_for_file = False

            for chunk in file_chunks:
                # selected_chars measures the actual amount of source
                # context sent downstream, including intentional
                # overlap between adjacent chunks.
                if (
                    selected_chars + chunk.char_count
                    > self.max_analysis_chars
                ):
                    truncated = True
                    truncation_reason = (
                        "Maximum source-character analysis budget "
                        "was reached."
                    )
                    break

                chunks.append(chunk)

                selected_chars += chunk.char_count
                selected_for_file = True

            if selected_for_file:
                files_selected += 1

            if truncated:
                break

        non_empty_files = (
            files_discovered
            - empty_files
        )

        files_excluded_by_budget = max(
            0,
            non_empty_files
            - files_selected,
        )

        return ContextBuildResult(
            chunks=chunks,
            files_discovered=files_discovered,
            files_selected=files_selected,
            empty_files=empty_files,
            files_excluded_by_budget=files_excluded_by_budget,
            total_source_chars=total_source_chars,
            selected_chars=selected_chars,
            truncated=truncated,
            truncation_reason=truncation_reason,
        )

    def _chunk_source_file(
        self,
        source_file: SourceFile,
    ) -> list[ContextChunk]:
        """
        Split one source file into bounded chunks.

        The original source line numbers are preserved.

        A chunk never contains content from more than one source file.
        """

        lines = source_file.source_code.splitlines(
            keepends=True
        )

        if not lines:
            return []

        chunks: list[ContextChunk] = []

        start_index = 0

        while start_index < len(lines):
            end_index = self._find_chunk_end(
                lines,
                start_index,
            )

            selected_lines = lines[
                start_index:end_index
            ]

            source_code = "".join(selected_lines)

            start_line = start_index + 1
            end_line = end_index

            chunk_id = (
                f"{source_file.relative_path}:"
                f"{start_line}-{end_line}"
            )

            chunks.append(
                ContextChunk(
                    chunk_id=chunk_id,
                    source_file=source_file.relative_path,
                    language=source_file.language,
                    start_line=start_line,
                    end_line=end_line,
                    source_code=source_code,
                    char_count=len(source_code),
                )
            )

            if end_index >= len(lines):
                break

            next_start = max(
                start_index + 1,
                end_index - self.overlap_lines,
            )

            # Defensive guarantee that the builder always progresses,
            # even if overlap_lines is unusually large.
            if next_start <= start_index:
                next_start = start_index + 1

            start_index = next_start

        return chunks

    def _find_chunk_end(
        self,
        lines: list[str],
        start_index: int,
    ) -> int:
        """
        Find a conservative chunk boundary.

        The hard constraint is max_chunk_chars.

        When possible, the builder prefers the last blank line before
        the hard limit because this is often a better language-neutral
        boundary than cutting directly in the middle of a code block.

        A single source line that exceeds max_chunk_chars is kept
        intact rather than silently truncating or modifying source.
        """

        char_count = 0
        index = start_index
        last_blank_index: int | None = None

        while index < len(lines):
            line = lines[index]

            prospective_size = (
                char_count + len(line)
            )

            if (
                char_count > 0
                and prospective_size
                > self.max_chunk_chars
            ):
                break

            char_count = prospective_size

            if not line.strip():
                last_blank_index = index + 1

            index += 1

            if char_count >= self.max_chunk_chars:
                break

        if index >= len(lines):
            return len(lines)

        if (
            last_blank_index is not None
            and last_blank_index > start_index
        ):
            return last_blank_index

        return max(
            start_index + 1,
            index,
        )