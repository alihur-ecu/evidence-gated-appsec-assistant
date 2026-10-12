"""
Real static source-analysis preparation provider.

This provider safely processes a source archive uploaded by the user,
collects supported source files, builds bounded source-code context, and
records narrowly scoped, source-grounded candidate patterns. The separate
LLM proposer may suggest additional candidates.

Patterns are proposals only: they never claim exploitability and never
bypass independent verification or human review. This module calls no LLM.

Pipeline:

    uploaded ZIP
        ->
    SafeZipExtractor
        ->
    StaticSourceCollector
        ->
    StaticContextBuilder
        ->
    bounded source chunks

The resulting chunks can later be supplied to any configured proposer.

The provider is independent of DVWA, Juice Shop, specific filenames,
local development paths, and programming languages.
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from app.static_analysis.archive import SafeZipExtractor
from app.static_analysis.collector import StaticSourceCollector
from app.static_analysis.context_builder import StaticContextBuilder
from app.analysis.static_source_candidates import collect_static_source_candidates


def run_static_source_analysis(
    *,
    source_path: str,
    original_filename: str,
    application_name: str,
) -> dict:
    """
    Safely extract an uploaded project and build bounded static context.

    This stage performs safe source ingestion, bounded context preparation,
    and conservative pattern-based candidate proposal collection. No source
    candidate is automatically promoted to a verified vulnerability. The
    LLM stage and evidence verification are independent later steps.
    """

    archive_path = Path(source_path)

    if not archive_path.exists():
        raise FileNotFoundError(
            f"Uploaded source archive does not exist: {archive_path}"
        )

    extractor = SafeZipExtractor()
    collector = StaticSourceCollector()
    # Smaller bounded chunks reduce local-model output truncation when a
    # source file contains many separate functions/vulnerability candidates.
    # The builder's global defaults remain unchanged for other callers.
    context_builder = StaticContextBuilder(max_chunk_chars=3000, overlap_lines=10)

    with TemporaryDirectory(
        prefix="eg_static_source_"
    ) as extraction_directory:

        extraction = extractor.extract(
            archive_path,
            extraction_directory,
        )

        collection = collector.collect(
            extraction.destination
        )

        context_result = context_builder.build(
            collection.files
        )

        # Source-backed hypotheses complement the LLM; they NEVER mark
        # anything verified, and use only the source files already collected.
        source_pattern_proposals = collect_static_source_candidates(
            collection.files
        )

        skipped_files = list(
            collection.skipped_files
        )

        file_count = collection.file_count
        total_lines = collection.total_lines
        languages = collection.languages

        source_chunks = [
            chunk.to_dict()
            for chunk in context_result.chunks
        ]
        # Preserve all bounded contexts of the origin file plus any linked
        # unsafe template. The static observer may need cross-function or
        # cross-template source lines. No source is executed or fabricated.
        for proposal in source_pattern_proposals:
            related = {proposal["source_file"], *proposal.get("related_source_files", [])}
            proposal["observed_in_chunks"] = [
                chunk["chunk_id"] for chunk in source_chunks
                if chunk["source_file"] in related
            ]

    return {
        "analysis_mode": "STATIC",
        "scan_type": "STATIC",

        "application_name": application_name,

        "source_file": Path(
            original_filename
        ).name,

        "provider": "STATIC_SOURCE",
        "context_source": "SOURCE_CODE",

        "archive": {
            "filename": Path(
                original_filename
            ).name,
            "extracted_files":
                extraction.extracted_files,
            "total_uncompressed_bytes":
                extraction.total_uncompressed_bytes,
        },

        "source_summary": {
            "source_files": file_count,
            "total_lines": total_lines,
            "languages": languages,
            "skipped_files": len(
                skipped_files
            ),
        },

        "context_coverage": {
            "files_discovered":
                context_result.files_discovered,

            "files_selected":
                context_result.files_selected,

            "empty_files":
                context_result.empty_files,

            "files_excluded_by_budget":
                context_result.files_excluded_by_budget,

            "chunks_created":
                context_result.chunk_count,

            "total_source_chars":
                context_result.total_source_chars,

            "selected_chars":
                context_result.selected_chars,

            "truncated":
                context_result.truncated,

            "truncation_reason":
                context_result.truncation_reason,
        },

        # Only bounded context is exposed downstream. This prevents a
        # future proposer from accidentally receiving an unlimited
        # repository in one request.
        "source_context": source_chunks,

        "skipped_files": skipped_files,

        "message": (
            f"Static source preparation completed. "
            f"{context_result.files_selected} non-empty source files "
            f"were prepared as "
            f"{context_result.chunk_count} bounded context chunks "
            f"across {len(languages)} detected language(s)."
        ),

        # Source patterns are labelled proposals and are combined with LLM
        # suggestions downstream, never silently promoted to proof.
        "source_pattern_proposals": source_pattern_proposals,
        "source_pattern_proposal_count": len(source_pattern_proposals),
        "findings": [],
    }