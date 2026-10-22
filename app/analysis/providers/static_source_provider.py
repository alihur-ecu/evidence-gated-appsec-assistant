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
 
    archive_path = Path(source_path)

    if not archive_path.exists():
        raise FileNotFoundError(
            f"Uploaded source archive does not exist: {archive_path}"
        )

    extractor = SafeZipExtractor()
    collector = StaticSourceCollector()
   
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

      
        "source_context": source_chunks,

        "skipped_files": skipped_files,

        "message": (
            f"Static source preparation completed. "
            f"{context_result.files_selected} non-empty source files "
            f"were prepared as "
            f"{context_result.chunk_count} bounded context chunks "
            f"across {len(languages)} detected language(s)."
        ),

        "source_pattern_proposals": source_pattern_proposals,
        "source_pattern_proposal_count": len(source_pattern_proposals),
        "findings": [],
    }