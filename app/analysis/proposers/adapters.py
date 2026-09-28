"""
Adapters from analysis-specific contexts to AnalysisContext.

The adapters form the boundary between analysis strategies and the
provider-independent LLM layer.

They preserve provenance while deliberately avoiding vulnerability
detection, CWE classification, severity assignment, verification, and
provider-specific behaviour.

Architecture:

    Static ContextChunk --------\
                                 -> AnalysisContext -> LLM proposer
    Dynamic DynamicContext -----/

Future analysis strategies can add their own adapters without changing
the AnalysisContext contract or existing adapters.
"""

from __future__ import annotations

from app.analysis.proposers.context import AnalysisContext
from app.dynamic_analysis.context_builder import DynamicContext
from app.static_analysis.context_builder import ContextChunk


def adapt_static_context(
    chunk: ContextChunk,
) -> AnalysisContext:
    """Adapt one static source chunk to the generic context contract."""

    if not isinstance(chunk, ContextChunk):
        raise TypeError(
            "chunk must be a ContextChunk."
        )

    return AnalysisContext(
        context_id=chunk.chunk_id,
        scan_type="STATIC",
        content=chunk.source_code,
        metadata={
            "source_file": chunk.source_file,
            "language": chunk.language,
            "start_line": chunk.start_line,
            "end_line": chunk.end_line,
        },
    )


def adapt_dynamic_context(
    context: DynamicContext,
) -> AnalysisContext:
    """Adapt one dynamic observation to the generic context contract."""

    if not isinstance(context, DynamicContext):
        raise TypeError(
            "context must be a DynamicContext."
        )

    return AnalysisContext(
        context_id=context.context_id,
        scan_type="DYNAMIC",
        content=context.context_text,
        metadata={
            "context_type": context.context_type,
            "source_url": context.source_url,
            "endpoint_url": context.endpoint_url,
            "method": context.method,
            "parameters": [
                dict(parameter)
                for parameter in context.parameters
            ],
            "observed_from": context.observed_from,
        },
    )


def adapt_static_contexts(
    chunks: list[ContextChunk],
) -> list[AnalysisContext]:
    """Adapt static chunks while preserving their existing order."""

    if not isinstance(chunks, list):
        raise TypeError(
            "chunks must be a list."
        )

    return [
        adapt_static_context(chunk)
        for chunk in chunks
    ]


def adapt_dynamic_contexts(
    contexts: list[DynamicContext],
) -> list[AnalysisContext]:
    """Adapt dynamic contexts while preserving their existing order."""

    if not isinstance(contexts, list):
        raise TypeError(
            "contexts must be a list."
        )

    return [
        adapt_dynamic_context(context)
        for context in contexts
    ]