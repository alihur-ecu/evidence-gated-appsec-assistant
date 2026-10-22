
from __future__ import annotations

import getpass
import os
import sys
import time
from typing import Any

from app.analysis.proposers.adapters import adapt_dynamic_contexts
from app.analysis.proposers.factory import create_static_proposer
from app.dynamic_analysis.authentication import (
    AUTH_FORM,
    AUTH_NONE,
    create_analysis_session,
)
from app.dynamic_analysis.context_builder import DynamicContextBuilder
from app.dynamic_analysis.discovery import DynamicDiscovery
from app.dynamic_analysis.target import build_dynamic_target


def heading(text: str) -> None:
    print()
    print(text)


def elapsed(started_at: float) -> str:
    return f"{time.perf_counter() - started_at:.3f}s"


def env_or_prompt(name: str, prompt: str, default: str = "") -> str:
    configured = os.getenv(name)
    if configured is not None and configured.strip():
        return configured.strip()

    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def choose_context(contexts: list[Any]) -> Any:
  
    if not contexts:
        raise RuntimeError("No AnalysisContexts were produced by discovery.")

    match = os.getenv("PHASE3F_CONTEXT_MATCH", "").strip().lower()

    if match:
        for context in contexts:
            metadata = context.metadata or {}
            searchable = "\n".join(
                [
                    str(context.context_id),
                    str(metadata.get("endpoint_url", "")),
                    str(metadata.get("source_url", "")),
                    str(context.content),
                ]
            ).lower()
            if match in searchable and context.content.strip():
                return context

        raise RuntimeError(
            "PHASE3F_CONTEXT_MATCH did not match any non-empty context: "
            f"{match!r}"
        )

    for context in contexts:
        if context.content.strip():
            return context

    raise RuntimeError("All adapted AnalysisContexts are empty.")


def main() -> None:
    print("=== PHASE 3F — SINGLE LLM REQUEST DIAGNOSTIC ===")
    print("This run sends exactly ONE dynamic AnalysisContext to the LLM.")

    target_url = env_or_prompt(
        "PHASE3F_TARGET_URL",
        "Target URL",
        "http://localhost:4280/",
    )

    auth_choice = env_or_prompt(
        "PHASE3F_AUTH_MODE",
        "Authentication mode (FORM/NONE)",
        "FORM",
    ).upper()

    if auth_choice not in {AUTH_FORM, AUTH_NONE}:
        raise RuntimeError("Authentication mode must be FORM or NONE.")

    username: str | None = None
    password: str | None = None

    if auth_choice == AUTH_FORM:
        username = env_or_prompt(
            "PHASE3F_USERNAME",
            "Username or email",
            "admin",
        )
        password = os.getenv("PHASE3F_PASSWORD")
        if password is None:
            password = getpass.getpass("Password: ")

    application_name = os.getenv(
        "PHASE3F_APPLICATION_NAME",
        "Phase 3F Dynamic Diagnostic",
    ).strip()

    overall_started = time.perf_counter()

    heading("=== 1. SESSION / AUTHENTICATION ===")
    stage_started = time.perf_counter()
    session, auth_result = create_analysis_session(
        target_url=target_url,
        authentication_mode=auth_choice,
        username=username,
        password=password,
    )
    print("Mode:", auth_result.mode)
    print("Authenticated:", auth_result.authenticated)
    print("Login URL:", auth_result.login_url)
    print("Elapsed:", elapsed(stage_started))

    heading("=== 2. DISCOVERY ===")
    stage_started = time.perf_counter()
    target = build_dynamic_target(target_url)
    discovery = DynamicDiscovery(session=session).discover(target)
    print("Pages:", len(discovery.pages))
    print("Endpoints:", len(discovery.endpoints))
    print("Forms:", len(discovery.forms))
    print("Elapsed:", elapsed(stage_started))

    heading("=== 3. CONTEXT BUILDING ===")
    stage_started = time.perf_counter()
    context_result = DynamicContextBuilder().build(discovery)
    analysis_contexts = adapt_dynamic_contexts(context_result.contexts)
    print("Native contexts:", len(context_result.contexts))
    print("Adapted AnalysisContexts:", len(analysis_contexts))
    print("Elapsed:", elapsed(stage_started))

    selected = choose_context(analysis_contexts)
    metadata = selected.metadata or {}

    heading("=== 4. SELECTED SINGLE CONTEXT ===")
    print("Context ID:", selected.context_id)
    print("Scan type:", selected.scan_type)
    print("Characters:", selected.char_count)
    print("Context type:", metadata.get("context_type"))
    print("Source URL:", metadata.get("source_url"))
    print("Endpoint URL:", metadata.get("endpoint_url"))
    print("Method:", metadata.get("method"))
    print("Parameters:", metadata.get("parameters"))
    print()
    print("IMPORTANT: only this one context will be sent to the proposer.")

    heading("=== 5. LLM PROVIDER ===")
    proposer = create_static_proposer()
    provider_name = str(getattr(proposer, "provider_name", "UNKNOWN"))
    model_name = getattr(proposer, "model", None)
    print("Configured LLM_PROVIDER:", os.getenv("LLM_PROVIDER", "none"))
    print("Provider:", provider_name)
    print("Model:", model_name)

    if provider_name.upper() == "NONE":
        raise RuntimeError(
            "LLM_PROVIDER is 'none'. Configure the same live provider used by "
            "the web application before running Phase 3F."
        )

    propose_contexts = getattr(proposer, "propose_contexts", None)
    if not callable(propose_contexts):
        raise RuntimeError(
            f"Provider {provider_name!r} does not implement propose_contexts()."
        )

    heading("=== 6. ONE LIVE LLM REQUEST ===")
    print("Starting exactly ONE proposer context...")
    print("If this remains here for an excessive time, press Ctrl+C once.")
    sys.stdout.flush()

    request_started = time.perf_counter()

    try:
        proposals = propose_contexts(
            application_name=application_name,
            contexts=[selected],
        )
    except KeyboardInterrupt:
        print()
        print("INTERRUPTED: the single-context proposer call did not complete.")
        print("Elapsed before interrupt:", elapsed(request_started))
        raise SystemExit(130)
    except Exception as exc:
        print("RESULT: ERROR")
        print("Elapsed:", elapsed(request_started))
        print("Error type:", type(exc).__name__)
        print("Error:", str(exc))
        report = getattr(proposer, "last_execution_report", None)
        if report is not None:
            print("Execution report:", report)
        raise

    request_elapsed = elapsed(request_started)

    heading("=== 7. RESULT ===")
    print("RESULT: COMPLETED")
    print("Single-context LLM elapsed:", request_elapsed)
    print("Proposals returned:", len(proposals))

    report = getattr(proposer, "last_execution_report", None)
    if report is not None:
        print("Execution report:", report)

    for index, proposal in enumerate(proposals, start=1):
        print()
        print(f"Proposal {index}:")
        if isinstance(proposal, dict):
            for key in (
                "type",
                "title",
                "cwe",
                "proposed_cwe",
                "suggested_severity",
                "source_file",
                "endpoint",
                "parameter",
                "status",
            ):
                if key in proposal:
                    print(f"  {key}: {proposal.get(key)}")
        else:
            print(" ", repr(proposal))

    heading("=== 8. DIAGNOSTIC INTERPRETATION ===")
    print("The one-context provider call completed.")
    print(
        "If the full web scan still stalls with many contexts, this supports "
        "the multi-context execution path as the next component to redesign."
    )
    print("Total Phase 3F elapsed:", elapsed(overall_started))
    print()
    print("=== PHASE 3F COMPLETE ===")


if __name__ == "__main__":
    main()
