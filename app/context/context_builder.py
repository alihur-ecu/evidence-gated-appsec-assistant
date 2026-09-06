"""
Context Builder.

Takes raw dynamic probing information (from http_probe.run_probe) and
assembles the structured context that will be sent to the LLM Proposer.
"""

from __future__ import annotations

from urllib.parse import urlencode

from app.http_probe import login_dvwa, run_probe


def build_url(base_url: str, endpoint: str, parameters: dict) -> str:
    """Combine base_url + endpoint + query parameters into a full URL."""
    query_string = urlencode(parameters)
    return f"{base_url.rstrip('/')}{endpoint}?{query_string}"


def build_context(
    target_name: str,
    base_url: str,
    endpoint: str,
    method: str,
    parameters: dict,
    excerpt_length: int = 300,
    session=None,
) -> dict:
    """
    Run a baseline probe against the given endpoint/parameters and
    build the context dict that will be handed to the LLM Proposer.

    If `session` is None, an authenticated DVWA session is created
    automatically so the probe sees real application behaviour
    instead of being redirected to the login page.
    """
    if session is None:
        session = login_dvwa(base_url)

    url = build_url(base_url, endpoint, parameters)
    evidence = run_probe(url, method=method, session=session)

    return {
        "target": target_name,
        "endpoint": endpoint,
        "method": method,
        "parameters": parameters,
        "baseline_status": evidence["status_code"],
        "response_excerpt": evidence["response_body"][:excerpt_length],
    }