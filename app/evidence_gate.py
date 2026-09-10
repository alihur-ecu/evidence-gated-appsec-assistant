"""
Evidence Gate.

The Evidence Gate evaluates deterministic runtime evidence and maps
the result into the project's canonical FindingStatus values.

The Gate never performs human acceptance/rejection.

Verification result:
    PROVED
    REFUTED
    NEEDS_HUMAN

Human decisions remain separate:
    ACCEPTED
    REJECTED
    NEEDS_FURTHER_REVIEW
"""

from __future__ import annotations

from app.models.finding import FindingStatus


def evaluate_evidence(
    evidence: dict,
) -> FindingStatus:
    """
    Evaluate SQL Injection runtime evidence.

    Current MVP policy:

    PROVED
        The verification requests executed successfully and the TRUE
        and FALSE conditions produced the expected deterministic
        behavioural difference.

    REFUTED
        Verification executed successfully, but baseline, TRUE and
        FALSE tests showed no meaningful behavioural difference.

    NEEDS_HUMAN
        Evidence is incomplete, inconsistent, or the verifier could
        not establish a reliable conclusion.

    Database error detection is treated only as an additional signal.
    It is NOT mandatory for PROVED.
    """

    if not evidence:
        return FindingStatus.NEEDS_HUMAN

    if (
        evidence.get("execution_status")
        != "COMPLETED"
    ):
        return FindingStatus.NEEDS_HUMAN

    signals = evidence.get(
        "signals",
        {},
    )

    all_requests_successful = signals.get(
        "all_requests_successful",
        False,
    )

    behaviour_changed = signals.get(
        "behaviour_changed",
        False,
    )

    true_false_difference = signals.get(
        "true_false_difference",
        False,
    )

    true_expands_results = signals.get(
        "true_expands_results",
        False,
    )

    false_reduces_results = signals.get(
        "false_reduces_results",
        False,
    )

    # ------------------------------------------------------------------
    # Invalid/incomplete verification
    # ------------------------------------------------------------------

    if not all_requests_successful:
        return FindingStatus.NEEDS_HUMAN

    # ------------------------------------------------------------------
    # Strong deterministic SQLi evidence
    # ------------------------------------------------------------------

    if (
        behaviour_changed
        and true_false_difference
        and true_expands_results
        and false_reduces_results
    ):
        return FindingStatus.PROVED

    # ------------------------------------------------------------------
    # No observed behavioural evidence
    # ------------------------------------------------------------------

    if (
        not behaviour_changed
        and not true_false_difference
    ):
        return FindingStatus.REFUTED

    # ------------------------------------------------------------------
    # Mixed/partial evidence
    # ------------------------------------------------------------------

    return FindingStatus.NEEDS_HUMAN