from __future__ import annotations

from app.models.finding import FindingStatus


def evaluate_evidence(
    evidence: dict,
) -> FindingStatus:
 
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



    if not all_requests_successful:
        return FindingStatus.NEEDS_HUMAN



    if (
        behaviour_changed
        and true_false_difference
        and true_expands_results
        and false_reduces_results
    ):
        return FindingStatus.PROVED



    if (
        not behaviour_changed
        and not true_false_difference
    ):
        return FindingStatus.REFUTED


    return FindingStatus.NEEDS_HUMAN