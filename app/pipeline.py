import os

from human_review import review_finding
from llm_proposer import propose_finding

from runtime_evidence_collector import (
    collect_sql_injection_evidence,
    save_evidence
)

from evidence_gate import evaluate_evidence


# ============================================================
# CONFIGURATION
# ============================================================

# The proposal provider can be:
#
# "gemini" -> use the real Gemini API
# "mock"   -> use a clearly labelled development proposal
#
# Default is Gemini.
PROPOSAL_MODE = os.getenv(
    "APPSEC_PROPOSER",
    "gemini"
).strip().lower()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def normalise_finding_type(finding_type):
    """
    Convert different names for the same vulnerability type
    into one consistent internal representation.
    """

    if not finding_type:
        return ""

    value = finding_type.strip().lower()

    sql_injection_names = {
        "sql injection",
        "sql_injection",
        "sqli",
        "sql-injection"
    }

    if value in sql_injection_names:
        return "SQL_INJECTION"

    return (
        finding_type
        .strip()
        .upper()
        .replace(" ", "_")
        .replace("-", "_")
    )


def get_mock_proposal():
    """
    Return a clearly labelled development proposal.

    This is NOT Gemini output.

    It exists only so the rest of the pipeline can be tested
    when the external Gemini service is unavailable.
    """

    return {
        "finding_type": "SQL_INJECTION",
        "parameter": "id",
        "description": (
            "Development test proposal: the 'id' parameter "
            "may be vulnerable to SQL Injection."
        ),
        "status": "PROPOSED",
        "proposal_source": "MOCK"
    }


def get_proposal():
    """
    Get a proposal from the configured provider.

    Gemini mode:
        Uses the real Gemini API.

    Mock mode:
        Uses a deterministic development proposal.
    """

    if PROPOSAL_MODE == "mock":

        print(
            "Proposal provider: MOCK "
            "(development/testing only)"
        )

        return get_mock_proposal()

    if PROPOSAL_MODE == "gemini":

        print(
            "Proposal provider: GEMINI"
        )

        proposal = propose_finding()

        # Make the source explicit for auditability.
        proposal["proposal_source"] = "GEMINI"

        return proposal

    raise ValueError(
        f"Unsupported APPSEC_PROPOSER value: "
        f"{PROPOSAL_MODE}"
    )


# ============================================================
# MAIN PIPELINE
# ============================================================

def run_pipeline():

    print("\n======================================")
    print("EVIDENCE-GATED APPSEC PIPELINE")
    print("======================================")

    print(
        f"\nConfigured proposal mode: "
        f"{PROPOSAL_MODE.upper()}"
    )

    # --------------------------------------------------------
    # STEP 1
    # AI / PROVIDER PROPOSAL
    # --------------------------------------------------------

    print("\nSTEP 1 - PROPOSED FINDING")
    print("--------------------------------------")

    try:
        proposal = get_proposal()

    except RuntimeError as exc:

        print("\nAI PROPOSAL UNAVAILABLE")
        print("--------------------------------------")
        print(exc)

        print(
            "\nThe pipeline stopped safely because "
            "no AI proposal was generated."
        )

        print(
            "\nFor development only, you can run "
            "the pipeline using MOCK mode."
        )

        return

    except Exception as exc:

        print("\nPROPOSAL STAGE FAILED")
        print("--------------------------------------")
        print(exc)

        return

    proposed_type = normalise_finding_type(
        proposal.get("finding_type")
    )

    proposed_parameter = proposal.get(
        "parameter"
    )

    proposal_source = proposal.get(
        "proposal_source",
        "UNKNOWN"
    )

    print(
        f"Proposal source: "
        f"{proposal_source}"
    )

    print(
        f"Finding type: "
        f"{proposed_type}"
    )

    print(
        f"Parameter: "
        f"{proposed_parameter}"
    )

    print(
        f"Description: "
        f"{proposal.get('description')}"
    )

    print(
        f"Status: "
        f"{proposal.get('status')}"
    )

    print(
        "\nImportant: "
        "A proposed finding is not proof."
    )

    # --------------------------------------------------------
    # STEP 2
    # CHECK VERIFICATION CAPABILITY
    # --------------------------------------------------------

    print("\nSTEP 2 - VERIFICATION CAPABILITY")
    print("--------------------------------------")

    if proposed_type != "SQL_INJECTION":

        print(
            f"No deterministic verifier is currently "
            f"available for: {proposed_type}"
        )

        print(
            "\nVerification result: NEEDS_HUMAN"
        )

        print(
            "\nThe system does not guess or run an "
            "unrelated verifier."
        )

        print(
            "This proposed finding should be reviewed "
            "by a human analyst."
        )

        return

    if not proposed_parameter:

        print(
            "The SQL Injection proposal does not contain "
            "an affected parameter."
        )

        print(
            "Verification result: NEEDS_HUMAN"
        )

        return

    print(
        "Supported verifier found:"
    )

    print(
        "SQL Injection Boolean Behaviour Comparison"
    )

    # --------------------------------------------------------
    # STEP 3
    # INDEPENDENT RUNTIME VERIFICATION
    # --------------------------------------------------------

    print("\nSTEP 3 - RUNTIME VERIFICATION")
    print("--------------------------------------")

    try:
        evidence = collect_sql_injection_evidence(
            finding_id="F-0001",
            endpoint="/vulnerabilities/sqli/",
            parameter=proposed_parameter,
            method="GET"
        )

    except Exception as exc:

        print(
            "\nRuntime verification failed:"
        )

        print(exc)

        print(
            "\nVerification result: NEEDS_HUMAN"
        )

        return

    signals = evidence.get(
        "signals",
        {}
    )

    print("\nRuntime observations:")

    print(
        f"Baseline result: "
        f"{signals.get('baseline_result_count')}"
    )

    print(
        f"TRUE result: "
        f"{signals.get('true_result_count')}"
    )

    print(
        f"FALSE result: "
        f"{signals.get('false_result_count')}"
    )

    print(
        f"Behaviour changed: "
        f"{signals.get('behaviour_changed')}"
    )

    print(
        f"TRUE/FALSE difference: "
        f"{signals.get('true_false_difference')}"
    )

    print(
        f"TRUE expands results: "
        f"{signals.get('true_expands_results')}"
    )

    print(
        f"FALSE reduces results: "
        f"{signals.get('false_reduces_results')}"
    )

    print(
        f"Database error detected: "
        f"{signals.get('database_error_detected')}"
    )

    # --------------------------------------------------------
    # STEP 4
    # EVIDENCE GATE
    # --------------------------------------------------------

    print("\nSTEP 4 - EVIDENCE GATE")
    print("--------------------------------------")

    decision = evaluate_evidence(
        evidence
    )

    # Save the deterministic gate result
    # inside the evidence record.
    evidence[
        "evidence_gate_result"
    ] = decision

    # Also keep proposal source for traceability.
    evidence[
        "proposal_source"
    ] = proposal_source

    print(
        f"Evidence gate decision: "
        f"{decision}"
    )

    print(
        "\nThe evidence gate uses deterministic "
        "runtime observations, not AI confidence."
    )

    # --------------------------------------------------------
    # STEP 5
    # SAVE EVIDENCE
    # --------------------------------------------------------

    print("\nSTEP 5 - SAVE EVIDENCE")
    print("--------------------------------------")

    try:
        json_file, csv_file = save_evidence(
            evidence
        )

    except Exception as exc:

        print(
            "Evidence could not be saved:"
        )

        print(exc)

        return

    print(
        f"Detailed JSON saved to:"
    )

    print(
        f"{json_file}"
    )

    print(
        "\nCSV summary saved to:"
    )

    print(
        f"{csv_file}"
    )

    # --------------------------------------------------------
    # STEP 6
    # PIPELINE SUMMARY
    # --------------------------------------------------------

    print("\n======================================")
    print("PIPELINE RESULT")
    print("======================================")

    print(
        f"Finding ID: "
        f"{evidence.get('finding_id')}"
    )

    print(
        f"Proposal source: "
        f"{proposal_source}"
    )

    print(
        f"Finding type: "
        f"{evidence.get('finding_type')}"
    )

    print(
        f"Endpoint: "
        f"{evidence.get('endpoint')}"
    )

    print(
        f"Parameter: "
        f"{evidence.get('parameter')}"
    )

    print(
        f"Baseline: "
        f"{signals.get('baseline_result_count')}"
    )

    print(
        f"TRUE condition: "
        f"{signals.get('true_result_count')}"
    )

    print(
        f"FALSE condition: "
        f"{signals.get('false_result_count')}"
    )

    print(
        f"Evidence Gate: "
        f"{decision}"
    )

    # --------------------------------------------------------
    # STEP 7
    # HUMAN REVIEW
    # --------------------------------------------------------

    print("\nSTEP 7 - HUMAN REVIEW")
    print("--------------------------------------")

    try:
        human_result = review_finding(
            proposal,
            evidence,
            decision
        )

    except Exception as exc:

        print(
            "Human review could not be completed:"
        )

        print(exc)

        return

    print("\n======================================")
    print("FINAL HUMAN REVIEW RESULT")
    print("======================================")

    print(
        f"Evidence Gate: "
        f"{decision}"
    )

    print(
        f"Human decision: "
        f"{human_result.get('human_decision')}"
    )

    print(
        f"Final description: "
        f"{human_result.get('final_description')}"
    )

    print("\n======================================")
    print("PIPELINE COMPLETED")
    print("======================================")

    print(
        "\nAI proposes -> "
        "Evidence verifies -> "
        "Human decides"
    )


if __name__ == "__main__":
    run_pipeline()