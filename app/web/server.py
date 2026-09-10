"""
Flask web application for the Evidence-Gated AppSec Finding Assistant.

Current development architecture:

Preloaded Finding
        ↓
Runtime Verifier
        ↓
Evidence
        ↓
Evidence Gate
        ↓
PROVED / REFUTED / NEEDS_HUMAN
        ↓
Human Review

The live LLM proposer is not connected yet.

Therefore, the initial findings below are deliberately labelled as
preloaded demonstration findings. The downstream verification pipeline
uses real runtime evidence from the local DVWA lab.
"""

from __future__ import annotations

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from app.evidence_gate import evaluate_evidence

from app.models.finding import (
    Finding,
    FindingStatus,
    FindingType,
)

from app.runtime_evidence_collector import (
    collect_sql_injection_evidence,
    save_evidence,
)


app = Flask(__name__)


# ======================================================================
# DISPLAY LABELS
# ======================================================================

FINDING_TYPE_LABELS = {
    FindingType.SQL_INJECTION:
        "Potential SQL Injection",

    FindingType.XSS:
        "Potential Cross-Site Scripting",
}


# ======================================================================
# PRELOADED FINDINGS
#
# These Finding objects represent the output that will eventually come
# from Hassan's live LLM proposer.
#
# They are real Finding model objects, but are currently created manually
# so the downstream verification pipeline can be implemented and tested.
# ======================================================================

FINDINGS = {}


sql_finding = Finding(
    finding_id="F-0001",
    finding_type=FindingType.SQL_INJECTION,
    endpoint="/vulnerabilities/sqli/",
    parameter="id",
    method="GET",
    explanation=(
        "A preloaded candidate finding identifies possible SQL "
        "injection in the id parameter. The live LLM proposer is not "
        "connected to the web application yet."
    ),
)

FINDINGS[
    sql_finding.finding_id
] = sql_finding


xss_finding = Finding(
    finding_id="F-0002",
    finding_type=FindingType.XSS,
    endpoint="/vulnerabilities/xss_r/",
    parameter="name",
    method="GET",
    explanation=(
        "A preloaded candidate finding identifies possible "
        "cross-site scripting in the name parameter. XSS dynamic "
        "verification is outside the current SQL Injection MVP."
    ),
)

FINDINGS[
    xss_finding.finding_id
] = xss_finding


# ======================================================================
# TEMPORARY METADATA
#
# These values are not part of Finding yet.
#
# We intentionally keep them separate instead of modifying Hassan's
# Finding model without coordinating the common data contract.
# ======================================================================

FINDING_METADATA = {

    "F-0001": {
        "target":
            "DVWA Test Environment",

        "source_file":
            "Preloaded / not connected",

        "proposed_cwe":
            "CWE-89",

        "suggested_severity":
            "HIGH",

        "proposal_source":
            "PRELOADED",
    },

    "F-0002": {
        "target":
            "DVWA Test Environment",

        "source_file":
            "Preloaded / not connected",

        "proposed_cwe":
            "CWE-79",

        "suggested_severity":
            "MEDIUM",

        "proposal_source":
            "PRELOADED",
    },
}


# ======================================================================
# TEMPORARY SERVER-SIDE STORES
#
# These dictionaries are intentionally in memory for the current MVP.
# Restarting Flask resets them.
#
# Later they can be replaced by SQLite or another persistent store
# without changing the browser workflow.
# ======================================================================

EVIDENCE_BY_FINDING = {}

REVIEW_BY_FINDING = {

    finding_id: {
        "reviewer_cwe": "",
        "final_severity": "",
        "reviewer_comment": "",
        "human_decision": None,
    }

    for finding_id in FINDINGS
}


# ======================================================================
# REVIEW VALIDATION
# ======================================================================

ALLOWED_REVIEW_FIELDS = {
    "reviewer_cwe",
    "final_severity",
    "reviewer_comment",
    "human_decision",
}

ALLOWED_HUMAN_DECISIONS = {
    "ACCEPTED",
    "REJECTED",
    "NEEDS_FURTHER_REVIEW",
}

ALLOWED_SEVERITIES = {
    "",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}


# ======================================================================
# HELPERS
# ======================================================================

def get_finding(
    finding_id: str,
) -> Finding:

    finding = FINDINGS.get(
        finding_id
    )

    if finding is None:
        abort(404)

    return finding


def verification_status_for(
    finding_id: str,
) -> str:
    """
    Execution state of the verifier.

    This is intentionally different from the Evidence Gate result.

    PENDING:
        No verification has been executed.

    COMPLETED:
        Runtime evidence exists and verification completed.
    """

    evidence = EVIDENCE_BY_FINDING.get(
        finding_id
    )

    if not evidence:
        return "PENDING"

    return evidence.get(
        "execution_status",
        "PENDING",
    )


def evidence_gate_result_for(
    finding: Finding,
) -> str:
    """
    Finding.status reflects the canonical result of the Evidence Gate.
    """

    if finding.status == FindingStatus.PROPOSED:
        return "PENDING"

    return finding.status.value


def build_evidence_tests(
    evidence: dict | None,
) -> list[dict]:
    """
    Translate the verifier's structured evidence into presentation data
    for finding_detail.html.
    """

    if not evidence:
        return []

    tests = evidence.get(
        "tests",
        {},
    )

    display_definitions = [

        (
            "baseline",
            "T-001",
            "Baseline request",
        ),

        (
            "true_condition",
            "T-002",
            "TRUE-condition SQL test",
        ),

        (
            "false_condition",
            "T-003",
            "FALSE-condition SQL test",
        ),
    ]

    result = []

    for (
        key,
        test_id,
        name,
    ) in display_definitions:

        test = tests.get(key)

        if not test:
            continue

        response = test.get(
            "response",
            {},
        )

        result.append({
            "test_id":
                test_id,

            "name":
                name,

            "result":
                "OBSERVED",

            "payload":
                test.get(
                    "payload",
                    "",
                ),

            "request":
                test.get(
                    "request_text",
                    "",
                ),

            "response": (
                f"HTTP status: "
                f"{response.get('status_code')}\n"
                f"Response length: "
                f"{response.get('response_length')}\n"
                f"Matched records: "
                f"{response.get('result_count')}\n"
                f"Database error detected: "
                f"{response.get('database_error_detected')}\n\n"
                f"{response.get('body_excerpt', '')}"
            ),

            "baseline":
                (
                    "Baseline request used to establish normal "
                    "application behaviour."
                    if key == "baseline"
                    else
                    f"Baseline matched records: "
                    f"{evidence['signals'].get('baseline_result_count')}"
                ),

            "observed":
                (
                    f"Observed matched records: "
                    f"{response.get('result_count')}"
                ),

            "observations": [],
        })

    return result


def build_evidence_summary(
    evidence: dict | None,
    gate_result: str,
) -> str | None:

    if not evidence:
        return None

    signals = evidence.get(
        "signals",
        {},
    )

    return (
        "Deterministic runtime verification completed against the "
        "local DVWA lab. "
        f"Baseline returned "
        f"{signals.get('baseline_result_count')} record(s), "
        f"the TRUE condition returned "
        f"{signals.get('true_result_count')} record(s), "
        f"and the FALSE condition returned "
        f"{signals.get('false_result_count')} record(s). "
        f"Evidence Gate result: {gate_result}."
    )


def build_view_model(
    finding: Finding,
) -> dict:

    metadata = FINDING_METADATA.get(
        finding.finding_id,
        {},
    )

    review = REVIEW_BY_FINDING.get(
        finding.finding_id,
        {},
    )

    evidence = EVIDENCE_BY_FINDING.get(
        finding.finding_id
    )

    verification_status = (
        verification_status_for(
            finding.finding_id
        )
    )

    gate_result = (
        evidence_gate_result_for(
            finding
        )
    )

    return {
        "finding_id":
            finding.finding_id,

        "finding_type":
            FINDING_TYPE_LABELS.get(
                finding.finding_type,
                finding.finding_type.value,
            ),

        "target":
            metadata.get(
                "target",
                "Local Lab",
            ),

        "source_file":
            metadata.get(
                "source_file",
                "Not available",
            ),

        "endpoint":
            finding.endpoint,

        "parameter":
            finding.parameter,

        "method":
            finding.method,

        "proposed_cwe":
            metadata.get(
                "proposed_cwe",
                "Not available",
            ),

        "reason":
            finding.explanation,

        # Candidate proposal remains visually distinct from verification.
        "llm_status":
            "PROPOSED",

        "proposal_source":
            metadata.get(
                "proposal_source",
                "PRELOADED",
            ),

        "suggested_severity":
            metadata.get(
                "suggested_severity",
                "Not assessed",
            ),

        "verification_status":
            verification_status,

        "evidence_gate_result":
            gate_result,

        "evidence_source":
            (
                "RUNTIME"
                if evidence
                else None
            ),

        "evidence_summary":
            build_evidence_summary(
                evidence,
                gate_result,
            ),

        "evidence":
            build_evidence_tests(
                evidence
            ),

        "run_id":
            (
                evidence.get("run_id")
                if evidence
                else None
            ),

        "timestamp_utc":
            (
                evidence.get(
                    "timestamp_utc"
                )
                if evidence
                else None
            ),

        "signals":
            (
                evidence.get(
                    "signals",
                    {}
                )
                if evidence
                else {}
            ),

        "reviewer_cwe":
            review.get(
                "reviewer_cwe",
                "",
            ),

        "final_severity":
            review.get(
                "final_severity",
                "",
            ),

        "reviewer_comment":
            review.get(
                "reviewer_comment",
                "",
            ),

        "human_decision":
            review.get(
                "human_decision"
            ),

        "verification_supported":
            (
                finding.finding_type
                == FindingType.SQL_INJECTION
            ),
    }


# ======================================================================
# ROOT
# ======================================================================

@app.route("/")
def home():

    return redirect(
        url_for("findings_list")
    )


# ======================================================================
# FINDINGS LIST
# ======================================================================

@app.route("/findings")
def findings_list():

    view_models = [

        build_view_model(finding)

        for finding
        in FINDINGS.values()
    ]

    return render_template(
        "findings_list.html",
        findings=view_models,
        active_page="findings",
    )


# ======================================================================
# FINDING DETAIL
# ======================================================================

@app.route(
    "/findings/<finding_id>"
)
def finding_detail(
    finding_id,
):

    finding = get_finding(
        finding_id
    )

    return render_template(
        "finding_detail.html",
        finding=build_view_model(
            finding
        ),
        active_page="findings",
    )


# ======================================================================
# RUN VERIFICATION
# ======================================================================

@app.route(
    "/findings/<finding_id>/verify",
    methods=["POST"],
)
def verify_finding(
    finding_id,
):

    finding = get_finding(
        finding_id
    )

    if (
        finding.finding_type
        != FindingType.SQL_INJECTION
    ):
        return jsonify({
            "ok": False,
            "error": (
                "Dynamic verification is currently implemented "
                "for SQL Injection only."
            ),
        }), 400

    try:

        evidence = (
            collect_sql_injection_evidence(
                finding
            )
        )

        gate_status = (
            evaluate_evidence(
                evidence
            )
        )

        # Canonical finding status comes from the Evidence Gate.
        finding.status = gate_status

        # Record gate result in the evidence artifact too.
        evidence["evidence_gate_result"] = (
            gate_status.value
        )

        json_file, csv_file = (
            save_evidence(
                evidence
            )
        )

        EVIDENCE_BY_FINDING[
            finding_id
        ] = evidence

        return jsonify({
            "ok":
                True,

            "finding_id":
                finding_id,

            "verification_status":
                "COMPLETED",

            "evidence_gate_result":
                gate_status.value,

            "run_id":
                evidence["run_id"],

            "json_artifact":
                str(json_file),

            "csv_artifact":
                str(csv_file),
        })

    except Exception as error:

        return jsonify({
            "ok": False,
            "error": str(error),
        }), 500


# ======================================================================
# HUMAN REVIEW
# ======================================================================

@app.route(
    "/findings/<finding_id>/review",
    methods=["POST"],
)
def update_review(
    finding_id,
):

    finding = get_finding(
        finding_id
    )

    data = (
        request.get_json(
            silent=True
        )
        or {}
    )

    field = data.get(
        "field"
    )

    value = data.get(
        "value"
    )

    if field not in ALLOWED_REVIEW_FIELDS:

        return jsonify({
            "ok": False,
            "error":
                f"Unknown review field: {field}",
        }), 400

    if field == "final_severity":

        if value not in ALLOWED_SEVERITIES:

            return jsonify({
                "ok": False,
                "error":
                    "Invalid severity value.",
            }), 400

    if field == "human_decision":

        # ----------------------------------------------------------
        # Backend enforcement:
        # Human decision is not allowed until independent runtime
        # verification has actually completed.
        # ----------------------------------------------------------

        if (
            finding_id
            not in EVIDENCE_BY_FINDING
        ):

            return jsonify({
                "ok": False,
                "error": (
                    "Human decision cannot be recorded before "
                    "independent verification has completed."
                ),
            }), 409

        if (
            value
            not in ALLOWED_HUMAN_DECISIONS
        ):

            return jsonify({
                "ok": False,
                "error":
                    "Invalid human decision.",
            }), 400

    REVIEW_BY_FINDING.setdefault(
        finding_id,
        {},
    )[field] = value

    return jsonify({
        "ok": True,
        "field": field,
        "value": value,
    })


# ======================================================================
# DEVELOPMENT SERVER
# ======================================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )