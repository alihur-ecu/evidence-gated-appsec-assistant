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

from pathlib import Path
from tempfile import TemporaryDirectory

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from app.analysis.analysis_service import run_static_analysis
from app.analysis.finding_adapter import adapt_analysis_result
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
# ANALYSIS RESULTS IN MEMORY
#
# Findings are populated by the configured analysis provider after the user
# starts an analysis. In the current Gabriel branch the default provider is
# MOCK. The same Finding model and downstream verification flow are preserved.
# ======================================================================

FINDINGS = {}
FINDING_METADATA = {}
ANALYSES = {}
LATEST_ANALYSIS_ID = None


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

            # Presentation-friendly fields used by finding_detail.html.
            # The original technical response remains preserved above.
            "result_count":
                response.get("result_count"),

            "status_code":
                response.get("status_code"),

            "database_error_detected":
                bool(response.get("database_error_detected", False)),

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




def register_analysis_result(analysis_result: dict) -> list[dict]:
    """Replace the current proposal set with findings from one analysis run."""
    global LATEST_ANALYSIS_ID

    FINDINGS.clear()
    FINDING_METADATA.clear()
    EVIDENCE_BY_FINDING.clear()
    REVIEW_BY_FINDING.clear()

    for finding, metadata in adapt_analysis_result(analysis_result):
        FINDINGS[finding.finding_id] = finding
        FINDING_METADATA[finding.finding_id] = metadata
        REVIEW_BY_FINDING[finding.finding_id] = {
            "final_severity": "",
            "reviewer_comment": "",
            "human_decision": None,
        }

    analysis_id = analysis_result["analysis_id"]
    ANALYSES[analysis_id] = analysis_result
    LATEST_ANALYSIS_ID = analysis_id

    return [build_view_model(finding) for finding in FINDINGS.values()]


# ======================================================================
# ROOT
# ======================================================================

@app.route("/")
def home():

    return render_template(
        "home.html",
        active_page="home",
    )




# ======================================================================
# START STATIC ANALYSIS
# ======================================================================

@app.route("/analysis/static", methods=["POST"])
def start_static_analysis():
    source_file = request.files.get("source_file")
    application_name = request.form.get("application_name", "").strip()
    authorised = request.form.get("authorised") == "true"

    if source_file is None or not source_file.filename:
        return jsonify({"ok": False, "error": "A source file is required."}), 400

    if not application_name:
        return jsonify({"ok": False, "error": "Application name is required."}), 400

    if not authorised:
        return jsonify({"ok": False, "error": "Authorisation confirmation is required."}), 400

    original_filename = Path(source_file.filename).name

    try:
        with TemporaryDirectory(prefix="eg_appsec_") as temp_dir:
            source_path = Path(temp_dir) / original_filename
            source_file.save(source_path)

            analysis_result = run_static_analysis(
                source_path=str(source_path),
                original_filename=original_filename,
                application_name=application_name,
            )

        findings = register_analysis_result(analysis_result)

        return jsonify({
            "ok": True,
            "analysis_id": analysis_result["analysis_id"],
            "provider": analysis_result["provider"],
            "fixture_recognised": analysis_result.get("fixture_recognised", False),
            "finding_count": len(findings),
            "redirect_url": url_for(
                "analysis_results",
                analysis_id=analysis_result["analysis_id"],
            ),
        })
    except Exception as error:
        return jsonify({"ok": False, "error": str(error)}), 500


@app.route("/analysis/<analysis_id>/results")
def analysis_results(analysis_id):
    analysis = ANALYSES.get(analysis_id)

    if analysis is None:
        abort(404)

    findings = [
        build_view_model(finding)
        for finding in FINDINGS.values()
        if FINDING_METADATA.get(finding.finding_id, {}).get("analysis_id") == analysis_id
    ]

    return render_template(
        "analysis_results.html",
        analysis=analysis,
        findings=findings,
        active_page="findings",
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