"""
Flask web application for the Evidence-Gated AppSec Finding Assistant.

Application architecture:

Authorised target
        ↓
Discovery / analysis
        ↓
AI candidate proposal
        ↓
Deterministic runtime verification
        ↓
PROVED / REFUTED / NEEDS_HUMAN
        ↓
Human Review

Production verification is target-driven. No application, domain, endpoint,
parameter, authentication mechanism, or laboratory environment is hardcoded
in this web layer. Local labs are used only by dedicated validation scripts.
"""

from __future__ import annotations

from pathlib import Path
from dataclasses import replace
from urllib.parse import urljoin, urlsplit, parse_qs
from tempfile import TemporaryDirectory, mkdtemp
import csv
import json
import uuid
import time
import os
import shutil
import threading


def _load_local_env() -> None:
    """Load missing environment variables from the project .env file.

    The browser selects the LLM provider per analysis request. Environment
    credentials provide a fallback when a request does not include a key.
    Existing process environment variables take precedence over .env values.
    """
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.is_file():
        return

    try:
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            if not key:
                continue

            if (
                len(value) >= 2
                and value[0] == value[-1]
                and value[0] in {"\"", "'"}
            ):
                value = value[1:-1]

            os.environ.setdefault(key, value)
    except OSError:
        # Environment loading is a convenience for local development. The
        # provider layer remains responsible for reporting missing secrets.
        return


_load_local_env()

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
from app.analysis.providers.static_source_provider import run_static_source_analysis
from app.analysis.static_pipeline import run_static_proposal_pipeline
from app.analysis.proposers.factory import create_static_proposer
from app.dynamic_analysis.pipeline import run_dynamic_analysis
from app.dynamic_analysis.discovery import DynamicDiscovery
from app.dynamic_analysis.context_builder import DynamicContextBuilder
from app.dynamic_analysis.authentication import (
    AUTH_FORM,
    AUTH_NONE,
    DynamicAuthenticationError,
    create_analysis_session,
    normalise_authentication_mode,
)
from app.analysis.finding_adapter import adapt_analysis_result

from app.models.finding import (
    Finding,
    FindingStatus,
    FindingType,
)

from app.dynamic_analysis.verification_service import (
    DynamicVerificationService,
    DynamicVerificationError,
)
from app.static_verification_service import (
    StaticVerificationService,
    StaticVerificationError,
)

from app.dynamic_analysis.verification_router import (
    VerificationReadiness,
    route_finding_for_verification,
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

# In-memory HTTP sessions are intentionally separate from analysis metadata.
# Credentials are never stored. A session is retained only so deterministic
# verification can reuse the same authorised access context as discovery.
ANALYSIS_SESSIONS = {}


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

    This is intentionally different from the deterministic verifier result.

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
    Finding.status reflects the canonical deterministic verification result.
    """

    if finding.status == FindingStatus.PROPOSED:
        return "PENDING"

    return finding.status.value


def build_evidence_tests(
    evidence: dict | None,
) -> list[dict]:
    """Translate runtime observations into presentation data.

    Phase 3E stores generic EvidenceBundle observations. A small legacy
    fallback is retained so older in-memory evidence can still render during
    development without affecting the new verification path.
    """

    if not evidence:
        return []

    observations = evidence.get("observations")

    if evidence.get("evidence_source") == "STATIC" and isinstance(observations, list):
        return [
            {
                "test_id": observation.get("observation_id", f"S-{index:03d}"),
                "name": observation.get("name") or str(observation.get("label", "Source observation")).replace("_", " ").title(),
                "result": observation.get("result", "OBSERVED"),
                "payload": "",
                "request": observation.get("detail", ""),
                "response": observation.get("source_excerpt", ""),
                "baseline": observation.get("detail", ""),
                "observed": observation.get("detail", ""),
                "result_count": None,
                "status_code": None,
                "database_error_detected": False,
                "observations": [],
                "source_lines": observation.get("source_lines", []),
                "source_metadata": observation.get("metadata", {}),
            }
            for index, observation in enumerate(observations, start=1)
        ]

    if isinstance(observations, list):
        result = []

        for index, observation in enumerate(observations, start=1):
            metadata = observation.get("metadata", {})
            label = str(observation.get("label", f"OBSERVATION_{index}"))
            is_baseline = (
                observation.get("observation_id")
                == evidence.get("baseline_observation_id")
            )

            test_value = metadata.get("test_value")
            if test_value in (None, ""):
                parameter_name = str(evidence.get("parameter", "") or "").strip()
                observation_url = str(observation.get("url", "") or "")
                if parameter_name and observation_url:
                    query_values = parse_qs(
                        urlsplit(observation_url).query,
                        keep_blank_values=True,
                    ).get(parameter_name, [])
                    if query_values:
                        test_value = query_values[0]

            result.append({
                "test_id": f"T-{index:03d}",
                "name": (
                    "Baseline request"
                    if is_baseline
                    else label.replace("_", " " ).title()
                ),
                "result": "OBSERVED",
                "payload": "" if test_value is None else str(test_value),
                "error_family": metadata.get("error_family"),
                "error_signature": metadata.get("error_signature"),
                "is_baseline": is_baseline,
                "request": (
                    f"{observation.get('method', '')} "
                    f"{observation.get('url', '')}"
                ).strip(),
                "response": (
                    f"HTTP status: {observation.get('status_code')}\n"
                    f"Response length: {observation.get('response_length')}\n"
                    f"Response digest: {observation.get('response_digest')}\n"
                    f"Error detected: {metadata.get('error_detected')}\n"
                    f"Error family: {metadata.get('error_family')}\n"
                    f"Error signature: {metadata.get('error_signature')}"
                ),
                "baseline": (
                    "Functional baseline used to establish normal "
                    "application behaviour."
                    if is_baseline
                    else "Compared with the functional baseline."
                ),
                "observed": (
                    f"Error detected: {metadata.get('error_detected', False)}"
                ),
                "result_count": None,
                "status_code": observation.get("status_code"),
                "database_error_detected": bool(
                    metadata.get("error_detected", False)
                ),
                "observations": [],
            })

        return result

    # Legacy development evidence fallback.
    tests = evidence.get("tests", {})
    display_definitions = [
        ("baseline", "T-001", "Baseline request"),
        ("true_condition", "T-002", "TRUE-condition SQL test"),
        ("false_condition", "T-003", "FALSE-condition SQL test"),
    ]

    result = []
    for key, test_id, name in display_definitions:
        test = tests.get(key)
        if not test:
            continue
        response = test.get("response", {})
        result.append({
            "test_id": test_id,
            "name": name,
            "result": "OBSERVED",
            "payload": test.get("payload", ""),
            "request": test.get("request_text", ""),
            "response": (
                f"HTTP status: {response.get('status_code')}\n"
                f"Response length: {response.get('response_length')}\n"
                f"Matched records: {response.get('result_count')}\n"
                f"Database error detected: "
                f"{response.get('database_error_detected')}\n\n"
                f"{response.get('body_excerpt', '')}"
            ),
            "baseline": (
                "Baseline request used to establish normal "
                "application behaviour."
                if key == "baseline"
                else "Compared with the baseline request."
            ),
            "observed": (
                f"Observed matched records: {response.get('result_count')}"
            ),
            "result_count": response.get("result_count"),
            "status_code": response.get("status_code"),
            "database_error_detected": bool(
                response.get("database_error_detected", False)
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

    verification = evidence.get("verification", {})
    reasons = verification.get("reasons", [])

    evidence_kind = (
        "source-code"
        if evidence.get("evidence_source") == "STATIC"
        else "runtime"
    )

    if reasons:
        return (
            f"Deterministic {evidence_kind} verification completed. "
            f"Result: {gate_result}. "
            + " ".join(str(reason) for reason in reasons)
        )

    return (
        f"Deterministic {evidence_kind} verification completed. "
        f"Result: {gate_result}."
    )


def build_web_evidence(result) -> dict:
    """Adapt a Phase 3E service result to the existing web contract."""

    evidence = result.evidence.to_dict()
    verification = result.verification.to_dict()

    evidence["finding_id"] = result.finding_id
    evidence["run_id"] = result.evidence.evidence_id
    evidence["timestamp_utc"] = result.evidence.collected_at_utc
    evidence["execution_status"] = "COMPLETED"
    evidence["evidence_gate_result"] = result.finding_status.value
    evidence["verification"] = verification

    return evidence


def save_web_evidence(
    evidence: dict,
) -> tuple[Path, Path]:
    """Persist generic Phase 3E evidence without DVWA-specific fields."""

    artifacts_dir = Path("artifacts") / "runs"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    run_id = evidence["run_id"]
    json_file = artifacts_dir / f"{run_id}_runtime_evidence.json"

    with json_file.open("w", encoding="utf-8") as file:
        json.dump(evidence, file, indent=2)

    csv_file = artifacts_dir / "runtime_evidence_results.csv"
    verification = evidence.get("verification", {})
    csv_row = {
        "run_id": run_id,
        "finding_id": evidence.get("finding_id"),
        "timestamp_utc": evidence.get("timestamp_utc"),
        "endpoint": evidence.get("endpoint"),
        "method": evidence.get("method"),
        "parameter": evidence.get("parameter"),
        "capability": evidence.get("capability"),
        "verifier_id": verification.get("verifier_id"),
        "decision": verification.get("decision"),
        "observation_count": len(evidence.get("observations", [])),
    }

    file_exists = csv_file.exists()
    with csv_file.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=csv_row.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(csv_row)

    return json_file, csv_file


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

    verification_route = (
        route_finding_for_verification(
            finding
        )
    )

    return {
        "finding_id":
            finding.finding_id,

        "scan_type":
            finding.scan_type.value,

        "finding_type":
            FINDING_TYPE_LABELS.get(
                finding.finding_type,
                finding.finding_type.value,
            ),

        "target":
            metadata.get(
                "target",
                "Not available",
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
                evidence.get("evidence_source", "RUNTIME")
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

        # Verification availability is capability-driven. The web layer
        # does not decide support from a vulnerability-specific if/elif chain.
        "verification_supported":
            verification_route.can_verify,

        "runtime_verification_supported":
            (
                verification_route.can_verify
                and verification_route.mode is not None
                and verification_route.mode.value == "RUNTIME"
            ),

        "static_verification_supported":
            (
                verification_route.can_verify
                and verification_route.mode is not None
                and verification_route.mode.value == "STATIC"
            ),

        "static_verification_pending":
            (
                finding.scan_type.value == "STATIC"
                and not verification_route.can_verify
            ),

        "verification_readiness":
            verification_route.readiness.value,

        "verification_capability":
            verification_route.capability_id,

        "verification_verifier":
            verification_route.verifier_id,

        "verification_mode":
            (
                verification_route.mode.value
                if verification_route.mode
                else None
            ),

        "verification_missing_fields":
            list(
                verification_route.missing_fields
            ),

        "verification_reason":
            verification_route.reason,
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


def prepare_dynamic_analysis_result(
    dynamic_result: dict,
    *,
    application_name: str,
    analysis_scope: str = "",
) -> dict:
    """
    Adapt the generic dynamic pipeline result to the existing web-analysis
    result contract without changing the dynamic pipeline itself.

    Candidate proposals remain PROPOSED. No verification result is invented.
    """

    analysis_id = f"D-{uuid.uuid4().hex[:8].upper()}"

    target = dynamic_result.get("target", {})
    target_url = (
        target.get("base_url")
        or target.get("original_url")
        or "Not available"
    )

    findings = []

    for proposal in dynamic_result.get("proposals", []):
        item = dict(proposal)

        # Existing finding_adapter consumes the common proposal fields.
        # Dynamic-only reporting metadata is added without changing the
        # proposal's security conclusion.
        item.setdefault("scan_type", "DYNAMIC")
        item.setdefault("source_file", "Runtime observation")
        item.setdefault("endpoint", target_url)
        item.setdefault("method", "GET")
        item.setdefault("parameter", None)
        item.setdefault(
            "proposal_source",
            dynamic_result.get(
                "proposal_provider",
                "UNKNOWN",
            ),
        )

        findings.append(item)

    return {
        "analysis_id": analysis_id,
        "provider": dynamic_result.get(
            "proposal_provider",
            "UNKNOWN",
        ),
        "proposal_provider": dynamic_result.get(
            "proposal_provider",
            "UNKNOWN",
        ),
        "application_name": application_name,
        "analysis_scope": analysis_scope,
        "analysis_type": "DYNAMIC",
        "scan_type": "DYNAMIC",
        "context_source": "DYNAMIC_DISCOVERY",
        "source_file": "Runtime target",
        "target": target_url,
        "message": (
            "Dynamic discovery and LLM proposal generation completed. "
            "Candidate findings remain unverified until independent "
            "runtime evidence is collected."
        ),
        "target_details": target,
        "discovery": dynamic_result.get(
            "discovery",
            {},
        ),
        "context_build": dynamic_result.get(
            "context_build",
            {},
        ),
        "findings": findings,
        "proposals": findings,
    }


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
# ASYNCHRONOUS ANALYSIS JOBS / REAL PROGRESS
# ======================================================================

ANALYSIS_JOBS: dict[str, dict] = {}
ANALYSIS_JOB_RUNTIME: dict[str, dict] = {}
ANALYSIS_JOBS_LOCK = threading.Lock()


def _job_update(job_id: str, **changes) -> None:
    with ANALYSIS_JOBS_LOCK:
        job = ANALYSIS_JOBS.get(job_id)
        if job is not None:
            job.update(changes)


def _job_snapshot(job_id: str) -> dict | None:
    with ANALYSIS_JOBS_LOCK:
        job = ANALYSIS_JOBS.get(job_id)
        if job is None:
            return None
        snapshot = dict(job)
        runtime = ANALYSIS_JOB_RUNTIME.get(job_id, {})
        tracker = runtime.get("tracker")

    if tracker is not None:
        live = tracker.live_progress()
        if live:
            snapshot.update(live)
    return snapshot


class _ProgressTrackingProposer:
    """Transparent proposer wrapper exposing real item-by-item LLM progress."""

    def __init__(self, proposer, job_id: str):
        self._proposer = proposer
        self._job_id = job_id
        self.provider_name = getattr(proposer, "provider_name", proposer.__class__.__name__)
        self.total_items = 0
        self.item_label = "item"
        self.active = False

    def __getattr__(self, name):
        return getattr(self._proposer, name)

    @property
    def last_execution_report(self):
        return getattr(self._proposer, "last_execution_report", None)

    def _begin(self, total: int, label: str) -> None:
        self.total_items = max(int(total), 0)
        self.item_label = label
        self.active = True
        _job_update(
            self._job_id,
            stage="LLM_PROPOSAL",
            stage_label="LLM proposal analysis",
            message=(
                f"LLM proposal analysis started — {self.total_items} "
                f"{label}{'' if self.total_items == 1 else 's'} selected."
            ),
            llm_total=self.total_items,
            llm_completed=0,
            progress=40,
        )

    def _finish(self) -> None:
        report = self.last_execution_report or {}
        completed = int(report.get("chunks_succeeded", 0) or 0) + int(report.get("chunks_failed", 0) or 0)
        self.active = False
        _job_update(
            self._job_id,
            llm_completed=min(completed, self.total_items),
            progress=100,
            message="LLM proposal analysis complete.",
        )

    def live_progress(self) -> dict:
        if not self.active or self.total_items <= 0:
            return {}
        report = self.last_execution_report or {}
        attempted = int(report.get("chunks_attempted", 0) or 0)
        completed = int(report.get("chunks_succeeded", 0) or 0) + int(report.get("chunks_failed", 0) or 0)
        completed = min(completed, self.total_items)
        current = min(max(attempted, completed), self.total_items)
        fraction = completed / self.total_items
        return {
            "stage": "LLM_PROPOSAL",
            "stage_label": "LLM proposal analysis",
            "progress": min(99, 40 + round(59 * fraction)),
            "llm_completed": completed,
            "llm_total": self.total_items,
            "llm_current": current,
            "message": (
                f"LLM proposal analysis — {completed} of {self.total_items} {self.item_label}s completed"
                + (f"; processing {self.item_label} {current}." if current > completed else ".")
            ),
        }

    def propose(self, *, application_name, chunks):
        self._begin(len(chunks), "chunk")
        try:
            return self._proposer.propose(application_name=application_name, chunks=chunks)
        finally:
            self._finish()

    def propose_contexts(self, *, application_name, contexts):
        valid = [item for item in contexts if getattr(item, "content", "") and str(item.content).strip()]
        self._begin(len(valid), "context")
        try:
            return self._proposer.propose_contexts(application_name=application_name, contexts=contexts)
        finally:
            self._finish()


def _run_static_job(job_id: str, source_path: str, original_filename: str, application_name: str, llm_provider: str, llm_api_key: str | None, temp_dir: str) -> None:
    try:
        _job_update(job_id, status="RUNNING", stage="SOURCE_PREPARATION", stage_label="Source preparation", progress=10, message="Preparing bounded source context...")
        provider_name = os.getenv("ANALYSIS_PROVIDER", "mock").strip().lower()

        if provider_name == "static_source":
            prepared = run_static_source_analysis(
                source_path=source_path,
                original_filename=original_filename,
                application_name=application_name,
            )
            _job_update(job_id, stage="CONTEXT_PREPARATION", stage_label="Context collection", progress=35, message="Source context collected. Applying the LLM execution budget...")
            proposer = create_static_proposer(provider_name=llm_provider, api_key=llm_api_key)
            tracker = _ProgressTrackingProposer(proposer, job_id)
            with ANALYSIS_JOBS_LOCK:
                ANALYSIS_JOB_RUNTIME[job_id] = {"tracker": tracker}
            analysis_result = run_static_proposal_pipeline(prepared_analysis=prepared, proposer=tracker)
            analysis_result["analysis_id"] = f"A-{uuid.uuid4().hex[:8].upper()}"
        else:
            # Preserve the existing mock/alternate analysis path unchanged.
            _job_update(job_id, progress=35, message="Prepared analysis is being processed...")
            analysis_result = run_static_analysis(
                source_path=source_path,
                original_filename=original_filename,
                application_name=application_name,
                llm_provider=llm_provider,
                llm_api_key=llm_api_key,
            )

        proposal_status = str(analysis_result.get("proposal_status", "SUCCESS")).upper()
        if proposal_status == "FAILED":
            raise RuntimeError("The selected LLM proposal stage could not complete.")

        findings = register_analysis_result(analysis_result)
        _job_update(
            job_id,
            status="COMPLETED",
            stage="COMPLETED",
            stage_label="Analysis complete",
            progress=100,
            finding_count=len(findings),
            provider=analysis_result.get("proposal_provider") or analysis_result.get("provider") or llm_provider.upper(),
            redirect_url=f"/analysis/{analysis_result['analysis_id']}/results",
            message=f"Analysis complete — {len(findings)} proposed finding(s).",
        )
    except Exception as error:
        app.logger.exception("Static analysis job failed")
        _job_update(job_id, status="FAILED", stage="FAILED", stage_label="Analysis failed", error=str(error), message=str(error))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


class _ProgressDiscovery:
    def __init__(self, discovery, job_id: str):
        self._discovery = discovery
        self._job_id = job_id

    def __getattr__(self, name):
        return getattr(self._discovery, name)

    def discover(self, target):
        result = self._discovery.discover(target)
        _job_update(
            self._job_id,
            stage="CONTEXT_PREPARATION",
            stage_label="Context preparation",
            progress=32,
            message=(
                f"Runtime discovery complete — {len(result.pages)} page(s), "
                f"{len(result.endpoints)} endpoint(s), {len(result.forms)} form(s). "
                "Building bounded analysis context..."
            ),
        )
        return result


class _ProgressContextBuilder:
    def __init__(self, builder, job_id: str):
        self._builder = builder
        self._job_id = job_id

    def __getattr__(self, name):
        return getattr(self._builder, name)

    def build(self, discovery_result):
        result = self._builder.build(discovery_result)
        _job_update(
            self._job_id,
            stage="CONTEXT_PREPARATION",
            stage_label="Context preparation",
            progress=39,
            message=(
                f"Context preparation complete — {result.contexts_selected} "
                f"of {result.contexts_created} context(s) selected for LLM analysis."
            ),
        )
        return result


def _run_dynamic_job(job_id: str, *, target_url: str, application_name: str, analysis_scope: str, authentication_mode: str, username: str, password: str, llm_provider: str | None, llm_api_key: str | None) -> None:
    try:
        _job_update(job_id, status="RUNNING", stage="TARGET_VALIDATION", stage_label="Target validation", progress=5, message="Target received and validated.")
        _job_update(job_id, stage="AUTHENTICATION", stage_label="Authentication" if authentication_mode == AUTH_FORM else "Session preparation", progress=12, message="Preparing the authorised analysis session...")
        analysis_session, auth_result = create_analysis_session(
            target_url=target_url,
            authentication_mode=authentication_mode,
            username=username if authentication_mode == AUTH_FORM else None,
            password=password if authentication_mode == AUTH_FORM else None,
        )
        _job_update(job_id, stage="DISCOVERY", stage_label="Runtime discovery", progress=20, message="Discovering the authorised runtime surface...")
        discovery = _ProgressDiscovery(DynamicDiscovery(session=analysis_session), job_id)
        context_builder = _ProgressContextBuilder(DynamicContextBuilder(), job_id)
        proposer = create_static_proposer(provider_name=llm_provider, api_key=llm_api_key)
        tracker = _ProgressTrackingProposer(proposer, job_id)
        with ANALYSIS_JOBS_LOCK:
            ANALYSIS_JOB_RUNTIME[job_id] = {"tracker": tracker}

        dynamic_result = run_dynamic_analysis(
            target_url=target_url,
            application_name=application_name,
            discovery=discovery,
            context_builder=context_builder,
            proposer=tracker,
        )
        proposal_status = str(dynamic_result.get("proposal_status", "SUCCESS")).upper()
        if proposal_status == "FAILED":
            raise RuntimeError("Runtime discovery completed, but the LLM proposal stage could not complete.")

        analysis_result = prepare_dynamic_analysis_result(dynamic_result, application_name=application_name, analysis_scope=analysis_scope)
        analysis_result["authentication"] = auth_result.to_dict()
        analysis_result["authentication_mode"] = auth_result.mode
        findings = register_analysis_result(analysis_result)
        analysis_id = analysis_result["analysis_id"]
        ANALYSIS_SESSIONS.clear()
        ANALYSIS_SESSIONS[analysis_id] = analysis_session
        discovery_result = dynamic_result.get("discovery", {})
        _job_update(
            job_id,
            status="COMPLETED",
            stage="COMPLETED",
            stage_label="Analysis complete",
            progress=100,
            finding_count=len(findings),
            provider=dynamic_result.get("proposal_provider", "UNKNOWN"),
            redirect_url=f"/analysis/{analysis_id}/results",
            discovery_summary={
                "pages": len(discovery_result.get("pages", [])),
                "endpoints": len(discovery_result.get("endpoints", [])),
                "forms": len(discovery_result.get("forms", [])),
                "errors": len(discovery_result.get("errors", [])),
            },
            message=f"Analysis complete — {len(findings)} proposed finding(s).",
        )
    except Exception as error:
        app.logger.exception("Dynamic analysis job failed")
        _job_update(job_id, status="FAILED", stage="FAILED", stage_label="Analysis failed", error=str(error), message=str(error))


@app.route("/analysis/jobs/<job_id>", methods=["GET"])
def analysis_job_status(job_id):
    snapshot = _job_snapshot(job_id)
    if snapshot is None:
        return jsonify({"ok": False, "error": "Analysis job was not found."}), 404
    return jsonify({"ok": True, **snapshot})


@app.route("/analysis/static/job", methods=["POST"])
def start_static_analysis_job():
    source_file = request.files.get("source_file")
    application_name = request.form.get("application_name", "").strip()
    authorised = request.form.get("authorised") == "true"
    llm_provider = request.form.get("llm_provider", "").strip().lower()
    llm_api_key = request.form.get("llm_api_key", "").strip() or None
    if not llm_provider or llm_provider not in {"openai", "gemini", "lmstudio"}:
        return jsonify({"ok": False, "error": "Choose a supported LLM provider: OpenAI, Gemini, or LM Studio."}), 400
    if source_file is None or not source_file.filename:
        return jsonify({"ok": False, "error": "A source file is required."}), 400
    if not application_name:
        return jsonify({"ok": False, "error": "Application name is required."}), 400
    if not authorised:
        return jsonify({"ok": False, "error": "Authorisation confirmation is required."}), 400

    original_filename = Path(source_file.filename).name
    temp_path = mkdtemp(prefix="eg_appsec_job_")
    source_path = Path(temp_path) / original_filename
    source_file.save(source_path)
    job_id = f"J-{uuid.uuid4().hex[:10].upper()}"
    _job_update(job_id)  # no-op until inserted
    with ANALYSIS_JOBS_LOCK:
        ANALYSIS_JOBS[job_id] = {"job_id": job_id, "status": "QUEUED", "stage": "UPLOAD_RECEIVED", "stage_label": "Upload received", "progress": 5, "message": "Upload received. Starting analysis...", "analysis_type": "STATIC"}
    threading.Thread(target=_run_static_job, kwargs=dict(job_id=job_id, source_path=str(source_path), original_filename=original_filename, application_name=application_name, llm_provider=llm_provider, llm_api_key=llm_api_key, temp_dir=temp_path), daemon=True).start()
    return jsonify({"ok": True, "job_id": job_id}), 202


@app.route("/analysis/dynamic/job", methods=["POST"])
def start_dynamic_analysis_job():
    data = request.get_json(silent=True) or request.form
    target_url = str(data.get("target_url", "")).strip()
    application_name = str(data.get("application_name", "")).strip() or target_url
    analysis_scope = str(data.get("analysis_scope", "")).strip()
    llm_provider = str(data.get("llm_provider", "")).strip().lower() or None
    llm_api_key = str(data.get("llm_api_key", "")).strip() or None
    authorised = data.get("authorised") is True or str(data.get("authorised")).lower() == "true"
    try:
        authentication_mode = normalise_authentication_mode(data.get("authentication_mode", AUTH_NONE))
    except DynamicAuthenticationError as error:
        return jsonify({"ok": False, "error": str(error)}), 400
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    if not target_url:
        return jsonify({"ok": False, "error": "Target URL is required."}), 400
    if not analysis_scope:
        return jsonify({"ok": False, "error": "Analysis scope is required."}), 400
    if not authorised:
        return jsonify({"ok": False, "error": "Authorisation confirmation is required."}), 400
    if llm_provider not in {"openai", "gemini", "lmstudio"}:
        return jsonify({"ok": False, "error": "Choose a supported LLM provider: OpenAI, Gemini, or LM Studio."}), 400
    if authentication_mode == AUTH_FORM and (not username or not password):
        return jsonify({"ok": False, "error": "Username and password are required for authenticated analysis."}), 400

    job_id = f"J-{uuid.uuid4().hex[:10].upper()}"
    with ANALYSIS_JOBS_LOCK:
        ANALYSIS_JOBS[job_id] = {"job_id": job_id, "status": "QUEUED", "stage": "TARGET_RECEIVED", "stage_label": "Target received", "progress": 3, "message": "Target received. Starting analysis...", "analysis_type": "DYNAMIC"}
    threading.Thread(target=_run_dynamic_job, kwargs=dict(job_id=job_id, target_url=target_url, application_name=application_name, analysis_scope=analysis_scope, authentication_mode=authentication_mode, username=username, password=password, llm_provider=llm_provider, llm_api_key=llm_api_key), daemon=True).start()
    return jsonify({"ok": True, "job_id": job_id}), 202


# ======================================================================
# START STATIC ANALYSIS
# ======================================================================

@app.route("/analysis/static", methods=["POST"])
def start_static_analysis():
    source_file = request.files.get("source_file")
    application_name = request.form.get("application_name", "").strip()
    authorised = request.form.get("authorised") == "true"
    llm_provider = request.form.get("llm_provider", "").strip().lower()
    llm_api_key = request.form.get("llm_api_key", "").strip() or None

    # The UI requires an explicit provider. Do not silently fall back to the
    # process-level LLM_PROVIDER because that would make the user selection
    # non-transparent.
    if not llm_provider:
        return jsonify({
            "ok": False,
            "error": "Choose an LLM provider: OpenAI or Gemini.",
        }), 400

    if llm_provider is not None and llm_provider not in {"openai", "gemini", "lmstudio"}:
        return jsonify({
            "ok": False,
            "error": "Choose a supported LLM provider: OpenAI or Gemini.",
        }), 400

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
                llm_provider=llm_provider,
                llm_api_key=llm_api_key,
            )

        proposal_status = str(analysis_result.get("proposal_status", "SUCCESS")).upper()
        proposal_execution = analysis_result.get("proposal_execution") or {}
        if proposal_status == "FAILED":
            failed_chunks = proposal_execution.get("failed_chunks", []) or []
            first_failure = failed_chunks[0] if failed_chunks else {}
            status_code = first_failure.get("status_code")
            if status_code == 429:
                message = (
                    "Static source preparation completed, but the selected LLM "
                    "provider reached its rate limit. No security conclusion has "
                    "been made. Please retry later or choose another provider."
                )
                http_status = 429
                code = "LLM_RATE_LIMITED"
            else:
                message = (
                    "Static source preparation completed, but the selected LLM "
                    "proposal stage could not complete. No security conclusion "
                    "has been made."
                )
                http_status = 502
                code = "LLM_PROPOSAL_FAILED"
            return jsonify({
                "ok": False,
                "stage": "PROPOSAL_FAILED",
                "code": code,
                "error": message,
                "provider": analysis_result.get("proposal_provider") or llm_provider.upper(),
                "source_preparation_completed": True,
            }), http_status

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
        print(
        f"[STATIC] FAILED: {type(error).__name__}: {error}",
        flush=True,
    )

    return jsonify({
        "ok": False,
        "error": (
            "Static analysis could not complete with the selected provider."
            if llm_api_key else str(error)
        ),
    }), 500


# ======================================================================
# START DYNAMIC ANALYSIS
# ======================================================================

@app.route("/analysis/dynamic", methods=["POST"])
def start_dynamic_analysis():
    request_started = time.perf_counter()

    def trace(step: str) -> None:
        elapsed = time.perf_counter() - request_started
        print(f"[DYNAMIC] {elapsed:8.3f}s | {step}", flush=True)

    trace("1. Request received")
    data = request.get_json(silent=True) or request.form

    target_url = str(data.get("target_url", "")).strip()
    application_name = str(data.get("application_name", "")).strip()
    analysis_scope = str(data.get("analysis_scope", "")).strip()
    llm_provider = str(data.get("llm_provider", "")).strip().lower() or None
    llm_api_key = str(data.get("llm_api_key", "")).strip() or None

    if llm_provider is not None and llm_provider not in {"openai", "gemini", "lmstudio"}:
        return jsonify({
            "ok": False,
            "error": "Choose a supported LLM provider: OpenAI, Gemini, or LM Studio.",
        }), 400

    authorised_value = data.get("authorised")
    authorised = (
        authorised_value is True
        or str(authorised_value).lower() == "true"
    )

    try:
        authentication_mode = normalise_authentication_mode(
            data.get("authentication_mode", AUTH_NONE)
        )
    except DynamicAuthenticationError as error:
        trace(f"FAILED while normalising authentication mode: {error}")
        return jsonify({"ok": False, "error": str(error)}), 400

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    trace(
        "2. Request parsed "
        f"(target={target_url!r}, auth_mode={authentication_mode!r}, "
        f"username_supplied={bool(username)}, password_supplied={bool(password)})"
    )

    if not target_url:
        return jsonify({"ok": False, "error": "Target URL is required."}), 400

    if not application_name:
        application_name = target_url

    if not analysis_scope:
        return jsonify({"ok": False, "error": "Analysis scope is required."}), 400

    if not authorised:
        return jsonify({
            "ok": False,
            "error": "Authorisation confirmation is required.",
        }), 400

    if authentication_mode == AUTH_FORM and (not username or not password):
        return jsonify({
            "ok": False,
            "error": (
                "Username and password are required for authenticated analysis."
            ),
        }), 400

    trace("3. Input validation complete")

    try:
        trace("4. Creating analysis session / starting authentication")
        stage_started = time.perf_counter()
        analysis_session, auth_result = create_analysis_session(
            target_url=target_url,
            authentication_mode=authentication_mode,
            username=username if authentication_mode == AUTH_FORM else None,
            password=password if authentication_mode == AUTH_FORM else None,
        )
        trace(
            "5. Authentication/session complete "
            f"({time.perf_counter() - stage_started:.3f}s; "
            f"authenticated={auth_result.authenticated})"
        )

        trace("6. Creating DynamicDiscovery with authenticated session")
        discovery = DynamicDiscovery(
            session=analysis_session,
        )

        trace("7. Starting dynamic pipeline (discovery -> context -> proposals)")
        stage_started = time.perf_counter()
        dynamic_result = run_dynamic_analysis(
            target_url=target_url,
            application_name=application_name,
            discovery=discovery,
            provider_name=llm_provider,
            api_key=llm_api_key,
        )
        trace(
            "8. Dynamic pipeline complete "
            f"({time.perf_counter() - stage_started:.3f}s)"
        )

        discovery_result = dynamic_result.get("discovery", {})

        proposal_execution = dynamic_result.get("proposal_execution")
        proposal_status = str(dynamic_result.get("proposal_status", "SUCCESS")).upper()
        if isinstance(proposal_execution, dict):
            attempted = int(proposal_execution.get("chunks_attempted", 0) or 0)
            succeeded = int(proposal_execution.get("chunks_succeeded", 0) or 0)
            failed = int(proposal_execution.get("chunks_failed", 0) or 0)
            if proposal_status == "FAILED" or (attempted > 0 and failed > 0 and succeeded == 0):
                failed_chunks = proposal_execution.get("failed_chunks", []) or []
                first_failure = failed_chunks[0] if failed_chunks else {}
                status_code = first_failure.get("status_code")
                error_type = first_failure.get("error_type", "ProviderError")
                if status_code == 429:
                    user_message = (
                        "Runtime discovery completed, but the AI proposal stage "
                        "could not complete because the configured LLM provider "
                        "reached its rate limit. No security conclusion has been made. "
                        "Please retry later."
                    )
                    http_status = 429
                    code = "LLM_RATE_LIMITED"
                else:
                    user_message = (
                        "Runtime discovery completed, but the AI proposal stage "
                        "could not complete. No security conclusion has been made. "
                        "Please retry the analysis."
                    )
                    http_status = 502
                    code = "LLM_PROPOSAL_FAILED"
                trace(
                    "9. Proposal stage failed "
                    f"(attempted={attempted}, failed={failed}, "
                    f"status={status_code}, type={error_type})"
                )
                return jsonify({
                    "ok": False,
                    "stage": "PROPOSAL_FAILED",
                    "code": code,
                    "error": user_message,
                    "provider": dynamic_result.get("proposal_provider", "UNKNOWN"),
                    "discovery_completed": True,
                    "discovery_summary": {
                        "pages": len(discovery_result.get("pages", [])),
                        "endpoints": len(discovery_result.get("endpoints", [])),
                        "forms": len(discovery_result.get("forms", [])),
                        "errors": len(discovery_result.get("errors", [])),
                    },
                }), http_status

        trace(
            "9. Pipeline summary: "
            f"pages={len(discovery_result.get('pages', []))}, "
            f"endpoints={len(discovery_result.get('endpoints', []))}, "
            f"forms={len(discovery_result.get('forms', []))}, "
            f"errors={len(discovery_result.get('errors', []))}, "
            f"proposals={len(dynamic_result.get('proposals', []))}, "
            f"provider={dynamic_result.get('proposal_provider', 'UNKNOWN')}"
        )

        trace("10. Preparing web analysis result")
        analysis_result = prepare_dynamic_analysis_result(
            dynamic_result,
            application_name=application_name,
            analysis_scope=analysis_scope,
        )

        # Only non-secret authentication metadata is reportable.
        analysis_result["authentication"] = auth_result.to_dict()
        analysis_result["authentication_mode"] = auth_result.mode

        trace("11. Registering candidate findings")
        findings = register_analysis_result(
            analysis_result
        )

        analysis_id = analysis_result["analysis_id"]
        ANALYSIS_SESSIONS.clear()
        ANALYSIS_SESSIONS[analysis_id] = analysis_session
        trace(
            f"12. Analysis registered ({analysis_id}); "
            f"findings={len(findings)}"
        )

        response = {
            "ok": True,
            "analysis_id": analysis_id,
            "provider": dynamic_result.get(
                "proposal_provider",
                "UNKNOWN",
            ),
            "analysis_type": "DYNAMIC",
            "proposal_provider": dynamic_result.get(
                "proposal_provider",
                "UNKNOWN",
            ),
            "authentication_mode": auth_result.mode,
            "authenticated": auth_result.authenticated,
            "finding_count": len(findings),
            "discovery_summary": {
                "pages": len(discovery_result.get("pages", [])),
                "endpoints": len(discovery_result.get("endpoints", [])),
                "forms": len(discovery_result.get("forms", [])),
                "errors": len(discovery_result.get("errors", [])),
            },
            "redirect_url": url_for(
                "analysis_results",
                analysis_id=analysis_id,
            ),
        }
        trace("13. JSON response ready")
        return jsonify(response)

    except DynamicAuthenticationError as error:
        trace(f"FAILED during authentication: {type(error).__name__}: {error}")
        return jsonify({
            "ok": False,
            "error": str(error),
        }), 400

    except Exception as error:
        if llm_api_key:
            trace(f"FAILED: {type(error).__name__}")
        else:
            trace(f"FAILED: {type(error).__name__}: {error}")
            app.logger.exception("Dynamic analysis request failed")
        return jsonify({
            "ok": False,
            "error": (
                "Dynamic analysis could not complete with the selected provider."
                if llm_api_key else str(error)
            ),
        }), 500


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

    verification_route = (
        route_finding_for_verification(
            finding
        )
    )

    if (
        verification_route.readiness
        is VerificationReadiness.CONTEXT_REQUIRED
    ):
        return jsonify({
            "ok": False,
            "code": "VERIFICATION_CONTEXT_REQUIRED",
            "verification_readiness":
                verification_route.readiness.value,
            "capability":
                verification_route.capability_id,
            "verifier":
                verification_route.verifier_id,
            "missing_fields":
                list(
                    verification_route.missing_fields
                ),
            "error":
                verification_route.reason,
        }), 409

    if (
        verification_route.readiness
        is VerificationReadiness.UNSUPPORTED
    ):
        return jsonify({
            "ok": False,
            "code": "VERIFICATION_UNSUPPORTED",
            "verification_readiness":
                verification_route.readiness.value,
            "error":
                verification_route.reason,
        }), 400

    if (
        verification_route.readiness
        is VerificationReadiness.NOT_ELIGIBLE
    ):
        return jsonify({
            "ok": False,
            "code": "VERIFICATION_NOT_ELIGIBLE",
            "verification_readiness":
                verification_route.readiness.value,
            "error":
                verification_route.reason,
        }), 409

    if not verification_route.can_verify:
        return jsonify({
            "ok": False,
            "code": "VERIFICATION_NOT_READY",
            "verification_readiness":
                verification_route.readiness.value,
            "error": (
                "Independent verification is not ready "
                "for this finding."
            ),
        }), 409

    try:
        metadata = FINDING_METADATA.get(finding_id, {})
        analysis_id = metadata.get("analysis_id")
        analysis_session = ANALYSIS_SESSIONS.get(analysis_id)

        # Static and dynamic findings use separate evidence domains.
        if finding.scan_type.value == "STATIC":
            if verification_route.verifier_id != "static_sql_injection_source":
                return jsonify({
                    "ok": False,
                    "code": "STATIC_VERIFICATION_EXECUTOR_UNAVAILABLE",
                    "error": "No Static Oracle executor is registered for this finding.",
                }), 501

            analysis_result = ANALYSES.get(analysis_id)
            if not isinstance(analysis_result, dict):
                return jsonify({
                    "ok": False,
                    "code": "STATIC_ANALYSIS_CONTEXT_MISSING",
                    "error": "The retained static analysis context is unavailable. Run the static analysis again.",
                }), 409

            static_result = StaticVerificationService().verify(
                finding,
                analysis_result=analysis_result,
                metadata=metadata,
            )
            finding.status = static_result.finding_status
            evidence = static_result.evidence
            EVIDENCE_BY_FINDING[finding_id] = evidence

            artifacts_dir = Path("artifacts") / "runs"
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            json_file = artifacts_dir / f"{evidence['run_id']}_static_evidence.json"
            with json_file.open("w", encoding="utf-8") as file:
                json.dump(evidence, file, indent=2)

            return jsonify({
                "ok": True,
                "finding_id": finding_id,
                "verification_status": "COMPLETED",
                "evidence_gate_result": static_result.finding_status.value,
                "run_id": evidence["run_id"],
                "json_artifact": str(json_file),
            })

        verification_finding = finding
        endpoint = (finding.endpoint or "").strip()
        endpoint_parts = urlsplit(endpoint)

        # The dynamic target was already authorised and supplied when the scan
        # started. Reuse that analysis context instead of asking the reviewer
        # to enter the same URL again.
        analysis = ANALYSES.get(analysis_id, {})
        runtime_target_url = str(
            analysis.get("target")
            or analysis.get("target_details", {}).get("base_url")
            or analysis.get("target_details", {}).get("original_url")
            or ""
        ).strip()

        if not endpoint_parts.scheme or not endpoint_parts.netloc:
            target_parts = urlsplit(runtime_target_url)
            if target_parts.scheme not in {"http", "https"} or not target_parts.netloc:
                return jsonify({
                    "ok": False,
                    "code": "DYNAMIC_TARGET_CONTEXT_MISSING",
                    "error": (
                        "The authorised dynamic target could not be recovered "
                        "from this analysis session. Run the dynamic analysis "
                        "again before collecting runtime evidence."
                    ),
                }), 409

            absolute_endpoint = urljoin(
                runtime_target_url.rstrip("/") + "/",
                endpoint.lstrip("/"),
            )
            verification_finding = replace(
                finding,
                endpoint=absolute_endpoint,
            )

        if (
            verification_route.verifier_id
            != "injection_differential"
        ):
            return jsonify({
                "ok": False,
                "code": "VERIFICATION_EXECUTOR_UNAVAILABLE",
                "verification_readiness":
                    verification_route.readiness.value,
                "capability":
                    verification_route.capability_id,
                "verifier":
                    verification_route.verifier_id,
                "error": (
                    "A verification capability was selected, "
                    "but no web execution adapter is registered "
                    "for its verifier."
                ),
            }), 501

        service = DynamicVerificationService(
            session=analysis_session,
        )
        result = service.verify(verification_finding)

        # The verifier result becomes the canonical verification status.
        # Human review remains a separate later decision.
        finding.status = result.finding_status

        evidence = build_web_evidence(result)
        json_file, csv_file = save_web_evidence(evidence)

        EVIDENCE_BY_FINDING[finding_id] = evidence

        return jsonify({
            "ok": True,
            "finding_id": finding_id,
            "verification_status": "COMPLETED",
            "evidence_gate_result": result.finding_status.value,
            "run_id": evidence["run_id"],
            "json_artifact": str(json_file),
            "csv_artifact": str(csv_file),
        })

    except StaticVerificationError as error:
        return jsonify({
            "ok": False,
            "error": str(error),
        }), 400

    except DynamicVerificationError as error:
        return jsonify({
            "ok": False,
            "error": str(error),
        }), 400

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

