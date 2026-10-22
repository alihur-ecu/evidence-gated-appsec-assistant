from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any, Iterable
from uuid import uuid4

from app.models.finding import Finding, FindingStatus, FindingType


class StaticVerificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class StaticVerificationResult:
    finding_id: str
    finding_status: FindingStatus
    evidence: dict[str, Any]


class StaticVerificationService:
    

    _SQL_WORD = re.compile(r"\b(select|insert|update|delete|replace|merge)\b", re.I)
    _PLACEHOLDER = re.compile(r"(%s|\?|:\w+|\$\d+|@\w+)")
    _EXECUTE = re.compile(
        r"\b(execute|executemany|query|raw|cursor\.execute|db\.execute)\b",
        re.I,
    )

    def verify(
        self,
        finding: Finding,
        *,
        analysis_result: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> StaticVerificationResult:
        if finding.status is not FindingStatus.PROPOSED:
            raise StaticVerificationError(
                "Only PROPOSED findings may enter static verification."
            )
        if finding.finding_type is FindingType.XSS:
            return self._verify_xss_source(finding, analysis_result=analysis_result, metadata=metadata)
        if finding.finding_type is not FindingType.SQL_INJECTION:
            raise StaticVerificationError(
                "No deterministic static verifier is registered for this finding type."
            )

        metadata = metadata or {}
        chunks = list(self._normalise_chunks(analysis_result.get("source_context", [])))
        if not chunks:
            raise StaticVerificationError(
                "The static analysis did not retain source context required by the Static Oracle."
            )

        relevant = self._select_relevant_chunks(chunks, finding, metadata)
        relevant = self._apply_source_scope(relevant, finding, metadata)
        parameter = (finding.parameter or "").strip()
        windows = self._build_local_windows(
            relevant,
            parameter=parameter,
            endpoint=(finding.endpoint or "").strip(),
        )
        if not windows:
            windows = self._fallback_windows(relevant)

        input_windows = [
            w for w in windows
            if self._parameter_present(w["text"], parameter)
        ]
        sql_windows = [
            w for w in windows
            if self._SQL_WORD.search(w["text"]) and self._EXECUTE.search(w["text"])
        ]
        unsafe_windows = [
            w for w in windows
            if self._unsafe_sql_composition(w["text"], parameter)
            and self._EXECUTE.search(w["text"])
        ]
        parameterised_windows = [
            w for w in windows
            if self._parameterised_execution(w["text"], parameter)
        ]

        input_observed = bool(input_windows)
        sql_observed = bool(sql_windows)
        unsafe_composition = bool(unsafe_windows)
        # SQL %-formatting is string interpolation, not safe bound-parameter
        # execution. Do not present contradictory "parameterized" evidence
        # when unsafe composition is already established in this source scope.
        parameterised = bool(parameterised_windows) and not unsafe_composition

        # A safe query elsewhere in a file must not cancel a localized unsafe flow.
        if input_observed and sql_observed and unsafe_composition:
            status = FindingStatus.PROVED
            conclusion = (
                "Independent source evidence shows the proposed input identifier "
                "participating in dynamically composed SQL that reaches a database "
                "execution operation."
            )
        elif input_observed and sql_observed and parameterised and not unsafe_composition:
            status = FindingStatus.NEEDS_HUMAN
            conclusion = (
                "A localized parameterised database operation was observed and no "
                "deterministic unsafe composition was established in the retained "
                "context. Human review is required."
            )
        else:
            status = FindingStatus.NEEDS_HUMAN
            conclusion = (
                "The retained source evidence is insufficient to prove or refute "
                "the proposal deterministically. Human interpretation is required."
            )

        observations = [
            self._observation(
                1, "INPUT_SOURCE_OBSERVATION", "Input / source observation",
                input_observed, input_windows or windows[:1],
                f"Identifier checked: {parameter or 'not supplied'}",
                parameter=parameter, signal_kind="input",
            ),
            self._observation(
                2, "SQL_SINK_OBSERVATION", "Database sink observation",
                sql_observed, sql_windows or windows[:1],
                "Checked for SQL construction together with a database execution operation.",
                parameter=parameter, signal_kind="sink",
            ),
            self._observation(
                3, "QUERY_CONSTRUCTION_OBSERVATION",
                "Query construction / mitigation observation",
                unsafe_composition,
                unsafe_windows or parameterised_windows or windows[:1],
                (
                    "Unsafe SQL composition observed."
                    if unsafe_composition
                    else (
                        "Localized parameterized SQL markers observed."
                        if parameterised
                        else "No conclusive unsafe composition or parameterization pattern was established."
                    )
                ),
                parameter=parameter,
                signal_kind="unsafe" if unsafe_composition else "parameterized",
            ),
        ]

        run_id = f"static-{uuid4().hex}"
        evidence = {
            "finding_id": finding.finding_id,
            "run_id": run_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "execution_status": "COMPLETED",
            "evidence_source": "STATIC",
            "capability": "STATIC_SQL_INJECTION_SOURCE",
            "evidence_gate_result": status.value,
            "observations": observations,
            "signals": {
                "input_source_observed": input_observed,
                "database_sink_observed": sql_observed,
                "unsafe_query_composition_observed": unsafe_composition,
                "parameterized_query_observed": parameterised,
            },
            "verification": {
                "verifier_id": "static_sql_injection_source",
                "decision": status.value,
                "reasons": [conclusion],
            },
        }
        return StaticVerificationResult(finding.finding_id, status, evidence)


    _XSS_INPUT = re.compile(r"(?:\$_(?:GET|POST|REQUEST)|request\.(?:args|form|values|GET|POST)|req\.(?:query|body|params))", re.I)
    _XSS_OUTPUT = re.compile(r"(?:\becho\b|\bprint\s*\(|\binnerHTML\b|\bouterHTML\b|\bdocument\.write\s*\(|\bres\.send\s*\(|\brender_template_string\s*\(|\|\s*safe\b)", re.I)
    _XSS_ESCAPE = re.compile(r"(?:htmlspecialchars|htmlentities|escape\s*\(|\bhtml\.escape\s*\(|\btextContent\b|\binnerText\b)", re.I)

    def _verify_xss_source(
        self, finding: Finding, *, analysis_result: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> StaticVerificationResult:
        metadata = metadata or {}
        chunks = list(self._normalise_chunks(analysis_result.get("source_context", [])))
        if not chunks:
            raise StaticVerificationError("Retained source context is required for XSS source observations.")
        relevant = self._select_relevant_chunks(chunks, finding, metadata)
        relevant = self._apply_source_scope(relevant, finding, metadata)
        # Restrict evidence to the proposal's selected source context.
        observations = []
        signals = {"input_source_observed": False, "html_output_observed": False,
                   "escaping_pattern_observed": False}
        patterns = (
            ("input_source_observed", self._XSS_INPUT, "Potential untrusted input"),
            ("html_output_observed", self._XSS_OUTPUT, "Potential HTML output sink"),
            ("escaping_pattern_observed", self._XSS_ESCAPE, "Possible output escaping or safe text sink"),
        )
        for index, (key, pattern, label) in enumerate(patterns, 1):
            matched = []
            for chunk in relevant:
                lines = chunk["text"].splitlines()
                for offset, line in enumerate(lines):
                    if pattern.search(line):
                        matched.append({
                            "file": chunk["file"] or "retained source context",
                            "line_number": int(chunk.get("start_line") or 1) + offset,
                            "text": line[:400], "highlight": True,
                        })
            signals[key] = bool(matched)
            observations.append({
                "observation_id": f"S-{index:03d}", "label": key.upper(),
                "name": label, "result": "OBSERVED" if matched else "NOT_ESTABLISHED",
                "observed": bool(matched),
                "detail": "Source pattern only; no end-to-end taint flow or contextual escaping proof.",
                "source_lines": matched[:10],
                "source_excerpt": "\n".join(f"{m['file']}:{m['line_number']}: {m['text']}" for m in matched[:10]),
                "metadata": {"source_kind": "STATIC_SOURCE", "signal_kind": key},
            })
        status = FindingStatus.NEEDS_HUMAN
        evidence = {
            "finding_id": finding.finding_id, "run_id": f"static-{uuid4().hex}",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "execution_status": "COMPLETED", "evidence_source": "STATIC",
            "capability": "STATIC_XSS_SOURCE_OBSERVATION",
            "evidence_gate_result": status.value, "observations": observations,
            "signals": signals,
            "verification": {
                "verifier_id": "static_xss_source_observation", "decision": status.value,
                "reasons": ["Potential input/output/escaping patterns were inspected in retained source. "
                            "A source-to-sink flow and output encoding have not been proved; human review is required."],
            },
        }
        return StaticVerificationResult(finding.finding_id, status, evidence)

    @staticmethod
    def _apply_source_scope(
        chunks: list[dict[str, Any]], finding: Finding, metadata: dict[str, Any]
    ) -> list[dict[str, Any]]:

        if metadata.get("proposal_source") != "STATIC_SOURCE_PATTERN":
            return chunks
        scope = metadata.get("source_scope")
        if not isinstance(scope, (tuple, list)) or len(scope) != 2:
            return chunks
        try:
            low, high = int(scope[0]), int(scope[1])
        except (TypeError, ValueError):
            return chunks
        if low < 1 or high < low:
            return chunks
        origin = str(metadata.get("source_file") or finding.source_file or "").replace("\\", "/").lower()
        restricted = []
        for chunk in chunks:
            name = str(chunk.get("file") or "").replace("\\", "/").lower()
            if name != origin:
                
                restricted.append(chunk)
                continue
            start = int(chunk.get("start_line") or 1)
            lines = chunk["text"].splitlines()
            keep = [(start+i, line) for i, line in enumerate(lines) if low <= start+i <= high]
            if keep:
                restricted.append({**chunk, "text": "\n".join(line for _,line in keep),
                                   "start_line": keep[0][0], "end_line": keep[-1][0]})
        return restricted

    @staticmethod
    def _normalise_chunks(raw: Any) -> Iterable[dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        result = []
        for index, chunk in enumerate(raw, start=1):
            if isinstance(chunk, str):
                result.append({
                    "file": "", "text": chunk, "start_line": 1,
                    "end_line": None, "index": index, "chunk_id": None,
                })
                continue
            if not isinstance(chunk, dict):
                continue
            text = next(
                (
                    chunk.get(k)
                    for k in ("source_code", "content", "text", "source", "code", "chunk")
                    if isinstance(chunk.get(k), str)
                ),
                "",
            )
            if not text:
                continue
            file_name = next(
                (
                    chunk.get(k)
                    for k in ("source_file", "file_path", "path", "file", "filename")
                    if chunk.get(k)
                ),
                "",
            )
            start_line = chunk.get("start_line") or chunk.get("line_start") or 1
            try:
                start_line = int(start_line)
            except (TypeError, ValueError):
                start_line = 1
            result.append({
                "file": str(file_name),
                "text": text,
                "start_line": start_line,
                "end_line": chunk.get("end_line") or chunk.get("line_end"),
                "index": index,
                "chunk_id": chunk.get("chunk_id") or chunk.get("context_id"),
            })
        return result

    @staticmethod
    def _select_relevant_chunks(
        chunks: list[dict[str, Any]],
        finding: Finding,
        metadata: dict[str, Any],
    ) -> list[dict[str, Any]]:
 
        wanted_chunk_ids = []
        direct_chunk = metadata.get("chunk_id")
        if direct_chunk:
            wanted_chunk_ids.append(str(direct_chunk))
        observed = metadata.get("observed_in_chunks") or []
        if isinstance(observed, str):
            observed = [observed]
        if isinstance(observed, (list, tuple, set)):
            for value in observed:
                value = str(value).strip()
                if value and value not in wanted_chunk_ids:
                    wanted_chunk_ids.append(value)

        if wanted_chunk_ids:
            matches = [
                c for c in chunks
                if c.get("chunk_id") and str(c.get("chunk_id")) in wanted_chunk_ids
            ]
            if matches:
                return matches

        wanted = str(
            metadata.get("source_file") or finding.source_file or ""
        ).replace("\\", "/").lower()

        if wanted and wanted != "not available":
            matches = [
                c for c in chunks
                if c["file"].replace("\\", "/").lower().endswith(wanted)
                or wanted.endswith(c["file"].replace("\\", "/").lower())
            ]
            if matches:
                return matches

        parameter = (finding.parameter or "").strip()
        if parameter:
            matches = [
                c for c in chunks
                if re.search(rf"\b{re.escape(parameter)}\b", c["text"], re.I)
            ]
            if matches:
                return matches
        return chunks[:3]

    @classmethod
    def _build_local_windows(
        cls,
        chunks: list[dict[str, Any]],
        *,
        parameter: str,
        endpoint: str,
    ) -> list[dict[str, Any]]:
        windows = []
        endpoint_token = endpoint.strip("/").split("/")[-1].lower()

        for chunk in chunks:
            lines = chunk["text"].splitlines()
            anchors = set()
            for i, line in enumerate(lines):
                parameter_hit = bool(
                    parameter
                    and re.search(rf"\b{re.escape(parameter)}\b", line, re.I)
                )
                endpoint_hit = bool(endpoint_token and endpoint_token in line.lower())
                if (
                    parameter_hit
                    or endpoint_hit
                    or cls._SQL_WORD.search(line)
                    or cls._EXECUTE.search(line)
                ):
                    anchors.add(i)

            for anchor in sorted(anchors):
                start = max(0, anchor - 6)
                end = min(len(lines), anchor + 9)
                selected = lines[start:end]
                text = "\n".join(selected)
                if parameter and not cls._parameter_present(text, parameter):
                    continue
                base = int(chunk.get("start_line") or 1)
                windows.append({
                    "file": chunk["file"],
                    "text": text,
                    "lines": selected,
                    "start_line": base + start,
                    "end_line": base + end - 1,
                })

        seen = set()
        result = []
        for window in windows:
            key = (window["file"], window["start_line"], window["end_line"])
            if key not in seen:
                seen.add(key)
                result.append(window)
        return result[:6]

    @staticmethod
    def _fallback_windows(chunks: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result = []
        for chunk in chunks[:3]:
            lines = chunk["text"].splitlines()[:18]
            base = int(chunk.get("start_line") or 1)
            result.append({
                "file": chunk["file"],
                "text": "\n".join(lines),
                "lines": lines,
                "start_line": base,
                "end_line": base + len(lines) - 1,
            })
        return result

    @staticmethod
    def _parameter_present(text: str, parameter: str) -> bool:
        return bool(
            parameter
            and re.search(rf"\b{re.escape(parameter)}\b", text, re.I)
        )

    @classmethod
    def _parameterised_execution(cls, text: str, parameter: str) -> bool:
        if not cls._EXECUTE.search(text) or not cls._PLACEHOLDER.search(text):
            return False
        if parameter and not cls._parameter_present(text, parameter):
            return False

        lines = text.splitlines()
        execute_lines = [
            i for i, line in enumerate(lines) if cls._EXECUTE.search(line)
        ]
        placeholder_lines = [
            i for i, line in enumerate(lines) if cls._PLACEHOLDER.search(line)
        ]
        return any(
            abs(e - p) <= 4
            for e in execute_lines
            for p in placeholder_lines
        )

    @classmethod
    def _unsafe_sql_composition(cls, text: str, parameter: str) -> bool:
        if not parameter:
            return False

        p = re.escape(parameter)
        lines = text.splitlines()
        parameter_lines = [
            i for i, line in enumerate(lines)
            if re.search(rf"\b{p}\b", line, re.I)
        ]
        sql_lines = [
            i for i, line in enumerate(lines)
            if cls._SQL_WORD.search(line)
        ]
        execute_lines = [
            i for i, line in enumerate(lines)
            if cls._EXECUTE.search(line)
        ]
        composition = re.compile(
            r"(\+|\.format\s*\(|%\s*[\(\w]|f[\"']|\$\{|#\{)",
            re.I,
        )
        composition_lines = [
            i for i, line in enumerate(lines)
            if composition.search(line)
        ]

        for line in lines:
            if (
                re.search(rf"\b{p}\b", line, re.I)
                and cls._SQL_WORD.search(line)
                and composition.search(line)
            ):
                return True

        return any(
            abs(pi - si) <= 5
            and abs(si - ei) <= 7
            and any(
                abs(ci - pi) <= 4 or abs(ci - si) <= 4
                for ci in composition_lines
            )
            for pi in parameter_lines
            for si in sql_lines
            for ei in execute_lines
        )

    @classmethod
    def _line_is_relevant(
        cls,
        line: str,
        *,
        parameter: str,
        signal_kind: str,
    ) -> bool:
        parameter_hit = bool(
            parameter
            and re.search(rf"\b{re.escape(parameter)}\b", line, re.I)
        )
        sql_hit = bool(cls._SQL_WORD.search(line))
        execute_hit = bool(cls._EXECUTE.search(line))
        placeholder_hit = bool(cls._PLACEHOLDER.search(line))
        composition_hit = bool(
            re.search(r"(\+|\.format\s*\(|%\s*[\(\w]|f[\"']|\$\{|#\{)", line, re.I)
        )

        if signal_kind == "input":
            return parameter_hit
        if signal_kind == "sink":
            return sql_hit or execute_hit
        if signal_kind == "unsafe":
            return parameter_hit or sql_hit or execute_hit or composition_hit
        if signal_kind == "parameterized":
            return parameter_hit or sql_hit or execute_hit or placeholder_hit
        return parameter_hit or sql_hit or execute_hit

    @classmethod
    def _observation(
        cls,
        index: int,
        label: str,
        name: str,
        observed: bool,
        windows: list[dict[str, Any]],
        detail: str,
        *,
        parameter: str,
        signal_kind: str,
    ) -> dict[str, Any]:
        source_lines = []
        excerpt_parts = []

        for window in windows[:2]:
            rendered = []
            for offset, line in enumerate(window["lines"]):
                line_number = window["start_line"] + offset
                highlighted = cls._line_is_relevant(
                    line,
                    parameter=parameter,
                    signal_kind=signal_kind,
                )
                source_lines.append({
                    "file": window["file"] or "retained source context",
                    "line_number": line_number,
                    "text": line,
                    "highlight": highlighted,
                })
                marker = ">>" if highlighted else "  "
                rendered.append(f"{marker} {line_number:>4} | {line}")

            excerpt_parts.append(
                f"File: {window['file'] or 'retained source context'}\n"
                f"Lines: {window['start_line']}-{window['end_line']}\n"
                + "\n".join(rendered)
            )

        return {
            "observation_id": f"S-{index:03d}",
            "label": label,
            "name": name,
            "result": "OBSERVED" if observed else "NOT_ESTABLISHED",
            "observed": observed,
            "detail": detail,
            "source_excerpt": "\n\n---\n\n".join(excerpt_parts),
            "source_lines": source_lines,
            "metadata": {
                "source_kind": "STATIC_SOURCE",
                "signal_kind": signal_kind,
            },
        }
