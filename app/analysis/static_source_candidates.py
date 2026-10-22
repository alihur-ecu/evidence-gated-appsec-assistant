
from __future__ import annotations

import ast
import re
from typing import Iterable

from app.static_analysis.collector import SourceFile

_SQL_VERB = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|REPLACE|MERGE)\b", re.I)
_TEMPLATE_UNSAFE = re.compile(r"\{\{[\s\S]*?\|\s*safe\b[\s\S]*?\}\}", re.I)


def _attribute_path(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _attribute_path(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _literal(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _inputs(function: ast.FunctionDef) -> dict[str, str]:
    
    result: dict[str, str] = {}
    for node in ast.walk(function):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if value is None:
            continue
        field: str | None = None
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
            if _attribute_path(value.func.value) in {
                "request.args", "request.form", "request.values", "request.json"
            } and value.func.attr == "get" and value.args:
                field = _literal(value.args[0])
        elif isinstance(value, ast.Subscript) and _attribute_path(value.value) in {
            "request.args", "request.form", "request.values", "request.json"
        }:
            field = _literal(value.slice)
        if not field:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                result[target.id] = field
    return result


def _names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _dynamic_expression(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.JoinedStr)
        or isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod))
        or isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"format", "format_map"}
    )


def _sql_in_expression(node: ast.AST) -> bool:
    return any(
        isinstance(n, ast.Constant) and isinstance(n.value, str)
        and _SQL_VERB.search(n.value)
        for n in ast.walk(node)
    )


def _route(function: ast.FunctionDef) -> tuple[str | None, str]:
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call) or not decorator.args:
            continue
        if not _attribute_path(decorator.func).endswith(".route"):
            continue
        path = _literal(decorator.args[0])
        if not path:
            continue
        methods = ["GET"]
        for kw in decorator.keywords:
            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                methods = [x.value.upper() for x in kw.value.elts
                           if isinstance(x, ast.Constant) and isinstance(x.value, str)]
        return path, ("POST" if "POST" in methods and ("GET" not in methods or any(_attribute_path(n) == "request.form" for n in ast.walk(function))) else "GET")
    return None, "GET"


def _candidate(*, finding_type: str, cwe: str, path: str, line: int,
               endpoint: str | None, parameter: str | None, method: str,
               explanation: str, severity: str = "HIGH",
               observed_in_chunks: list[str] | None = None,
               related_source_files: list[str] | None = None,
               source_scope: tuple[int, int] | None = None) -> dict:
    return {
        "finding_type": finding_type, "proposed_cwe": cwe,
        "suggested_severity": severity, "explanation": explanation,
        "source_file": path, "line_number": line,
        "endpoint": endpoint, "parameter": parameter, "method": method,
        "scan_type": "STATIC", "proposal_source": "STATIC_SOURCE_PATTERN",
        "confidence": None, "observed_in_chunks": observed_in_chunks or [],
        "related_source_files": related_source_files or [],
        "source_scope": list(source_scope) if source_scope else None,
    }


def _sql_candidates(source: SourceFile) -> list[dict]:
    try:
        tree = ast.parse(source.source_code, filename=source.relative_path)
    except (SyntaxError, ValueError, RecursionError):
        return []
    proposals: list[dict] = []
    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        path, method = _route(function)
        if path is None:
            continue
        inputs = _inputs(function)
        assignments: dict[str, ast.AST] = {}
        for node in ast.walk(function):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = node.value
        for call in (n for n in ast.walk(function) if isinstance(n, ast.Call)):
            if not isinstance(call.func, ast.Attribute) or call.func.attr not in {
                "execute", "executemany", "raw", "query"
            } or not call.args:
                continue
            value = call.args[0]
            assigned_value: ast.AST | None = None
            if isinstance(value, ast.Name):
                assigned_value = assignments.get(value.id)
            expression = assigned_value or value
            if not (_dynamic_expression(expression) and _sql_in_expression(expression)):
                continue
            candidates = sorted(set(_names(expression)) & set(inputs))
            if not candidates:
                continue
            # One proposed finding per unsafe SQL execution site, even when
            # multiple HTTP fields jointly affect the same SQL statement.
            parameter_names = list(dict.fromkeys(inputs[name] for name in candidates))
            # The current Finding contract has one primary parameter.
            # Preserve other participating input fields in the explanation.
            parameter = parameter_names[0]
            all_parameters = ", ".join(parameter_names)
            proposals.append(_candidate(
                finding_type="SQL_INJECTION", cwe="CWE-89",
                path=source.relative_path, line=getattr(expression, "lineno", call.lineno),
                endpoint=path, parameter=parameter, method=method,
                source_scope=(function.lineno, function.end_lineno or function.lineno),
                explanation=(
                    "Source-pattern candidate: request-controlled field(s) "
                    f"{all_parameters} appear in dynamically composed SQL at a database "
                    "execution site. Static source verification and human review "
                    "must determine whether the flow is genuinely unsafe."
                ),
            ))
    return proposals


def _template_safe_filters(files: Iterable[SourceFile]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for source in files:
        if source.extension.lower() not in {".html", ".htm", ".jinja", ".j2"}:
            continue
        unsafe = set()
        for match in _TEMPLATE_UNSAFE.finditer(source.source_code):
            first = re.search(r"\b([A-Za-z_]\w*)\s*\|\s*safe\b", match.group(0), re.I)
            if first:
                unsafe.add(first.group(1))
        if unsafe:
            found[source.relative_path] = unsafe
    return found


def _xss_candidates(source: SourceFile, templates: dict[str, set[str]]) -> list[dict]:
    try:
        tree = ast.parse(source.source_code, filename=source.relative_path)
    except (SyntaxError, ValueError, RecursionError):
        return []
    proposals: list[dict] = []
    for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
        path, method = _route(function)
        if path is None:
            continue
        inputs = _inputs(function)
        calls = [n for n in ast.walk(function) if isinstance(n, ast.Call)]
        for call in calls:
            callee = _attribute_path(call.func)
            if callee.endswith("render_template_string") and call.args:
                rendered = call.args[0]
                # Directly supplied request-controlled content in raw template
                # expressions, including a simple locally assigned expression.
                assigned = {n.targets[0].id: n.value
                            for n in ast.walk(function) if isinstance(n, ast.Assign)
                            and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)}
                expression = assigned.get(rendered.id, rendered) if isinstance(rendered, ast.Name) else rendered
                named = sorted(set(_names(expression)) & set(inputs))
                if named and _dynamic_expression(expression):
                    parameter = inputs[named[0]]
                    proposals.append(_candidate(
                        finding_type="XSS", cwe="CWE-79", path=source.relative_path,
                        line=getattr(expression, "lineno", call.lineno), endpoint=path,
                        parameter=parameter, method=method,
                        source_scope=(function.lineno, function.end_lineno or function.lineno),
                        explanation=("Source-pattern candidate: request-controlled content "
                                     "is interpolated into an HTML template string. "
                                     "Output encoding and exploitability require independent review."),
                    ))
            elif callee.endswith("render_template") and call.args:
                template_name = _literal(call.args[0])
                if not template_name:
                    continue
                matched = [p for p, unsafe in templates.items() if p.endswith("/"+template_name) or p == template_name]
                for template_path in matched:
                    unsafe = templates[template_path]
                    # For simple reflected routes, template kwarg maps to a
                    # request input directly; stored flows may use a collection
                    # and require manual validation.
                    for kw in call.keywords:
                        if kw.arg is None:
                            continue
                        reflected = [name for name in _names(kw.value) if name in inputs]
                        safe_kwarg = kw.arg in unsafe
                        possible_stored = bool(set(inputs.values()) & unsafe)
                        if not ((safe_kwarg and reflected) or (possible_stored and not reflected and kw.arg not in unsafe)):
                            continue
                        if reflected:
                            parameter = inputs[reflected[0]]
                        else:
                            # A stored rendering proposal requires an observed
                            # source field and an unsafe template output.
                            parameter = next((field for field in inputs.values() if field in unsafe), None)
                        if not parameter:
                            continue
                        proposals.append(_candidate(
                            finding_type="XSS", cwe="CWE-79", path=source.relative_path,
                            line=call.lineno, endpoint=path, parameter=parameter,
                            method=method,
                            source_scope=(function.lineno, function.end_lineno or function.lineno),
                            explanation=(f"Source-pattern candidate: template {template_name} "
                                         "contains explicit unsafe rendering (|safe) and the "
                                         "route reads HTTP input. A source-to-sink flow and "
                                         "escaping behaviour still require independent review."),
                            related_source_files=[template_path],
                        ))
    return proposals


def collect_static_source_candidates(files: Iterable[SourceFile]) -> list[dict]:
   
    source_files = list(files)
    templates = _template_safe_filters(source_files)
    findings: list[dict] = []
    for source in source_files:
        if source.extension.lower() != ".py":
            continue
        findings.extend(_sql_candidates(source))
        findings.extend(_xss_candidates(source, templates))
    findings.sort(key=lambda p: (p["source_file"].lower(), p["line_number"], p["proposed_cwe"], p["parameter"] or ""))
    # Never return duplicate observations of the exact same source site.
    return list({(f["source_file"], f["line_number"], f["proposed_cwe"]): f for f in findings}.values())
