# Oracle Rules: origin, implementation, and limits

**Source-checked:** `Evidence-Gated AppSec Finding Assistant.zip` uploaded 22 October 2026. These are the actual rules in that version, not hypothetical best practices.

## Who designed the rules?

The **project team selected and implemented** the Oracle decision rules as a deterministic proof-of-concept; Md Mahmud Hassan Rabby reports substantial work on Oracle integration and technical improvement. **The provided source does not identify the individual who originally proposed each threshold.** Security concepts are motivated by SQL injection/CWE-89 and OWASP guidance, but **neither mandates this project's two-error threshold**. It is an explicit, *unvalidated project heuristic*.

## Actual runtime SQLi rule

| Code location | Responsibilities |
|---|---|
| `app/dynamic_analysis/planning/injection_observation_policy.py` | Select one baseline, two neutral controls and three non-destructive syntax strings (text or numeric variants) |
| `app/dynamic_analysis/planning/baseline_resolver.py` | Establish a functional/repeatable baseline context |
| `app/dynamic_analysis/probes/injection/probe.py` | Send bounded HTTP observations with request context |
| `app/dynamic_analysis/evidence/response_signals.py` | Record status, response length, SHA-256 digest and recognised error signals |
| `app/dynamic_analysis/verifiers/injection/verifier.py` | Produce evidence-derived status |
| `app/dynamic_analysis/verification_service.py` | Orchestrate verification and return an evidence-backed result |
| `app/dynamic_analysis/verification_router.py` | Route only supported finding classes |

In `InjectionDifferentialVerifier.verify()` (currently starting around line 27 in `verifiers/injection/verifier.py`), the `PROVED` predicate is:

```python
if new_error_in_test and len(test_errors) >= 2 and from_baseline:
    return VerificationResult(... decision=VerificationDecision.PROVED, ...)
```

`new_error_in_test` requires an **error-free baseline** with at least one error-bearing test; `from_baseline` requires some non-baseline response to differ from the baseline in status, length or digest. The rule counts **all non-baseline test observations, including the two neutral controls**, not just syntax probes. This is a documented limitation.

- **PROVED:** clean baseline, at least two non-baseline observations with recognised new error flags, and a differing response.
- **NEEDS_HUMAN:** no usable baseline/enough observations, or evidence of a new error without sufficient repeatability; other ambiguous changes can also require human review.
- **REFUTED:** bounded observations produced no qualifying evidence under this verifier, **not** a proof of absence of SQLi.

Exact test values are selected in `InjectionObservationPolicy`: default numeric baseline `1`, controls `2` and `3`, syntax probes `1'`, `1"`, `1\`; text variants use `egaa-baseline`, `egaa-control-a`, `egaa-control-b`, and `'`, `"`, `\`. The baseline may instead use an observed input value. This is a lab-only, non-destructive differential check.

## Static SQLi rule

Implemented in `app/static_verification_service.py`, `StaticVerificationService.verify()`. Source chunks are retained with file/line provenance. Three signals must all be present in relevant source windows:

1. request-controlled input / proposed parameter;
2. SQL keyword + a database execution pattern;
3. unsafe query composition near execution.

If all are observed in scoped source context, the result is **PROVED by this project's pattern heuristic**. If parameterised execution is observed, or evidence is insufficient, it returns **NEEDS_HUMAN**. The static SQLi route does **not** return REFUTED. Pattern-based matching alone is not full data-flow validation and may overstate certainty.

## Static XSS observation

`StaticVerificationService._verify_xss_source()` checks possible input, HTML output and escaping patterns in retained source, stores numbered observations and **always returns NEEDS_HUMAN**. No static XSS result is declared PROVED solely from those patterns.

## Separate source-pattern candidate generator

`app/analysis/static_source_candidates.py` uses Python AST patterns to propose additional SQLi/XSS candidates. These findings do **not** count as LLM output, and the source-pattern generator itself is **not** an Oracle. Oracle verification must happen separately.

## Distinguishing project rule and security standard

CWE-89/OWASP describe the weakness and verification considerations; they do not prescribe `>=2` parser errors or the team's choice of syntax probes. Report the Oracle verdict together with reproducible evidence and reviewer decision; do not equate it with an external penetration-test certification. The full labelled benchmark was not completed.
