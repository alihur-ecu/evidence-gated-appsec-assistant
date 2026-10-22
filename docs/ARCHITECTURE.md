# System Architecture (source-checked, 22 October 2026)

## Trust boundary

```text
Static upload -> safe ZIP extraction -> source file collection -> bounded context
                 |                                 |
                 v                                 v
          Python-pattern proposer               LLM proposer
                 +---------------+-----------------+
                                 v
                       aggregated candidates
                                 |
                        user-triggered verify
                                 v
                        StaticVerificationService
                                 |
                      evidence + Oracle status
                                 |
                         human review / save

Dynamic lab URL -> optional login -> same-origin crawl -> context -> LLM proposals
                                 |
                        user-triggered verify
                                 v
   VerificationRouter -> baseline resolver -> bounded SQLi probe -> error signals
                                 |
                   InjectionDifferentialVerifier
                                 |
                      evidence + Oracle status
                                 |
                        human review / save
```

**Core principle:** suggestions are not evidence. The deterministic verifier and the final reviewer have separate roles. A proposer can be the configured LLM or a static Python source-pattern candidate generator.

## Actual source modules

- **Flask web/UI:** `app/web/server.py` (2,385 source lines), Jinja2 templates under `app/web/templates`, assets under `app/web/static`. This is a Python-rendered web UI.
- **Model/provider choice:** `app/analysis/proposers/factory.py`, adapters in `app/analysis/proposers/` for LM Studio, OpenAI and Gemini; `none` default.
- **Static input:** `app/static_analysis/archive.py`, `collector.py`, `context_builder.py`; `app/analysis/providers/static_source_provider.py`; `app/analysis/static_source_candidates.py`. Static SQLi/XSS verification: `app/static_verification_service.py`.
- **Dynamic input:** `app/dynamic_analysis/authentication.py`, `discovery.py`, `context_builder.py`, `pipeline.py`.
- **Dynamic verification:** `app/dynamic_analysis/verification_router.py`, `verification_service.py`, `planning/injection_observation_policy.py`, `planning/baseline_resolver.py`, `probes/injection/probe.py`, `evidence/response_signals.py`, `verifiers/injection/verifier.py`.
- **Review/reporting:** `app/web/server.py` and `app/web/scan_history_store.py`; in-memory dictionaries plus local saved snapshots and report exports.

## Main Flask routes (verified from actual decorators)

| Route | Purpose |
|---|---|
| `/` | Home / scan selection |
| `/analysis/static/job`, `/analysis/dynamic/job` | Start background scans |
| `/analysis/jobs/<job_id>` | Read job status |
| `/analysis/static`, `/analysis/dynamic` | Synchronous scan endpoints |
| `/analysis/<analysis_id>/results` | Results |
| `/findings`, `/findings/<finding_id>` | Candidate list/detail |
| `/findings/<finding_id>/verify` | Manual Oracle verification |
| `/findings/<finding_id>/review` | Human decision and final severity |
| `/scan-history`, `/scan-history/<analysis_id>/open` | Saved scan history |
| `/analysis/<analysis_id>/report`, `/analysis/<analysis_id>/save` | Report/save |
| `/reports`, `/reports/<analysis_id>/export/<format_name>` | Saved report and JSON/CSV export |

## Important caveats

- The Flask application uses module-level in-memory state; cross-session or concurrent use is **not guaranteed to behave like a production service**. Saved scans are persisted by local JSON files.
- The verifier is **not automatically run for every proposal**. A finding can remain `PENDING` until verification is requested, even if its vulnerability type has a verifier.
- Dynamic verifier coverage is SQL injection; source verification covers SQLi and observational XSS. Other candidate classes may lack verifier support.
- Static heuristics are not a full taint-flow or program-analysis engine. SQLi runtime errors are not a comprehensive assessment of blind SQL injection.
- This review did not run the Flask UI or a live DVWA integration; architecture/entrypoints/paths are verified in source, not through a complete working deployment.