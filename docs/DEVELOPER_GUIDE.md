# Developer and extension guide

## Working safely with this prototype

- Work in the existing shared repository, review differences before replacing old files and avoid force-pushing to `master`.
- Create a feature branch and pull request for future changes, even if the team chose direct master commits for the final deadline.
- Use Python venv and dependency files; do not hardcode API credentials; never commit `.env`.
- Run the unit/integration tests after updates. The 148 offline subset is recorded in `RESULTS_AND_EVIDENCE.md`; it is not proof of complete functionality.

## Key modification points

| Change | Module / mechanism |
|---|---|
| Add an LLM provider | `app/analysis/proposers/base.py`, `factory.py`, adapters and tests |
| Add source ZIP parsing/language support | `app/static_analysis/archive.py`, `collector.py`, `context_builder.py` |
| Add static proposals | `app/analysis/static_source_candidates.py` and `app/analysis/static_pipeline.py` |
| Add static verifier | `app/static_verification_service.py`; update routing and tests |
| Add dynamic vulnerability type | `app/dynamic_analysis/verification_router.py`, planning/observation policy, probe, signals, verifier, registries and tests |
| Change verification threshold | `app/dynamic_analysis/verifiers/injection/verifier.py` (SQLi) plus corresponding test expectations/documentation |
| Adjust review/report/scan history | `app/web/server.py`, templates, JS, `app/web/scan_history_store.py` |

## Implementing a new runtime verifier

1. Define a bounded, authorised **observation policy** that distinguishes controls from vulnerability-specific probes.
2. Implement a probe preserving request context/session safety and records signal provenance.
3. Implement a deterministic verifier with explicit conditions and an *uncertain* outcome.
4. Register the capability in the router/registry; do not route unsupported vulnerability classes to the SQLi verifier.
5. Add positive, negative and ambiguous unit/integration tests with safe lab fixtures.
6. Store evidence with reviewer traceability and update Oracle catalogue/user instructions.
7. Where possible, evaluate false positives/recall on a labelled benchmark before claiming improved accuracy.

## Oracle rule provenance

The provided source implements the exact predicates in `docs/ORACLE_RULE_CATALOGUE.md`. These are the team-selected rules; the `>=2` error threshold is **not a rule from OWASP**. The source archive cannot establish who initially suggested that numerical threshold. Attribute team ownership and implementation contributions accurately.

## Documentation maintenance

Update source references and tests whenever implementation changes. Run `python docs/tools/source_inventory.py` from the project root for a module list, and `git rev-parse HEAD` to identify the real submitted commit. Avoid presenting historical scan summaries as newly reproduced test results.
