# Final CSI6224 submission and handover checklist

## Existing GitHub repository

- [ ] Check the latest `master` branch and teammate changes **before** replacing anything. Do not force-push.
- [ ] Copy the **contents** of the new full handover archive into the checked-out team repository root (not the top-level wrapper folder).
- [ ] Check `git diff`, `git status` and branch; ensure `.env`, credentials, node_modules, caches and irrelevant OS files are not staged.
- [ ] Confirm README links work and required source code, templates, tests and docs are in one repository.
- [ ] Install Python dependencies and run `python -m pytest tests -q` on the team's development machine.
- [ ] Launch UI and locally reproduce one static test + DVWA dynamic scan; save redacted evidence and provider/model IDs.
- [ ] Record `git rev-parse HEAD` after final commit and ensure supervisors have access to GitHub `master`.
- [ ] Review `docs/AI_TOOLS_ACKNOWLEDGEMENT.md`; disclose actual AI assistance used for reports, coding and documentation, including versions where known (confirm any earlier Claude use).

## Canvas

- [ ] Submit the **1–2 page final executive/project summary** to **Final Project Outputs** with a link to the *verified* GitHub repository.
- [ ] Complete the **separate individual peer review/self-assessment** based on actual evidence of contributions.
- [ ] Make sure any other proposal deliverables that were promised are available to supervisors; GitHub access alone does not replace missing data/results.
