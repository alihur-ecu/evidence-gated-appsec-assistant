# Evidence-Gated AppSec Finding Assistant

Edith Cowan University applied project — **CSI6224**, Semester 2, 2026.

An LLM-assisted AppSec helper that may **propose** findings but may only **promote** them when deterministic, replayable evidence exists. A person accepts, rejects, or edits. The lab stays local.

## Supervision and industry

| Role | Name |
|---|---|
| Principal supervisor | Dr. Ali Hur |
| Co-supervisor | Miss Taylah Griffiths |
| Industry partner | Secure.com (mentoring and design-review feedback only) |

Industry partners advise. They are not requesting a proprietary product build. Student deliverables are intended for release under the **MIT License**.

## Team (first names)

Gabriel, Irtifa, Mahmud.

## Data boundary

- **In:** public intentionally vulnerable applications such as OWASP Juice Shop or DVWA, run in a **local lab only**, plus replayable checks and a human review trail.
- **Out:** customer code, production scanning, and any live customer AppSec toolchain as a hard dependency.

## Scope (one-liners)

- **In scope:** local-lab targets, an agent that proposes, deterministic verifiers, and HITL accept / reject / edit.
- **Out of scope:** promoting a finding on model confidence alone, or scanning anything that is not the agreed local lab.

## Working rule — GitHub accounts

Join this repository with your **personal GitHub account**. Do not share one login, password, or token among the team.

1. Send Dr. Ali Hur your personal GitHub **username** (not a password).
2. Accept the collaborator invite on that same account.
3. Add a **personal recovery email** you control so you cannot lose access.
4. Never commit `.env` files, API keys, or customer / production artefacts.

## Getting started

```bash
git clone https://github.com/alihur-ecu/evidence-gated-appsec-assistant.git
cd evidence-gated-appsec-assistant
```

Keep the first running slice thin: lab app → proposed finding → replayable evidence → human decision.

## License

MIT. See [LICENSE](LICENSE).
