# AISA: A Trusted Controller for Supervising AI Agent Actions — A Proof of Concept

**Publication candidate 1.0.0-rc1. Prepared 19 October 2026; not yet published.**

AISA places application-controlled checks between an AI model's proposed action and a resource operation. The Primary model proposes an action; the trusted Controller applies the configured objective and policy, requests Shadow review where required, and controls access through a capability broker and resource wrapper. Completion output is also checked.

The controlled demonstration reads artificial PUBLIC reports held in memory. It records evidence of action decisions and generates a summary of the observed content. It does not demonstrate unrestricted host-file access or production infrastructure.

**Qualified demonstration closure approved 19 October 2026. Full formal acceptance INCOMPLETE. Reference performance HARD-DEFERRED. L7 comparative acceptance INCOMPLETE. No production acceptance claim.**

## Start here

- [Reproduce offline](docs/REPRODUCE.md)
- [Architecture and source map](docs/ARCHITECTURE.md)
- [Technical report](docs/TECHNICAL_REPORT.md)
- [Evidence guide](docs/EVIDENCE.md)
- [Limitations](docs/LIMITATIONS.md)
- [Publication decisions](docs/PUBLICATION_CHECKLIST.md)

## Release identity

One canonical Controller implementation: `workspace/source/baseline-src/shadow_poc/`, engineering baseline v0.15.22. Final hosted demonstration: `aisa_confirmation_v0_5.py` with its v0.5 support module. Earlier small launchers and verification scripts are retained as test dependencies and to reproduce the incomplete v0.3 continuation. They use the same canonical core; they are not multiple installations of the Controller.

`aisa.py` is a new offline-only convenience entry point. It dispatches to preserved launchers without modifying their bytes. Historical source/configuration bindings are preserved. This packaging candidate has a separate identity from the historical tested release.

## Quick start — Linux, Python 3.12

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python aisa.py review
python tools/verify_publication.py
python tools/verify_offline.py
```

The default public workflow makes no hosted API calls. No credential is required. Source is provided for inspection; the licence decision is pending. See LICENSE before redistribution.

Selected live evidence dates from 16 October 2026. Historical hosted model identifiers are recorded for traceability, not promised as currently available services. New hosted qualification is separate work.
