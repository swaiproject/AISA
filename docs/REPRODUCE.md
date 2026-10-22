# Reproduce the bounded demonstration

## Environment

Historical operator environment: Ubuntu 24.04.5 LTS on VMware, x86_64, CPython 3.12.3. Linux is required by the hosted support's fcntl use. Use Python 3.12. A compatible local verification environment is recorded in validation-output; this is not the original VMware machine.

From the extracted github directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python tools/verify_publication.py
python aisa.py summary
python aisa.py review
python aisa.py permitted
python aisa.py blocked
python aisa.py missing
python tools/verify_offline.py
```

For the complete historical pinned test environment, use `python -m pip install --require-hashes -r requirements-test.lock` in a separate Python 3.12 environment. requirements.txt pins the direct runtime dependency only; transitive resolution may differ. The historical lock is not a security or current-version certification.

## Expected results

| Command | Expected meaning |
|---|---|
| summary | Mock provider responses produce a summary of the actual artificial fixture content |
| review | Mock Primary action, mock Shadow ALLOW, read, then completion |
| permitted | Scripted fixture read EXECUTED; this old launcher does not generate a summary |
| blocked | Scripted unauthorized target BLOCKED |
| missing | Action FAILED because fixture is missing; check PASS means the negative test succeeded |

Generated records appear in workspace/evidence with unique run directories. Mock results must not be labelled as new live model results. The verifier covers all four retained offline suites (14 + 15 + 8 + 7 checks) and the four strict-fixture scenarios.

## Stop handling

Ctrl+C requests local stop. `touch workspace/STOP` prevents work at the next stop check; remove that file deliberately before another run. Offline tests exercise interruption and deadline cleanup. Stopping local work cannot guarantee that a provider has cancelled or will not bill an already dispatched request. No real hosted stop-cancellation guarantee is established here.

## Hosted execution

The public entry point has no live mode. Preserved historical launchers expose guarded live options for source inspection. Do not use them as a new deployment recipe: the closed campaign consumed all eight approved attempts and its live ledger is intentionally not installed in the runnable workspace. No new spending is authorized by this package. Historical evidence is held separately under selected-evidence.

Any future hosted work needs model availability/pricing/access checks, fresh bindings and explicit campaign authorization. Do not recreate or reset the historical ledger to bypass its attempt limit. Never place API keys in files, source control or a public Space.
