# AISA: A Trusted Controller for Supervising AI Agent Actions — A Proof of Concept

Sebastian Weerakkody — publication candidate 1.0.0-rc1, prepared 19 October 2026.

## Abstract

AISA explores an application-owned control layer between AI model proposals and resource effects. A trusted Controller evaluates an explicit objective and policy, routes ambiguous actions to a Shadow model, and enforces resource access through a capability broker and wrapper. A bounded demonstration reads an artificial report and releases a grounded summary. Offline tests exercise control paths, fixture failures, task bounds, stop handling and cost accounting. Three retained hosted runs include a successful direct summary, an incomplete reviewed continuation, and a successful refined continuation. These establish a narrow engineering demonstration rather than production acceptance or comparative performance.

## Problem and scope

A model's assertion that an operation is permitted must not itself authorize the operation. AISA separates proposal generation from application-controlled enforcement and records the decision path. The demonstrated resource is an explicitly named in-memory PUBLIC report. Local storage holds configuration and evidence. No real production resources were migrated or operated.

## Method

The Primary proposes structured outputs. Trusted configuration supplies objective, policy and schema constraints. The Controller evaluates the proposal, invokes Shadow review when required, and issues broker-controlled authorization before wrapper effects. Completion is checked against observed evidence. The final demonstration is limited to three turns and a 19-second local deadline. Hosted calls use persistent reservation and settlement accounting, with unresolved charges retained conservatively.

## Observations

On 16 October 2026, the direct summary run completed with two Primary calls. The first reviewed run used two Primary calls and one Shadow call: Shadow returned ALLOW and the read executed, but the subsequent Primary output requested permission and no summary was released. The refined continuation explicitly retained completed action state and observed content. Its live confirmation completed in two turns with two Primary calls and one Shadow call. The change does not prove the internal cause of the earlier output or establish a general improvement across models or tasks.

The source fixture stated: “Artificial report: 12 orders received; 10 shipped; 2 pending.” The released summary preserved those three quantities. Provider completion records include cited evidence IDs; the user-facing summary sentence itself does not print an inline citation. No stronger human-visible citation-format claim is made.

## Evidence and cost

Selected records retain all three hosted trajectories, including the incomplete one. Public run metadata normalizes a machine-local ledger path; provider response request IDs are removed from public derivatives. Event files are retained byte-for-byte and their chains can be verified. Operational provider request IDs embedded in those event records remain present; their release requires owner review. The complete internal backup remains separate. The eight hosted calls settled to a conservative aggregate of US$0.0172608 under a US$1 cap. No further hosted execution is authorized here.

## Interpretation

The evidence demonstrates integration of a Primary proposal, model-based review, enforced fixture read, retained continuation state, completion checking and recorded evidence within the specified task. It does not show that adding Shadow improves accuracy over a baseline, defeats all attacks, or meets production service requirements. Related-work and novelty assessment remain future work; no first-of-its-kind claim is made.

## Limitations and closure

Reference performance HARD-DEFERRED; L7 comparative acceptance INCOMPLETE; full formal acceptance INCOMPLETE; no production acceptance claim. The operator approved qualified demonstration closure on 19 October 2026. Publication is a separate decision.

## Attribution and reproducibility

The project was developed with ChatGPT/Codex assistance under Sebastian Weerakkody's engineering direction and operational review. See NOTICE, source maps, evidence records and offline reproduction instructions. No model weights are distributed. The package is a licence-pending review candidate.
