# Selected evidence

| Run suffix | Build | Result | Calls |
|---|---|---|---|
| f454afb1469543fd9e7612f3e3838ca8 | hosted 0.3 | Direct summary COMPLETED | 2 Primary |
| 8f51e3c7fd004245939397d7afc1b234 | hosted 0.3 | Reviewed read EXECUTED; continuation REQUESTED, no summary | 2 Primary + 1 Shadow |
| f63f2cbe9dca4630ac39401700ffcff1 | confirmation 0.5 | Reviewed read and completion COMPLETED | 2 Primary + 1 Shadow |

All three occurred on 16 October 2026. Raw event chains are retained unchanged, including operational provider request IDs embedded in their provenance fields. Selected provider prompts and outputs are supplied; request IDs in response metadata are removed. Run metadata replaces a local ledger path. See REDACTIONS.json for original/public hashes and exact changes. Internal file_hashes in historical run.json refer to originals; use PUBLICATION-MANIFEST.json for public derivatives. Never present a redacted file as byte-identical to the original.

The historical spend ledger is evidence only; it is not installed as a new executable campaign. It retains all eight calls and the extension record. New offline verification writes to a temporary workspace and keeps selected-evidence unchanged.

Offline reports retain historical pass/fail lists, not new model calls. New packaging results appear in validation-output. Original archive integrity was reviewed at qualified closure, but this public subset is not the entire historical project archive.
