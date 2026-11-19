# Risk scoring (qualitative, not CVSS)

For every finding give integer scores 0-3 with a short `risk.rationale` (15-500 characters) and, when needed, `risk.assumptions`:

- **exposure**: 0 unreachable/dead code, 1 internal or trusted callers only, 2 authenticated or limited external access, 3 reachable by unauthenticated/external input (shown by source).
- **exploitability**: 0 theoretical, 1 significant prerequisites, 2 moderate constraints, 3 straightforward with crafted input.
- **impact**: 0 negligible, 1 limited disclosure/integrity, 2 meaningful account/data/service compromise, 3 code execution, broad privileged compromise, or severe sensitive-data exposure.

`verification_status`:
- `source-supported`: the vulnerable flow is visible in the source.
- `conditional`: depends on deployment or configuration you cannot see; state the assumption.
- `requires-review`: reachability or impact is uncertain (e.g. helper with no visible caller); state the assumption.

The local program computes severity from these scores (0-2 Low, 3-5 Medium, 6-7 High, 8-9 Critical), caps `conditional` at High and `requires-review` at Medium, and raises actively used weak password storage to at least High. Score honestly; do not tune numbers to reach a severity.
