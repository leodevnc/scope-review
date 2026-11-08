# Design and boundaries

## Workflow

The user is a developer reviewing an agent tool permission change. Inputs are a baseline
policy, a proposed policy, and expected request decisions. Useful output is a structured
change report and a shell exit code suitable for a local pre-merge check. Success means
unobserved permission changes are reported even when all supplied cases still pass, and
malformed inputs cannot produce a passing report.

The provider boundary is a normalized principal/tool/logical-resource triple. No LLM is
called and no model adapter is implemented. A model may propose a tool call elsewhere;
this tool only studies the declared authority used to review such requests. Synthetic
cases are sufficient to reproduce the workflow without credentials or external services.

## 1. Compare permissions, not JSON lines

Grant order and redundant child grants do not change authority. Group grants by literal
principal/tool pair, then remove any prefix covered by another prefix in the same group.
The remaining subtrees form a disjoint set for that pair.

For each proposed subtree P:

1. If an old subtree contains P, it adds nothing.
2. Otherwise, the newly allowed region is P minus old subtrees nested inside P.
3. The request at P itself is a witness: no old ancestor covers it, and a strict descendant
   cannot cover it.

Repeat in reverse to find removed permissions. Two segment-prefix subtrees are either
nested or disjoint, so these cases exhaust their possible overlap. This reasoning depends
on containers themselves being valid logical request resources and on allow-only union
semantics. It does not generalize to conditions, wildcard languages, or explicit deny precedence.

Normalization and comparison use simple quadratic scans over at most 256 grants. The
implementation favors inspectability over indexing. No throughput or production scale claim
is made. Case evaluation is separate and scans only the matching principal/tool group's grants.

## 2. Do not infer safety from observed cases

Cases answer whether named workflows retain the expected decisions. They do not prove that
unobserved resources remain inaccessible. The symbolic comparison covers the entire valid
logical resource language in the supported profile. A passing case set cannot suppress a
new region or a removed region.

The gate treats both expansion and contraction as review-required. A narrower permission
set may reduce authority but still break a user workflow. The tool does not decide which
tradeoff is acceptable or mark a changed policy as approved.

## 3. Reject ambiguous inputs

JSON is UTF-8, limited to 1 MiB per file, with duplicate keys, invalid Unicode, and non-finite
numbers rejected. All policy and case fields are explicit; unsupported fields fail closed.
Principal/tool names are literal, and resource paths have a canonical spelling. No decoding,
case folding, filesystem traversal, symlink resolution, or URL normalization is performed on
logical resources.

The input files themselves must be regular non-symlink files. This is not protection from
a hostile local process racing filesystem changes. Use a trusted working directory. Expected
input failures produce fixed diagnostics without echoing source values. Reports, in contrast,
deliberately include identifying policy data. Argparse syntax errors may echo CLI arguments.

## 4. Keep reports as the durable output

There is no database or worker because comparison is a bounded pure operation. Load and
validate all three inputs before generating stdout. Exit codes distinguish a meaningful
change report from invalid input. Users can save stdout, but filesystem/output failures can
leave truncated redirected files. Consumers must check exit codes and parse the complete JSON.

The normalized policy hashes are useful for correlating reviews; they are not signed and
do not bind deployment state. Case changes have a separate fingerprint because changing an
expectation can hide a workflow regression without changing the policy.

## Questions explored

- Can sampled calls miss an expansion? Yes: the unchanged team-note request still succeeds
  when the parent notes subtree becomes allowed. Symbolic comparison exposes the extra region.
- Is every string-prefix match a descendant? No: `/notes/team` must not cover `/notes/teammate`.
- Does a stricter policy imply a safe rollout? No: an existing draft-write case can become denied.
- Is a policy with extra lines necessarily broader? No: a redundant descendant adds no authority.
- Can a witness prove a real exploit exists? No: it proves a decision difference under the
  declared logical model. Tool argument mapping, principal authentication, resource existence,
  and runtime enforcement remain separate integration questions.
