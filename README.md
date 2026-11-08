# Scope Review

Review agent tool permission changes before rollout.

A developer changes a meeting assistant from reading `/notes/team` to reading `/notes`.
Existing team-note tests still pass, but private notes have become accessible. At the same
time, narrowing its draft-write scope can break an existing workflow.

Scope Review compares two explicit policies and checks expected tool-call decisions. It
returns added and removed permission regions, concrete logical requests that distinguish
the policies, and case failures. It is an offline developer tool, not a runtime permission
enforcer or a deployment service.

## Run

Python 3.11+; no runtime dependencies, credentials, model, or network connection.
From this checkout:

```sh
python3 -m scope_review examples/before.json examples/proposed.json \
  --cases examples/cases.json
```

The example intentionally exits **1** (`review_required`). Its JSON report shows:

- Read access added under `/notes`, excluding the already-allowed `/notes/team` subtree.
- Write access removed under `/drafts`, excluding the still-allowed `/drafts/team` subtree.
- Two changed case decisions and two expectation failures among four cases.

All supplied identifiers are synthetic. The decisions are produced by the actual comparison
engine, not model fixtures or a mock authorization service. The multilingual case ID is preserved.

Reordering grants or adding a redundant descendant does not change permissions:

```sh
python3 -m scope_review examples/before.json examples/equivalent.json \
  --cases examples/cases.json
```

This exits **0** (`pass`). To retain a report, redirect stdout to a new local file:

```sh
python3 -m scope_review examples/before.json examples/proposed.json \
  --cases examples/cases.json > review.json
```

Check the exit status. Shell redirection can create an empty file even when inputs are invalid;
file existence is not a successful review. The program itself never modifies the inputs.

## Policy contract

```json
{
  "version": 1,
  "grants": [
    {"principal": "meeting-assistant", "tool": "notes.read", "resource": "/notes/team"}
  ]
}
```

A grant allows that exact principal/tool pair on the named resource **and all its descendants**.
Everything else is denied. `/notes/team` covers `/notes/team/weekly`, not `/notes/teammate`.
`/` covers every valid logical resource. Matching is case-sensitive.

Resources are logical names, not filesystem paths or URLs. Each segment contains ASCII letters,
digits, underscores, or hyphens, with at most 64 characters and 16 levels. Trailing slashes,
empty segments, dot segments, percent encoding, query strings, and backslashes are rejected,
not normalized. Principal/tool identifiers contain 1-64 ASCII letters, digits, `_`, `.`, `:`,
or `-`, beginning with a letter or digit.

Policies permit up to 256 grants, including an empty deny-all list. Duplicate grants, unknown
fields, unsupported versions, wildcards, roles, explicit deny rules, and conditions are rejected.
This restricted format is **not AWS IAM, OAuth scopes, MCP authorization, or an import of any
provider's policy language**. An integration must explicitly map its authority model to this
contract and verify that mapping independently.

## Expected decisions

```json
{
  "version": 1,
  "cases": [
    {"id": "private-notes-boundary", "principal": "meeting-assistant",
     "tool": "notes.read", "resource": "/notes/private/budget", "expect": "deny"}
  ]
}
```

Supply 1-1,024 cases with unique IDs and `expect: "allow"` or `"deny"`. Expectations apply to
the **proposed** policy. Reports show both old and new decisions. These are representative
requests, not a log of executed tool calls; no tool handler is invoked.

## Gate and report

| Exit | Meaning |
| --- | --- |
| 0 | Policies allow the same requests within this profile, and all expectations match |
| 1 | Any added/removed permission region or any expectation failure requires review |
| 2 | Invalid/unsupported input, resource limit, or I/O failure |

Even an intentional contraction requires review: it may break a workflow not represented in
the cases. There is no automated approval override or deploy command. Decide and authorize a
change outside this tool, using the report as evidence rather than as the approval itself.

`added` and `removed` each contain regions represented as an included subtree minus excluded
subtrees. Each has a witness request in the difference. Such a request need not name a resource
that currently exists; comparison concerns possible logical requests, not an inventory scan.

Policy fingerprints identify normalized semantics in this limited profile, independent of grant
order and redundant descendants. The case fingerprint includes case order and expectations.
Neither is a signature, proof of deployed configuration, nor an approval token. Reports intentionally
contain principal names, resource paths, and case IDs; review them before sharing private policies.

## Test and install

```sh
python3 -m unittest discover -s tests -v
```

Optional installation into a virtual environment: `python3 -m pip install .`, then use
`scope-review` with the same arguments. Packaging needs setuptools 68+; running directly from
the checkout needs no installation or downloads.

See [design decisions](docs/design.md), [reproducible tests](docs/testing.md), and
[roadmap](docs/roadmap.md). MIT licensed.
