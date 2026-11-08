# Roadmap

## Implemented

- Strict allow-only logical subtree policy format and default-deny decisions.
- Normalized semantic comparison with added/removed regions and distinguishing requests.
- Expected-call regression checks and a conservative review gate.
- Deterministic JSON reports, fingerprints, bounded parsing, and offline CLI tests.

## Possible extensions

- An adapter for a specific application's permission manifest, with conformance tests proving
  that its runtime decisions match this profile. Do not silently approximate unsupported rules.
- A separately signed review receipt bound to policy and case fingerprints. Key custody,
  reviewer authority, and deployment verification would need their own design.
- Batch comparisons for multiple service configurations, preserving per-pair failures rather
  than combining all results into a misleading single approval.

These are not implemented. Explicit deny rules, roles, conditional attributes, wildcards,
live enforcement, and deployment are outside the initial scope.
