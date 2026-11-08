# Reproducible checks

```sh
python3 -m unittest discover -s tests -v
```

The suite has 22 tests. It uses real local files and CLI subprocesses, with no network or
model calls. The end-to-end test runs the example, checks its exit status and JSON result,
persists that result, reads it in another process, reruns the comparison for determinism,
and confirms the original input bytes were not modified.

| Area | Evidence |
| --- | --- |
| Changed-policy workflow | One added region, one removed region, two changed decisions and two expectation failures |
| No-change workflow | Reordered/redundant grants pass, with equal normalized fingerprints |
| Coverage beyond cases | Expansion and contraction require review even with zero case failures |
| Prefix algebra | Root grants, excluded subtrees, siblings, removed leaves, case sensitivity and segment boundaries |
| Independent oracle | 200 seeded policy pairs checked against tuple-prefix enumeration of a small resource tree |
| Isolation | Different principals and tools never borrow each other's grants |
| Invalid input | Unknown fields, wildcards, unsupported versions, duplicate grants/IDs, malformed paths and expectations |
| Bounded parsing | File size, grant/case counts, duplicate JSON keys, non-finite numbers, invalid Unicode and excessive JSON recursion |
| Error behavior | Invalid late grant yields exit 2, no partial stdout report, and no private sentinel in diagnostics |

The finite oracle is a supporting experiment, not a substitute for the subtree reasoning in
[design](design.md). It checks represented membership and every returned witness against
an independently written tuple-based predicate. It does not measure production capacity.

## Manual example

```sh
python3 -m scope_review examples/before.json examples/proposed.json --cases examples/cases.json
```

Expected exit: `1`. Expected summary:

```json
{"added_regions":1,"removed_regions":1,"cases":4,"changed_cases":2,"expectation_failures":2}
```

Change the second file to `examples/equivalent.json` to get exit `0` and no differences.
An unknown field in any policy should produce exit `2` and no stdout JSON report.

## Offline installed-command check

With setuptools 68+ and wheel already installed locally:

```sh
source_dir="$PWD"
package_dir=$(mktemp -d /tmp/scope-review-package.XXXXXX)
python3 -m pip wheel --no-deps --no-build-isolation --no-index --wheel-dir "$package_dir" .
python3 -m venv "$package_dir/venv"
"$package_dir/venv/bin/python" -m pip install --no-index --no-deps \
  "$package_dir/scope_review-0.1.0-py3-none-any.whl"
cd "$package_dir"
"$package_dir/venv/bin/scope-review" "$source_dir/examples/before.json" \
  "$source_dir/examples/equivalent.json" --cases "$source_dir/examples/cases.json"
```

Expected exit: `0`. This exercises the wheel's entry point outside the source tree, without
downloading dependencies. The temporary directory is retained for inspection.

## Limits

No actual tools, authorization servers, or deployments are contacted. There is no evidence
here that a real runtime implements this policy faithfully, or that a model selects correct
tools. Directory race attacks, large-scale performance, and richer policy languages are not
covered. Human review must consider the actual principal and resource mapping.
