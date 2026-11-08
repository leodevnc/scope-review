import itertools
import json
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

from scope_review.core import (
    MAX_FILE, Invalid, cases, decide, differences, encode,
    fingerprint, load, policy, resource, review,
)


ROOT = Path(__file__).resolve().parents[1]


def document(*paths, principal="agent", tool="notes.read"):
    return {"version": 1, "grants": [
        {"principal": principal, "tool": tool, "resource": path} for path in paths]}


def case_document(path="/notes/team", expect="allow"):
    return {"version": 1, "cases": [{"id": "sample", "principal": "agent",
                                    "tool": "notes.read", "resource": path, "expect": expect}]}


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.before = load(ROOT / "examples/before.json")
        self.after = load(ROOT / "examples/proposed.json")
        self.cases = load(ROOT / "examples/cases.json")

    def cli(self, before, after, cases_path):
        return subprocess.run([sys.executable, "-m", "scope_review", str(before), str(after),
                               "--cases", str(cases_path)], cwd=ROOT,
                              capture_output=True, timeout=10)

    def test_real_cli_reports_new_access_and_broken_workflow(self):
        paths = [ROOT / "examples" / name for name in ("before.json", "proposed.json", "cases.json")]
        originals = [path.read_bytes() for path in paths]
        result = self.cli(*paths)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["gate"], "review_required")
        self.assertEqual(report["summary"], {"added_regions": 1, "removed_regions": 1,
                                           "cases": 4, "changed_cases": 2, "expectation_failures": 2})
        self.assertEqual(report["added"][0]["exclude_subtrees"], ["/notes/team"])
        self.assertEqual(report["removed"][0]["exclude_subtrees"], ["/drafts/team"])
        self.assertEqual(report["cases"][0]["id"], "회의-notes-read")
        self.assertEqual(originals, [path.read_bytes() for path in paths])
        # Persist the real CLI output and read it in a fresh process.
        saved = self.root / "report.json"
        saved.write_bytes(result.stdout)
        checked = subprocess.run([sys.executable, "-c",
                                  "import json,sys; r=json.load(open(sys.argv[1])); assert r['gate']=='review_required'",
                                  str(saved)], capture_output=True, timeout=10)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(result.stdout, self.cli(*paths).stdout)

    def test_real_cli_semantically_equivalent_policy_passes(self):
        result = self.cli(ROOT / "examples/before.json", ROOT / "examples/equivalent.json",
                          ROOT / "examples/cases.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["gate"], "pass")
        self.assertEqual(report["policy_fingerprints"]["before"], report["policy_fingerprints"]["after"])

    def test_unknown_fields_fail_with_no_partial_report_or_value_echo(self):
        self.after["grants"][-1]["PRIVATE_SENTINEL"] = "PRIVATE_VALUE"
        path = self.root / "invalid.json"
        path.write_bytes(encode(self.after))
        result = self.cli(ROOT / "examples/before.json", path, ROOT / "examples/cases.json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"PRIVATE", result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_expected_mismatch_fails_even_without_policy_change(self):
        result = review(document("/notes"), document("/notes"), case_document(expect="deny"))
        self.assertEqual(result["summary"]["expectation_failures"], 1)
        self.assertEqual(result["gate"], "review_required")

    def test_unobserved_expansion_and_contraction_both_require_review(self):
        for old, new in [(document("/notes/team"), document("/notes")),
                         (document("/notes"), document("/notes/team"))]:
            with self.subTest(old=old):
                result = review(old, new, case_document())
                self.assertEqual(result["summary"]["changed_cases"], 0)
                self.assertEqual(result["summary"]["expectation_failures"], 0)
                self.assertEqual(result["gate"], "review_required")

    def test_subtree_matching_uses_segment_boundaries(self):
        compiled = policy(document("/notes/team"))
        self.assertEqual(decide(compiled, "agent", "notes.read", "/notes/team"), "allow")
        self.assertEqual(decide(compiled, "agent", "notes.read", "/notes/team/a"), "allow")
        for path in ("/notes/teammate", "/notes", "/Notes/team"):
            self.assertEqual(decide(compiled, "agent", "notes.read", path), "deny")

    def test_principal_and_tool_are_literal_independent_dimensions(self):
        old = policy(document("/", principal="one", tool="read"))
        new = policy(document("/", principal="two", tool="write"))
        self.assertEqual(len(differences(new, old)), 1)
        self.assertEqual(len(differences(old, new)), 1)
        self.assertEqual(decide(old, "two", "read", "/a"), "deny")
        self.assertEqual(decide(old, "one", "write", "/a"), "deny")

    def test_empty_policy_defaults_to_deny(self):
        compiled = policy(document())
        self.assertEqual(decide(compiled, "agent", "notes.read", "/"), "deny")
        result = review(document(), document(), case_document(expect="deny"))
        self.assertEqual(result["gate"], "pass")

    def test_root_expansion_and_holes(self):
        changes = differences(policy(document("/")), policy(document("/a", "/b/c")))
        self.assertEqual(changes[0]["include_subtree"], "/")
        self.assertEqual(changes[0]["exclude_subtrees"], ["/a", "/b/c"])
        self.assertEqual(changes[0]["witness"]["resource"], "/")

    def test_normalization_discards_redundant_descendants(self):
        a = policy(document("/notes/team/x", "/notes", "/notes/team"))
        b = policy(document("/notes"))
        self.assertEqual(a, b)
        self.assertEqual(fingerprint(a), fingerprint(b))
        self.assertEqual(differences(a, b), [])

    def test_removed_leaf_and_added_sibling_are_separate(self):
        before, after = policy(document("/a/x", "/a/y")), policy(document("/a/y", "/a/z"))
        self.assertEqual(differences(after, before)[0]["include_subtree"], "/a/z")
        self.assertEqual(differences(before, after)[0]["include_subtree"], "/a/x")

    def test_input_order_does_not_change_policy_diff(self):
        first = policy(document("/a", "/b/c"))
        second = policy(document("/b/c", "/a"))
        self.assertEqual(fingerprint(first), fingerprint(second))
        self.assertEqual(differences(policy(document("/")), first),
                         differences(policy(document("/")), second))

    def test_symbolic_regions_against_independent_finite_tree_oracle(self):
        rng = random.Random(2401)
        paths = ["/"] + ["/" + "/".join(parts) for depth in range(1, 4)
                          for parts in itertools.product(("a", "b"), repeat=depth)]

        def oracle(grants, path):
            parts = path.strip("/").split("/") if path != "/" else []
            for grant in grants:
                prefix = grant.strip("/").split("/") if grant != "/" else []
                if parts[:len(prefix)] == prefix:
                    return True
            return False

        for _ in range(200):
            old = rng.sample(paths, rng.randrange(7))
            new = rng.sample(paths, rng.randrange(7))
            added = differences(policy(document(*new)), policy(document(*old)))
            removed = differences(policy(document(*old)), policy(document(*new)))
            for path in paths + ["/c/unseen", "/a/c/unseen"]:
                for regions, left, right in [(added, new, old), (removed, old, new)]:
                    represented = any(oracle([r["include_subtree"]], path)
                                      and not oracle(r["exclude_subtrees"], path) for r in regions)
                    self.assertEqual(represented, oracle(left, path) and not oracle(right, path))
            for regions, left, right in [(added, new, old), (removed, old, new)]:
                for region in regions:
                    witness = region["witness"]["resource"]
                    self.assertTrue(oracle(left, witness))
                    self.assertFalse(oracle(right, witness))

    def test_duplicate_grants_and_case_ids_rejected(self):
        with self.assertRaises(Invalid):
            policy(document("/a", "/a"))
        value = case_document()
        value["cases"] *= 2
        with self.assertRaises(Invalid):
            cases(value)

    def test_policy_versions_shapes_and_wildcards_rejected(self):
        invalid = [{}, [], {"version": True, "grants": []}, {"version": 2, "grants": []},
                   {"version": 1, "grants": {}, "deny": []},
                   document("/a", principal="*"), document("/a", tool="notes.*")]
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(Invalid):
                policy(item)

    def test_noncanonical_resources_rejected_not_silently_normalized(self):
        invalid = ["", "a", "/a/", "/a//b", "/a/../b", "/a/./b", "/a%2fb",
                   "/a\\b", "/a?x=1", "/a#x", "/a/*", "/" + "a" * 65,
                   "/" + "/".join(["a"] * 17), None, True]
        for path in invalid:
            with self.subTest(path=path), self.assertRaises(Invalid):
                resource(path)

    def test_case_validation_bounds_and_expectations(self):
        invalid = ["ALLOW", True, None, {}, []]
        for expected in invalid:
            with self.subTest(expected=expected), self.assertRaises(Invalid):
                cases(case_document(expect=expected))
        for value in [{"version": 1, "cases": []}, {"version": False, "cases": []}]:
            with self.assertRaises(Invalid):
                cases(value)
        for label in ["", "x\nprivate", "x" * 129]:
            value = case_document()
            value["cases"][0]["id"] = label
            with self.assertRaises(Invalid):
                cases(value)

    def test_policy_and_case_count_limits(self):
        with self.assertRaises(Invalid):
            policy(document(*[f"/item-{i}" for i in range(257)]))
        value = case_document()
        value["cases"] = [{**value["cases"][0], "id": str(i)} for i in range(1025)]
        with self.assertRaises(Invalid):
            cases(value)

    def test_json_duplicate_nonfinite_unicode_and_depth_errors(self):
        path = self.root / "bad.json"
        invalid = [b'{"version":1,"version":1}', b'{"x":NaN}', b'{"x":1e999}',
                   b'{"x":"\\ud800"}', b'\xff', '{}'.encode("utf-16"), b'{',
                   b'[' * 2000 + b'0' + b']' * 2000]
        for raw in invalid:
            path.write_bytes(raw)
            with self.subTest(raw=raw[:40]), self.assertRaises(Invalid):
                load(path)

    def test_file_size_limit_and_symlinks(self):
        path = self.root / "big.json"
        path.write_bytes(b" " * (MAX_FILE + 1))
        with self.assertRaises(Invalid):
            load(path)
        link = self.root / "link"
        link.symlink_to(ROOT / "examples/before.json")
        with self.assertRaises(Invalid):
            load(link)

    def test_missing_file_has_safe_diagnostic_and_no_output(self):
        result = self.cli(self.root / "PRIVATE_NAME", ROOT / "examples/proposed.json",
                          ROOT / "examples/cases.json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"PRIVATE_NAME", result.stderr)

    def test_expected_cases_are_not_a_sampling_based_permission_proof(self):
        result = review(document("/notes/team"), document("/notes"), case_document())
        self.assertTrue(all(c["matches_expectation"] for c in result["cases"]))
        self.assertEqual(result["gate"], "review_required")
        self.assertEqual(result["added"][0]["witness"]["resource"], "/notes")


if __name__ == "__main__":
    unittest.main()
