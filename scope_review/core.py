import hashlib
import json
import re
from pathlib import Path


MAX_FILE = 1024 * 1024
MAX_GRANTS = 256
MAX_CASES = 1024
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}\Z")
SEGMENT = re.compile(r"[a-zA-Z0-9_-]{1,64}\Z")


class Invalid(ValueError):
    """Expected input error with a fixed, value-free diagnostic."""


def encode(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False,
                       sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def load(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise Invalid("input must be a regular file, not a symbolic link")
    with path.open("rb") as stream:
        raw = stream.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise Invalid("input exceeds 1 MiB")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Invalid("duplicate JSON keys")
            result[key] = value
        return result

    def reject_constant(_):
        raise Invalid("non-finite JSON number")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=reject_constant)
        encode(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Invalid("invalid or unsupported UTF-8 JSON") from error


def fields(value, expected):
    if not isinstance(value, dict) or value.keys() != set(expected):
        raise Invalid("missing or unsupported fields")


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise Invalid("invalid principal or tool identifier")
    return value


def resource(value):
    if not isinstance(value, str) or not value.startswith("/"):
        raise Invalid("resource must be an absolute logical path")
    if value == "/":
        return value
    parts = value[1:].split("/")
    if len(parts) > 16 or any(not SEGMENT.fullmatch(part) for part in parts):
        raise Invalid("resource has unsupported segments or exceeds 16 levels")
    return value


def contains(parent, child):
    """Both arguments must already be canonical logical resource paths."""
    return parent == "/" or parent == child or child.startswith(parent + "/")


def policy(value):
    fields(value, ("version", "grants"))
    if type(value["version"]) is not int or value["version"] != 1:
        raise Invalid("unsupported policy version")
    if not isinstance(value["grants"], list) or len(value["grants"]) > MAX_GRANTS:
        raise Invalid("policy must contain at most 256 grants")
    groups = {}
    seen = set()
    for grant in value["grants"]:
        fields(grant, ("principal", "tool", "resource"))
        principal, tool = identifier(grant["principal"]), identifier(grant["tool"])
        path = resource(grant["resource"])
        key = (principal, tool, path)
        if key in seen:
            raise Invalid("duplicate grant")
        seen.add(key)
        groups.setdefault((principal, tool), []).append(path)
    # Removing redundant descendant grants makes semantic comparison independent of order.
    return {key: tuple(sorted(path for path in paths
                             if not any(other != path and contains(other, path) for other in paths)))
            for key, paths in groups.items()}


def cases(value):
    fields(value, ("version", "cases"))
    if type(value["version"]) is not int or value["version"] != 1:
        raise Invalid("unsupported case format version")
    if not isinstance(value["cases"], list) or not 1 <= len(value["cases"]) <= MAX_CASES:
        raise Invalid("provide 1-1024 expected-decision cases")
    seen = set()
    for case in value["cases"]:
        fields(case, ("id", "principal", "tool", "resource", "expect"))
        label = case["id"]
        if not isinstance(label, str) or not 1 <= len(label) <= 128 or any(ord(c) < 32 or ord(c) == 127 for c in label):
            raise Invalid("invalid case id")
        if label in seen:
            raise Invalid("duplicate case id")
        seen.add(label)
        identifier(case["principal"])
        identifier(case["tool"])
        resource(case["resource"])
        if case["expect"] not in ("allow", "deny"):
            raise Invalid("case expectation must be allow or deny")
    return value["cases"]


def decide(compiled, principal, tool, path):
    return "allow" if any(contains(parent, path) for parent in compiled.get((principal, tool), ())) else "deny"


def differences(left, right):
    """Describe exactly the resources allowed by left but not right, within this profile."""
    result = []
    for principal, tool in sorted(left):
        right_paths = right.get((principal, tool), ())
        for path in left[(principal, tool)]:
            if any(contains(other, path) for other in right_paths):
                continue
            excluded = [other for other in right_paths if contains(path, other)]
            result.append({
                "principal": principal, "tool": tool,
                "include_subtree": path, "exclude_subtrees": excluded,
                "witness": {"principal": principal, "tool": tool, "resource": path},
            })
    return result


def fingerprint(compiled):
    grants = [{"principal": principal, "tool": tool, "resource": path}
              for principal, tool in sorted(compiled) for path in compiled[(principal, tool)]]
    return hashlib.sha256(encode({"version": 1, "grants": grants})).hexdigest()


def review(before_document, after_document, case_document):
    before, after = policy(before_document), policy(after_document)
    checked_cases = cases(case_document)
    added = differences(after, before)
    removed = differences(before, after)
    outcomes = []
    for case in checked_cases:
        old = decide(before, case["principal"], case["tool"], case["resource"])
        new = decide(after, case["principal"], case["tool"], case["resource"])
        outcomes.append({**case, "before": old, "after": new, "changed": old != new,
                         "matches_expectation": new == case["expect"]})
    mismatches = sum(not outcome["matches_expectation"] for outcome in outcomes)
    changed_cases = sum(outcome["changed"] for outcome in outcomes)
    # Contractions can break unobserved workflows, so every semantic change requires review.
    blocked = bool(added or removed or mismatches)
    return {
        "format_version": 1,
        "gate": "review_required" if blocked else "pass",
        "policy_fingerprints": {"before": fingerprint(before), "after": fingerprint(after)},
        "case_fingerprint": hashlib.sha256(encode(case_document)).hexdigest(),
        "summary": {"added_regions": len(added), "removed_regions": len(removed),
                    "cases": len(outcomes), "changed_cases": changed_cases,
                    "expectation_failures": mismatches},
        "added": added, "removed": removed, "cases": outcomes,
        "scope": "Logical subtree grants only; no tool execution or deployment verification.",
    }
