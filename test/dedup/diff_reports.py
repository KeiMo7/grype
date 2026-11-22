#!/usr/bin/env python3
"""Compare two grype JSON reports produced from the same image with a fixed DB snapshot.

Acceptance contract for the deterministic dedup change:

* the two reports must contain the same set of findings, identified by
  (vulnerability.id, vulnerability.namespace, artifact.name, artifact.version,
   artifact.type);
* the only allowed per-finding differences are the discovery path list
  (artifact.locations) and the optional "merge" audit block, both of which are
  produced by second-stage finding deduplication;
* any other addition, removal, or field change is a failure and exits non-zero,
  because it could mean a vulnerability was wrongly deleted or altered.

Run with -I (isolated mode) per the workspace's untrusted-data rules:
    python3 -I diff_reports.py before.json after.json
"""

import argparse
import json
import sys


def finding_key(match):
    v = match.get("vulnerability", {})
    a = match.get("artifact", {})
    return (
        v.get("id", ""),
        v.get("namespace", ""),
        a.get("name", ""),
        a.get("version", ""),
        a.get("type", ""),
    )


def location_paths(match):
    a = match.get("artifact", {})
    return sorted(
        loc.get("path", "")
        for loc in a.get("locations", [])
    )


def index(report):
    """Group findings by identity. A key may repeat in the BEFORE report: two path variants of
    one package carry identical (vuln, namespace, name, version, type) and are exactly the
    duplication finding-mode is meant to collapse. Such repeats are returned, not treated as a
    malformed report."""
    out = {}
    duplicates = {}
    for m in report.get("matches", []):
        k = finding_key(m)
        if k in out:
            duplicates.setdefault(k, 1)
            duplicates[k] += 1
        out.setdefault(k, []).append(m)
    return out, duplicates


def strip_allowed(match):
    """Return a deep-ish copy with the only fields allowed to differ removed."""
    m = json.loads(json.dumps(match))
    m.get("artifact", {}).pop("locations", None)
    m.pop("merge", None)
    return m


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("before")
    ap.add_argument("after")
    ap.add_argument(
        "--summary",
        action="store_true",
        help="print totals and per-merge details for human/annotator review",
    )
    args = ap.parse_args()

    with open(args.before, encoding="utf-8") as f:
        before = json.load(f)
    with open(args.after, encoding="utf-8") as f:
        after = json.load(f)

    before_idx, before_dups = index(before)
    after_idx, after_dups = index(after)

    bk, ak = set(before_idx), set(after_idx)
    added = sorted(ak - bk)
    removed = sorted(bk - ak)

    errors = []
    if added:
        errors.append(f"{len(added)} findings added in after: {added[:5]}")
    if removed:
        errors.append(f"{len(removed)} findings removed in after: {removed[:5]}")

    # field-level comparison on findings present in both reports. BEFORE may hold several path
    # variants of one identity; each must match the AFTER survivor modulo allowed fields.
    changed = []
    for k in sorted(bk & ak):
        after_matches = after_idx[k]
        # finding-mode output must be unique per identity; a surviving duplicate means the
        # merge did not happen when it should have.
        if len(after_matches) > 1:
            errors.append(
                f"finding {k} still has {len(after_matches)} entries in after (expected one after merge)"
            )
            continue
        a = strip_allowed(after_matches[0])
        if not any(strip_allowed(b) == a for b in before_idx[k]):
            changed.append(k)
    if changed:
        errors.append(
            f"{len(changed)} findings changed outside the allowed fields: {changed[:5]}"
        )

    before_total = len(before.get("matches", []))
    after_total = len(after.get("matches", []))
    merge_count = sum(1 for m in after.get("matches", []) if m.get("merge"))
    truncated = sum(
        1 for m in after.get("matches", []) if m.get("merge", {}).get("pathsTruncated")
    )
    # every before-duplicate identity must have collapsed: after count < before count for it
    collapsed = sum(before_dups[k] - 1 for k in before_dups)

    print("== grype report comparison ==")
    print(f"before matches: {before_total}")
    print(f"after  matches: {after_total}")
    print(f"duplicate identities before (merge candidates): {len(before_dups)}")
    print(f"entries collapsed by the merge: {collapsed}")
    print(f"findings carrying a merge block: {merge_count}")
    print(f"findings with truncated paths:   {truncated}")
    if after_dups:
        print(
            f"WARNING: {len(after_dups)} duplicate identities remain in after: "
            f"{list(after_dups)[:5]}",
            file=sys.stderr,
        )

    if args.summary:
        print("\n== merged finding details ==")
        for m in after.get("matches", []):
            mg = m.get("merge")
            if not mg:
                continue
            k = finding_key(m)
            print(f"\n{k[0]} on {k[2]}@{k[3]} ({k[4]})")
            print(f"  reason:          {mg.get('reason')}")
            print(f"  merged records:  {len(mg.get('mergedFrom', []))}")
            print(f"  after paths:     {location_paths(m)}")
            if mg.get("pathsTruncated"):
                print(f"  paths dropped:   {mg.get('pathsDropped')}")
            for rec in mg.get("mergedFrom", []):
                print(
                    f"    - fp={rec.get('fingerprint', '')[:12]} "
                    f"version={rec.get('packageVersion')} "
                    f"constraint={rec.get('constraint')} "
                    f"unaffected={rec.get('unaffected')} "
                    f"paths={rec.get('paths')}"
                )

    if errors:
        print("\nDIFF FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    print("\nOK: no finding added, removed, or changed outside merge/location fields")


if __name__ == "__main__":
    main()
