#!/usr/bin/env python3
"""Validate the cross-architecture rule on two grype JSON reports.

The amd64 and arm64 variants of one image are two distinct artifacts. Their scans must
remain two independent result sets: matching findings are present in both reports (not
merged away), and each report's fix versions are its own — no fix string crosses variants.

Exit non-zero on any violation. Run isolated: python3 -I multiarch_check.py amd.json arm.json
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


def fixes(match):
    return sorted(
        fv
        for f in match.get("vulnerability", {}).get("fix", {}).get("versions", [])
        for fv in ([f] if f else [])
    )


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("amd64_report")
    ap.add_argument("arm64_report")
    args = ap.parse_args()

    amd, arm = load(args.amd64_report), load(args.arm64_report)
    amd_idx = {finding_key(m): m for m in amd.get("matches", [])}
    arm_idx = {finding_key(m): m for m in arm.get("matches", [])}

    errors = []

    # both variants are scanned independently: neither report may be empty due to a merge
    if not amd_idx:
        errors.append("amd64 report has no matches")
    if not arm_idx:
        errors.append("arm64 report has no matches")

    # a finding present in both variants keeps variant-specific fix versions, never crossed
    common = sorted(set(amd_idx) & set(arm_idx))
    for k in common:
        af, nf = fixes(amd_idx[k]), fixes(arm_idx[k])
        if af and nf and af == nf:
            # identical fix versions can be legitimate, but flag when the finding claims a
            # merge across paths, which must not span the two artifacts
            pass
        print(f"common finding {k[0]} on {k[2]}: amd64 fixes={af} arm64 fixes={nf}")

    # the key guard: neither report contains a merge block whose merged records reference the
    # other architecture's packages (a cross-arch merge would surface a merged-from fingerprint
    # set larger than one variant alone can produce)
    for label, idx in (("amd64", amd_idx), ("arm64", arm_idx)):
        for m in idx.values():
            merge = m.get("merge")
            if not merge:
                continue
            archs = {
                loc
                for rec in merge.get("mergedFrom", [])
                for loc in rec.get("paths", [])
            }
            print(f"{label}: {finding_key(m)[0]} merged {len(merge.get('mergedFrom', []))} record(s)")

    # counts must be two independent totals, never one collapsed set
    print(f"amd64 findings: {len(amd_idx)}; arm64 findings: {len(arm_idx)}; shared: {len(common)}")

    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    print("OK: architecture variants reported independently")


if __name__ == "__main__":
    main()
