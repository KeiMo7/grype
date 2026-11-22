# Deterministic match deduplication

This directory holds the acceptance tooling for grype's second-stage match deduplication
(`grype/match/dedup`). The design and rationale live in `../../DEDUP_DESIGN.md`.

## Configuration

Deduplication is configured under the `dedup` key in a grype config file (or the
`GRYPE_DEDUP_*` environment variables). The default is legacy behavior, unchanged from
grype without this feature:

```yaml
dedup:
  # legacy  (default): existing fingerprint-only dedup, no report changes
  # finding: deterministic finding-level dedup
  mode: finding

  # discovery paths retained on one merged finding; 0 = default (50), -1 = unlimited
  max-paths: 50

  # keep system and language packages of the same name/version as separate findings
  include-package-type: true

  # optional: write the full merge audit trail (which findings merged, on what rule,
  # which record survived) to this JSON file
  audit-report: dedup-audit.json
```

## Merge semantics under `mode: finding`

* One CVE hitting multiple version records of one package keeps the strongest record; the
  folded records' versions/constraints/fix versions appear in the `merge` block.
* One CVE on different packages (e.g. an OS package and a language package) stays separate
  while `include-package-type` is true — their fix paths differ.
* One package discovered through several paths (symlinks, multi-layer copies) becomes one
  finding whose `artifact.locations` is the union, truncated at `max-paths` with
  `merge.pathsTruncated` / `pathsDropped` annotated.
* amd64 and arm64 variants never merge: architecture (package metadata, else image source,
  dialect-canonicalized via the architecture qualifier aliases) is part of the key.
* If a dedup key cannot be computed for a finding, that finding is kept unmerged and listed
  in the audit report's `failures` — nothing is dropped.

## Acceptance

### Unit-level contract

`go test ./grype/match/dedup/...` covers multi-path merges, package-type/namespace/version
separation, cross-architecture non-merging, unaffected-record authority, path truncation,
key-failure degradation, order independence, and a no-finding-lost identity check.

### Report-level contract

`diff_reports.py` compares two JSON reports of the same input and fixed DB snapshot. It
fails unless the only differences are `artifact.locations` and the `merge` block:

```
python3 -I diff_reports.py before.json after.json --summary
```

### End-to-end harness

`acceptance.sh` scans fixed SBOM fixtures once in each mode against a fixed local DB and
runs the diff contract on every pair:

```
GRYPE_BIN=./grype GRYPE_DB_DIR=/path/to/db ./acceptance.sh
```

Multi-architecture SBOM pairs named `*amd64*.json` / `*arm64*.json` placed under
`multiarch/` additionally get the cross-architecture check via `multiarch_check.py`.

## Tracking unaffected -> affected changes across DB updates

Scan reports reflect the current database only. Changes in vulnerability status between two
database snapshots are tracked by the existing `grype db diff` command; its
`Test_packageStatusStates` pins the full status-transition table (including
not-vulnerable -> vulnerable reported as `added`).
