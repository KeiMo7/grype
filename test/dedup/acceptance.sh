#!/usr/bin/env bash
# Acceptance harness for deterministic match dedup.
#
# Scans one fixed set of inputs (SBOM fixtures, no network or image pull) twice against one
# fixed DB snapshot: once with the legacy dedup behavior and once with finding-mode dedup, and
# verifies with diff_reports.py that the only differences are the merge/path fields.
#
# Requirements:
#   - a pre-built grype binary path passed via GRYPE_BIN (default: ./grype)
#   - a local grype DB directory passed via GRYPE_DB_DIR (auto-update disabled)
#   - python3 on PATH (the diff tool runs with -I)
#
# Usage:
#   GRYPE_BIN=./grype GRYPE_DB_DIR=/path/to/db ./test/dedup/acceptance.sh [sbom ...]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRYPE_BIN="${GRYPE_BIN:-./grype}"
GRYPE_DB_DIR="${GRYPE_DB_DIR:-}"
OUT_DIR="${OUT_DIR:-$(mktemp -d)}"

if [ ! -x "${GRYPE_BIN}" ]; then
  echo "grype binary not executable: ${GRYPE_BIN}" >&2
  exit 2
fi
if [ -z "${GRYPE_DB_DIR}" ]; then
  echo "GRYPE_DB_DIR must point at a fixed local DB snapshot" >&2
  exit 2
fi

if [ "$#" -eq 0 ]; then
  echo "pass one or more SBOM files; or extend this script with a fixture list" >&2
  exit 2
fi

mkdir -p "${OUT_DIR}/legacy" "${OUT_DIR}/finding"

run_scan() {
  config_mode="$1"
  input="$2"
  out="$3"
  name="$(basename "${input}")"
  config_file="${OUT_DIR}/config-${config_mode}.yaml"
  {
    printf 'check-for-app-update: false\n'
    printf 'db:\n'
    printf '  cache-dir: %s\n' "${GRYPE_DB_DIR}"
    printf '  auto-update: false\n'
    printf '  validate-age: false\n'
    printf 'dedup:\n'
    printf '  mode: %s\n' "${config_mode}"
  } > "${config_file}"
  "${GRYPE_BIN}" "sbom:${input}" -o json \
    -c "${config_file}" \
    > "${out}"
}

status=0
for input in "$@"; do
  name="$(basename "${input}")"
  echo "== scanning ${name}"
  run_scan legacy  "${input}" "${OUT_DIR}/legacy/${name}"
  run_scan finding "${input}" "${OUT_DIR}/finding/${name}"

  if ! python3 -I "${SCRIPT_DIR}/diff_reports.py" \
        "${OUT_DIR}/legacy/${name}" "${OUT_DIR}/finding/${name}" --summary; then
    echo "DIFF CONTRACT VIOLATED for ${name}" >&2
    status=1
  fi
done

# Multi-architecture acceptance: two SBOMs that describe the same image's amd64 and arm64
# variants must produce two independent findings that never merge. Pass them as the last two
# arguments named *amd64*.json / *arm64*.json, or place pairs under test/dedup/multiarch/.
MULTIARCH_DIR="${SCRIPT_DIR}/multiarch"
if [ -d "${MULTIARCH_DIR}" ]; then
  shopt -s nullglob
  amd_files=("${MULTIARCH_DIR}"/*amd64*.json)
  if [ "${#amd_files[@]}" -gt 0 ]; then
    echo "== multi-architecture checks"
    for amd in "${amd_files[@]}"; do
      arm="${amd/amd64/arm64}"
      if [ ! -f "${arm}" ]; then
        continue
      fi
      run_scan finding "${amd}" "${OUT_DIR}/finding/multi-amd64.json"
      run_scan finding "${arm}" "${OUT_DIR}/finding/multi-arm64.json"
      python3 -I "${SCRIPT_DIR}/multiarch_check.py" \
        "${OUT_DIR}/finding/multi-amd64.json" \
        "${OUT_DIR}/finding/multi-arm64.json" || status=1
    done
  fi
fi

echo "reports written under ${OUT_DIR}"
exit "${status}"
