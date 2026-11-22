package dedup

import (
	"fmt"
	"slices"

	"github.com/anchore/syft/syft/file"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
)

// Dedup applies second-stage deduplication over a matched result set. It never changes a match
// decision: every output match is built only from input matches, and under ModeLegacy the input
// is returned untouched with an empty Report. Under ModeFinding, findings sharing one explicit
// content key are merged into the strongest record, carrying the union of their discovery paths
// and a MergeAudit describing the fold.
//
// Failures while computing a key never drop a finding: the offending match is carried into the
// output unchanged and recorded in Report.Failures.
func Dedup(matches match.Matches, ctx pkg.Context, cfg Config) (match.Matches, Report) {
	if err := cfg.Validate(); err != nil {
		// invalid config is a caller programming error; preserve everything and explain it once
		return passthrough(matches, Report{Mode: string(cfg.Mode), Failures: []KeyFailure{{Error: err.Error()}}})
	}

	if cfg.Mode == ModeLegacy {
		return matches, Report{Mode: string(ModeLegacy), InputCount: matches.Count(), OutputCount: matches.Count()}
	}

	sourceArch := sourceArchitecture(ctx)

	groups, failures := groupByKey(matches.Sorted(), cfg, sourceArch)

	out := match.NewMatches()
	report := Report{
		Mode:       string(ModeFinding),
		InputCount: matches.Count(),
		Failures:   failures,
	}

	// deterministic group order for the audit report and stable downstream sorting
	keys := make([]findingKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b findingKey) int { return compareKey(a, b) })

	for _, k := range keys {
		members := groups[k]
		if len(members) == 1 {
			out.Add(members[0])
			continue
		}

		merged, truncated, _ := mergeGroup(members, cfg)
		out.Add(merged)

		report.MergedGroupCount++
		report.MergedGroups = append(report.MergedGroups, MergedGroup{
			Key:    k.String(),
			Reason: ReasonFindingKey,
			Kept:   refOf(merged, k.architecture),
			Merged: merged.MergeAudit.MergedFrom,
		})
		if truncated {
			report.PathsTruncated++
		}
	}

	report.OutputCount = out.Count()
	return out, report
}

// keyForFunc is the key computation used by grouping. It is a package-level variable solely so
// the failure-degradation path (recover, keep the raw finding) can be exercised deterministically
// in tests without depending on a real field that cannot fail; production always uses keyFor.
var keyForFunc = keyFor

// groupByKey partitions sorted input matches by finding key. A panic in key computation for one
// match isolates to that match: it is returned as a failure and kept out of grouping, so one bad
// record cannot lose the rest of the result set.
func groupByKey(matches []match.Match, cfg Config, sourceArch string) (map[findingKey][]match.Match, []KeyFailure) {
	groups := make(map[findingKey][]match.Match)
	var failures []KeyFailure

	for _, m := range matches {
		k, err := safeKeyFor(m, cfg, sourceArch)
		if err != nil {
			failures = append(failures, KeyFailure{
				Fingerprint:     m.Fingerprint().ID(),
				VulnerabilityID: m.Vulnerability.ID,
				PackageName:     m.Package.Name,
				Error:           err.Error(),
			})
			// failed matches bypass grouping entirely; they survive as their own singleton group
			groups[fallbackKey(m)] = []match.Match{m}
			continue
		}
		groups[k] = append(groups[k], m)
	}
	return groups, failures
}

// safeKeyFor computes a key, converting a panic in field extraction into an error so the
// degradation rule (keep the raw entry, never drop it) is enforceable and testable.
func safeKeyFor(m match.Match, cfg Config, sourceArch string) (k findingKey, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("dedup key computation failed: %v", r)
		}
	}()
	return keyForFunc(m, cfg, sourceArch), nil
}

// fallbackKey gives a failed match a group that cannot collide with any real finding key: the
// architecture field carries the failure marker, which no successful key produces.
func fallbackKey(m match.Match) findingKey {
	return findingKey{
		vulnerabilityID:        m.Vulnerability.ID,
		vulnerabilityNamespace: m.Vulnerability.Namespace,
		packageName:            m.Package.Name,
		packageVersion:         m.Package.Version,
		packageType:            string(m.Package.Type),
		architecture:           "key-failure:" + m.Fingerprint().ID(),
	}
}

// mergeGroup folds a non-empty, same-key group into one match. members arrive in the global
// sorted order; the strongest record is selected by the same authority comparison Merge uses,
// so the survivor does not depend on arrival order.
func mergeGroup(members []match.Match, cfg Config) (match.Match, bool, int) {
	strongest := 0
	for i := 1; i < len(members); i++ {
		if compareAuthority(members[i], members[strongest]) < 0 {
			strongest = i
		}
	}

	survivor := members[strongest]
	audit := &match.MergeAudit{Reason: ReasonFindingKey}

	// union discovery paths first, so the survivor carries every path the group reached
	pathSet := file.NewLocationSet(survivor.Package.Locations.ToSlice()...)

	for i, other := range members {
		if i == strongest {
			continue
		}
		audit.MergedFrom = append(audit.MergedFrom, recordOf(other))

		survivor.MergeFields(other)
		pathSet.Add(other.Package.Locations.ToSlice()...)
	}

	locations, truncated, dropped := capLocations(pathSet, cfg.MaxPaths)
	survivor.Package.Locations = locations
	audit.PathsTruncated = truncated
	audit.PathsDropped = dropped
	if truncated || len(audit.MergedFrom) > 0 {
		survivor.MergeAudit = audit
	}
	return survivor, truncated, dropped
}

// recordOf captures the auditable fields of one folded match. Paths are rendered as RealPath,
// annotating AccessPath when a symlink/virtual location makes it differ.
func recordOf(m match.Match) match.MergedRecord {
	rec := match.MergedRecord{
		Fingerprint:    m.Fingerprint().ID(),
		PackageVersion: m.Package.Version,
		Status:         m.Vulnerability.Status,
		Unaffected:     m.Vulnerability.Unaffected,
		FixVersions:    append([]string(nil), m.Vulnerability.Fix.Versions...),
		Paths:          locationStrings(m.Package.Locations),
	}
	if m.Vulnerability.Constraint != nil {
		rec.Constraint = m.Vulnerability.Constraint.String()
	}
	return rec
}

// locationStrings renders a location set deterministically, RealPath first and with the
// AccessPath appended when the content was reached through a different (e.g. symlinked) path.
func locationStrings(set file.LocationSet) []string {
	locs := set.ToSlice()
	out := make([]string, 0, len(locs))
	for _, l := range locs {
		if l.AccessPath != "" && l.AccessPath != l.RealPath {
			out = append(out, l.RealPath+" (via "+l.AccessPath+")")
			continue
		}
		out = append(out, l.RealPath)
	}
	return out
}

// capLocations truncates a location set to the configured limit. Locations are taken in the
// set's deterministic sorted order, so the retained prefix is stable across scans.
func capLocations(set file.LocationSet, maxPaths int) (file.LocationSet, bool, int) {
	locs := set.ToSlice()
	if maxPaths == UnlimitedPaths || len(locs) <= maxPaths {
		return set, false, 0
	}
	dropped := len(locs) - maxPaths
	return file.NewLocationSet(locs[:maxPaths]...), true, dropped
}

// compareAuthority wraps the match package's record-authority ordering. It is kept local so
// this file reads the ordering rule in one place.
func compareAuthority(a, b match.Match) int {
	return match.CompareRecordAuthority(a, b)
}

func compareKey(a, b findingKey) int {
	switch {
	case a.vulnerabilityID != b.vulnerabilityID:
		return cmpString(a.vulnerabilityID, b.vulnerabilityID)
	case a.vulnerabilityNamespace != b.vulnerabilityNamespace:
		return cmpString(a.vulnerabilityNamespace, b.vulnerabilityNamespace)
	case a.packageName != b.packageName:
		return cmpString(a.packageName, b.packageName)
	case a.packageVersion != b.packageVersion:
		return cmpString(a.packageVersion, b.packageVersion)
	case a.packageType != b.packageType:
		return cmpString(a.packageType, b.packageType)
	default:
		return cmpString(a.architecture, b.architecture)
	}
}

func cmpString(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func passthrough(matches match.Matches, report Report) (match.Matches, Report) {
	report.Mode = string(report.Mode)
	if report.Mode == "" {
		report.Mode = string(ModeLegacy)
	}
	report.InputCount = matches.Count()
	report.OutputCount = matches.Count()
	return matches, report
}
