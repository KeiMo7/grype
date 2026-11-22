package remediation

import (
	"fmt"
	"slices"
	"strings"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
)

// NewPlan computes a remediation plan over the given (already filtered) match
// results. The input matches are treated as read-only; the plan is built from
// copies. The result is a pure function of the input: the same matches always
// produce the same plan, regardless of map or insertion order.
func NewPlan(matches match.Matches) Plan {
	byPkg := matches.AllByPkgID()

	ids := make([]string, 0, len(byPkg))
	for id := range byPkg {
		ids = append(ids, string(id))
	}
	slices.Sort(ids)

	plan := Plan{Packages: make([]PackagePlan, 0, len(ids))}
	for _, id := range ids {
		ms := byPkg[pkg.ID(id)]
		// sort findings up front so nothing downstream depends on iteration order
		slices.SortFunc(ms, func(a, b match.Match) int {
			if c := strings.Compare(a.Vulnerability.ID, b.Vulnerability.ID); c != 0 {
				return c
			}
			return strings.Compare(a.Vulnerability.Namespace, b.Vulnerability.Namespace)
		})
		plan.Packages = append(plan.Packages, planPackage(ms))
	}

	slices.SortFunc(plan.Packages, func(a, b PackagePlan) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		if c := strings.Compare(a.Version, b.Version); c != 0 {
			return c
		}
		return strings.Compare(a.PackageID, b.PackageID)
	})

	return plan
}

// fixableFinding is a finding whose fix state is "fixed" with at least one
// recorded fix version strictly above the installed version.
type fixableFinding struct {
	Finding
	// fixVersions holds the parsed fix versions above the installed version,
	// sorted ascending by the ecosystem comparator.
	fixVersions []*version.Version
}

// stepCandidate pairs a candidate target version with its row in the coverage
// matrix (covers[idx][finding]).
type stepCandidate struct {
	target *version.Version
	idx    int
}

// pruneDominated drops candidates whose coverage is a subset of another
// candidate's coverage; among candidates with identical coverage only the
// first (the smallest version, candidates arrive sorted ascending) is kept.
func pruneDominated(viable []stepCandidate, covers [][]bool) []stepCandidate {
	subset := func(a, b []bool) bool {
		for i := range a {
			if a[i] && !b[i] {
				return false
			}
		}
		return true
	}
	keep := make([]stepCandidate, 0, len(viable))
	for i, a := range viable {
		dominated := false
		for j, b := range viable {
			if i == j || !subset(covers[a.idx], covers[b.idx]) {
				continue
			}
			// a is covered by b: dominated outright when b covers strictly more,
			// and on identical coverage the later (larger) version yields
			if !subset(covers[b.idx], covers[a.idx]) || j < i {
				dominated = true
				break
			}
		}
		if !dominated {
			keep = append(keep, a)
		}
	}
	return keep
}

// planPackage computes the plan for all findings of one package instance. The
// matches must all belong to the same package and be sorted deterministically.
//
//nolint:gocognit,funlen
func planPackage(ms []match.Match) PackagePlan {
	p := ms[0].Package

	pp := PackagePlan{
		PackageID: string(p.ID),
		Name:      p.Name,
		Version:   p.Version,
		Type:      string(p.Type),
		PURL:      p.PURL,
	}

	format := pkg.VersionFormat(p)
	if format == version.UnknownFormat {
		// some ecosystems (npm, composer, ...) are not mapped by pkg.VersionFormat;
		// fall back to the package-type parsing the DB transformers use
		format = version.ParseFormat(string(p.Type))
	}
	pp.VersionFormat = format.String()

	unplannable := func(reason string) PackagePlan {
		pp.Status = StatusManualReview
		pp.StatusReason = reason
		for _, m := range ms {
			pp.Residual = append(pp.Residual, Residual{
				Finding: findingFrom(m),
				Reason:  ReasonPackageUnplannable,
				Detail:  fmt.Sprintf("package could not be planned: %s", reason),
			})
		}
		return pp
	}

	if format == version.UnknownFormat {
		return unplannable(fmt.Sprintf("unknown version format for package type %q", p.Type))
	}

	current := version.New(p.Version, format)
	if err := current.Validate(); err != nil {
		return unplannable(fmt.Sprintf("unable to parse installed version %q as %s: %v", p.Version, format, err))
	}

	pp.Annotations = annotationsFor(p.Version, format)

	// classify every finding; anything that cannot be cleared by an upgrade
	// lands in the residual set with its own reason
	var fixable []fixableFinding
	for _, m := range ms {
		f := findingFrom(m)
		switch m.Vulnerability.Fix.State {
		case vulnerability.FixStateFixed:
			if len(m.Vulnerability.Fix.Versions) == 0 {
				pp.Residual = append(pp.Residual, Residual{
					Finding: f,
					Reason:  ReasonDataAnomaly,
					Detail:  "fix state is \"fixed\" but no fix versions are recorded",
				})
				continue
			}
			var above []*version.Version
			for _, raw := range m.Vulnerability.Fix.Versions {
				fv := version.New(raw, format)
				if err := fv.Validate(); err != nil {
					return unplannable(fmt.Sprintf("unable to parse fix version %q for %s as %s: %v", raw, f.VulnerabilityID, format, err))
				}
				cmp, err := current.Compare(fv)
				if err != nil {
					return unplannable(fmt.Sprintf("unable to compare installed version %q with fix version %q: %v", p.Version, raw, err))
				}
				if cmp < 0 {
					// strictly above the installed version only; never plan a downgrade
					above = append(above, fv)
				}
			}
			if len(above) == 0 {
				pp.Residual = append(pp.Residual, Residual{
					Finding: f,
					Reason:  ReasonFixNotAboveCurrent,
					Detail:  "all recorded fix versions are at or below the installed version",
				})
				continue
			}
			if !sortVersionsChecked(above) {
				return unplannable(fmt.Sprintf("unable to determine a consistent order across the fix versions of %s", f.VulnerabilityID))
			}
			fixable = append(fixable, fixableFinding{Finding: f, fixVersions: above})
		case vulnerability.FixStateNotFixed:
			pp.Residual = append(pp.Residual, Residual{
				Finding: f,
				Reason:  ReasonNoFixAvailable,
				Detail:  "the vendor has not released a fix",
			})
		case vulnerability.FixStateWontFix:
			pp.Residual = append(pp.Residual, Residual{
				Finding: f,
				Reason:  ReasonWontFix,
				Detail:  "the vendor has stated this will not be fixed",
			})
		default:
			pp.Residual = append(pp.Residual, Residual{
				Finding: f,
				Reason:  ReasonInsufficientInfo,
				Detail:  fmt.Sprintf("fix state is %q; not enough information to plan an upgrade", m.Vulnerability.Fix.State),
			})
		}
	}

	pp.Status = StatusPlanned
	if len(fixable) == 0 {
		return pp
	}

	// candidate targets: every recorded fix version above the installed version,
	// deduplicated and sorted ascending by the ecosystem comparator
	targets := candidateTargets(fixable)
	if targets == nil {
		return unplannable("unable to determine a consistent order across the candidate fix versions")
	}

	covers := make([][]bool, len(targets)) // covers[target][finding]
	for ti, t := range targets {
		covers[ti] = make([]bool, len(fixable))
		for fi, f := range fixable {
			covers[ti][fi] = targetCovers(t, f)
		}
	}

	// does a single target clear every fixable finding? recommend the smallest one
	fullCover := -1
	for ti := range targets {
		all := true
		for fi := range fixable {
			if !covers[ti][fi] {
				all = false
				break
			}
		}
		if all {
			fullCover = ti
			break // targets are sorted ascending: the first full cover is the minimal one
		}
	}

	if fullCover >= 0 {
		pp.Steps = []Step{stepFor(targets[fullCover], covers[fullCover], fixable, pp.Residual)}
		return pp
	}

	// no single version clears everything: offer every viable target as a step,
	// ordered by what each leaves behind (least severe residual, then fewest).
	// Dominated targets -- those whose coverage is a subset of another
	// candidate's -- are pruned: nobody should be told to upgrade to a version
	// that clears strictly less than an alternative. Among candidates with
	// identical coverage only the smallest version is kept.
	var viable []stepCandidate
	for ti, t := range targets {
		covered := 0
		for fi := range fixable {
			if covers[ti][fi] {
				covered++
			}
		}
		if covered > 0 {
			viable = append(viable, stepCandidate{target: t, idx: ti})
		}
	}
	viable = pruneDominated(viable, covers)

	steps := make([]Step, 0, len(viable))
	for _, v := range viable {
		steps = append(steps, stepFor(v.target, covers[v.idx], fixable, pp.Residual))
	}
	slices.SortStableFunc(steps, func(a, b Step) int {
		if c := strings.Compare(severityRankKey(a.ResidualMaxSeverity), severityRankKey(b.ResidualMaxSeverity)); c != 0 {
			return c
		}
		if a.ResidualCount != b.ResidualCount {
			return a.ResidualCount - b.ResidualCount
		}
		if len(a.Resolves) != len(b.Resolves) {
			return len(b.Resolves) - len(a.Resolves)
		}
		// versions are known-comparable here; ties end on the raw string
		ta, tb := version.New(a.TargetVersion, format), version.New(b.TargetVersion, format)
		if cmp, err := ta.Compare(tb); err == nil && cmp != 0 {
			return cmp
		}
		return strings.Compare(a.TargetVersion, b.TargetVersion)
	})
	pp.Steps = steps

	// any fixable finding no target covers must still be accounted for
	coveredAny := make([]bool, len(fixable))
	for ti := range targets {
		for fi := range fixable {
			coveredAny[fi] = coveredAny[fi] || covers[ti][fi]
		}
	}
	for fi, f := range fixable {
		if !coveredAny[fi] {
			pp.Residual = append(pp.Residual, Residual{
				Finding: f.Finding,
				Reason:  ReasonNotCoveredByPlan,
				Detail:  "no recorded fix version both upgrades the package and covers this finding",
			})
		}
	}

	return pp
}

// findingFrom copies the planning-relevant fields out of a match. The match's
// own slices are never mutated.
func findingFrom(m match.Match) Finding {
	severity := "unknown"
	if m.Vulnerability.Metadata != nil && m.Vulnerability.Metadata.Severity != "" {
		severity = m.Vulnerability.Metadata.Severity
	}
	var fixVersions []string
	if len(m.Vulnerability.Fix.Versions) > 0 {
		fixVersions = slices.Clone(m.Vulnerability.Fix.Versions)
		slices.Sort(fixVersions)
	}
	return Finding{
		VulnerabilityID: m.Vulnerability.ID,
		Namespace:       m.Vulnerability.Namespace,
		Severity:        severity,
		FixState:        m.Vulnerability.Fix.State.String(),
		FixVersions:     fixVersions,
	}
}

// candidateTargets unions the fix versions of all fixable findings, deduplicated
// and sorted ascending. It returns nil if the versions cannot be consistently
// ordered (the caller then marks the package for manual review).
func candidateTargets(fixable []fixableFinding) []*version.Version {
	seen := map[string]bool{}
	var out []*version.Version
	for _, f := range fixable {
		for _, fv := range f.fixVersions {
			if seen[fv.Raw] {
				continue
			}
			seen[fv.Raw] = true
			out = append(out, fv)
		}
	}
	if !sortVersionsChecked(out) {
		return nil
	}
	return out
}

// targetCovers reports whether upgrading to t clears the finding: t must reach
// at least one of the finding's fix versions while staying on that fix
// version's release line.
func targetCovers(t *version.Version, f fixableFinding) bool {
	for _, fv := range f.fixVersions {
		if cmp, err := t.Compare(fv); err == nil && cmp >= 0 && sameReleaseLine(fv.Raw, t.Raw, t.Format) {
			return true
		}
	}
	return false
}

// stepFor builds the plan step for one upgrade target.
func stepFor(target *version.Version, cover []bool, fixable []fixableFinding, baseResidual []Residual) Step {
	step := Step{TargetVersion: target.Raw}
	residualMax := vulnerability.UnknownSeverity
	residualCount := len(baseResidual)
	for _, r := range baseResidual {
		if s := vulnerability.ParseSeverity(r.Severity); s > residualMax {
			residualMax = s
		}
	}
	for fi, f := range fixable {
		if cover[fi] {
			step.Resolves = append(step.Resolves, f.Finding)
		} else {
			residualCount++
			if s := vulnerability.ParseSeverity(f.Severity); s > residualMax {
				residualMax = s
			}
		}
	}
	step.ResidualCount = residualCount
	step.ResidualMaxSeverity = "none"
	if residualCount > 0 {
		step.ResidualMaxSeverity = residualMax.String()
	}
	return step
}

// annotationsFor notes pre-release and build-metadata usage on the installed
// version, per the package's documented comparison policy.
func annotationsFor(rawVersion string, format version.Format) []string {
	var out []string
	if isPrerelease(rawVersion, format) {
		out = append(out, "installed version is a pre-release; compared per ecosystem pre-release rules")
	}
	if hasBuildMetadata(rawVersion, format) {
		out = append(out, "installed version carries build metadata; metadata is ignored for version ordering")
	}
	return out
}

// sortVersionsChecked sorts ascending by ecosystem comparator, breaking ties on
// the raw string. It reports false if any pair could not be compared -- the
// caller must then refuse to plan rather than rely on a guessed order.
func sortVersionsChecked(vs []*version.Version) (ok bool) {
	ok = true
	slices.SortStableFunc(vs, func(a, b *version.Version) int {
		cmp, err := a.Compare(b)
		if err != nil {
			ok = false
			return strings.Compare(a.Raw, b.Raw)
		}
		if cmp != 0 {
			return cmp
		}
		return strings.Compare(a.Raw, b.Raw)
	})
	return ok
}

// severityRankKey pads a severity's rank so string comparison orders by rank.
func severityRankKey(severity string) string {
	if severity == "none" {
		return "0"
	}
	return fmt.Sprintf("%d", int(vulnerability.ParseSeverity(severity))+1)
}
