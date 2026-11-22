package remediation

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func testPkg(id, name, ver string, ty syftPkg.Type) pkg.Package {
	return pkg.Package{
		ID:      pkg.ID(id),
		Name:    name,
		Version: ver,
		Type:    ty,
	}
}

func testMatch(p pkg.Package, id, severity string, state vulnerability.FixState, fixVersions ...string) match.Match {
	return match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        id,
				Namespace: "test:namespace",
			},
			Fix: vulnerability.Fix{
				State:    state,
				Versions: fixVersions,
			},
			Metadata: &vulnerability.Metadata{
				ID:       id,
				Severity: severity,
			},
		},
		Package: p,
	}
}

func stepTargets(pp PackagePlan) []string {
	var out []string
	for _, s := range pp.Steps {
		out = append(out, s.TargetVersion)
	}
	return out
}

func residualReasons(pp PackagePlan) map[string]ResidualReason {
	out := map[string]ResidualReason{}
	for _, r := range pp.Residual {
		out[r.VulnerabilityID] = r.Reason
	}
	return out
}

// requirePlanInvariants checks the rules every plan must satisfy: no step ever
// targets a version at or below the installed version, and every finding is
// accounted for -- resolved by at least one step, or listed in the residual
// set, never both, never neither. (Steps are alternative targets, so a finding
// may be resolved by more than one step.)
func requirePlanInvariants(t *testing.T, pp PackagePlan, totalFindings int) {
	t.Helper()
	format := version.ParseFormat(pp.VersionFormat)
	resolved := map[string]bool{}
	for _, s := range pp.Steps {
		require.NotEmpty(t, s.Resolves, "step %q resolves nothing", s.TargetVersion)
		if format != version.UnknownFormat {
			current := version.New(pp.Version, format)
			target := version.New(s.TargetVersion, format)
			cmp, err := current.Compare(target)
			require.NoError(t, err)
			require.Negative(t, cmp, "step target %q must be strictly above installed %q", s.TargetVersion, pp.Version)
		}
		for _, f := range s.Resolves {
			resolved[f.VulnerabilityID] = true
		}
	}
	inResidual := map[string]bool{}
	for _, r := range pp.Residual {
		inResidual[r.VulnerabilityID] = true
		assert.NotEmpty(t, r.Detail, "every residual must explain why it remains")
	}
	for id := range resolved {
		assert.False(t, inResidual[id], "finding %s is both resolved and residual", id)
	}
	assert.Len(t, resolved, totalFindings-len(pp.Residual), "every non-residual finding must be resolved by some step")
}

// one finding per ecosystem, with fix versions that string ordering would sort
// wrong ("1.2.10" < "1.2.9" as strings): the planner must pick the minimal
// version by the ecosystem's own rules.
func TestPlan_PerEcosystemMinimalTarget(t *testing.T) {
	cases := []struct {
		name       string
		pkgType    syftPkg.Type
		format     string
		current    string
		fixes      []string
		wantTarget string
	}{
		{"deb distro revision", syftPkg.DebPkg, "Deb", "1.2.3-1", []string{"1.2.10-1", "1.2.9-1"}, "1.2.9-1"},
		{"rpm release", syftPkg.RpmPkg, "RPM", "1.2.3-1.el8", []string{"1.2.10-1.el8", "1.2.9-2.el8"}, "1.2.9-2.el8"},
		{"apk revision", syftPkg.ApkPkg, "Apk", "1.2.3-r0", []string{"1.2.10-r0", "1.2.9-r1"}, "1.2.9-r1"},
		{"python pep440", syftPkg.PythonPkg, "Python", "1.2.3", []string{"1.2.10", "1.2.9"}, "1.2.9"},
		{"gem", syftPkg.GemPkg, "Gem", "1.2.3", []string{"1.2.10", "1.2.9"}, "1.2.9"},
		{"golang", syftPkg.GoModulePkg, "Go", "v1.2.3", []string{"v1.2.10", "v1.2.9"}, "v1.2.9"},
		{"maven", syftPkg.JavaPkg, "Maven", "1.2.3", []string{"1.2.10", "1.2.9"}, "1.2.9"},
		{"npm semantic fallback", syftPkg.NpmPkg, "Semantic", "1.2.3", []string{"1.2.10", "1.2.9"}, "1.2.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := testPkg("id-"+tc.name, "pkg-"+tc.name, tc.current, tc.pkgType)
			matches := match.NewMatches(testMatch(p, "CVE-0001", "high", vulnerability.FixStateFixed, tc.fixes...))

			plan := NewPlan(matches)
			require.Len(t, plan.Packages, 1)
			pp := plan.Packages[0]

			assert.Equal(t, StatusPlanned, pp.Status)
			assert.Equal(t, tc.format, pp.VersionFormat)
			require.Len(t, pp.Steps, 1, "a single finding must yield exactly one upgrade target")
			assert.Equal(t, tc.wantTarget, pp.Steps[0].TargetVersion)
			require.Len(t, pp.Steps[0].Resolves, 1)
			assert.Equal(t, "CVE-0001", pp.Steps[0].Resolves[0].VulnerabilityID)
			assert.Empty(t, pp.Residual)
			requirePlanInvariants(t, pp, 1)
		})
	}
}

// multiple findings, one version clears them all: that version is the only
// step and it names every finding it covers.
func TestPlan_SingleTargetCoversAllFindings(t *testing.T) {
	p := testPkg("id-1", "libfoo", "1.2.0", syftPkg.NpmPkg)
	matches := match.NewMatches(
		testMatch(p, "CVE-0001", "critical", vulnerability.FixStateFixed, "1.2.4"),
		testMatch(p, "CVE-0002", "high", vulnerability.FixStateFixed, "1.2.5"),
		testMatch(p, "CVE-0003", "medium", vulnerability.FixStateFixed, "1.2.4"),
	)

	plan := NewPlan(matches)
	require.Len(t, plan.Packages, 1)
	pp := plan.Packages[0]

	require.Len(t, pp.Steps, 1)
	assert.Equal(t, "1.2.5", pp.Steps[0].TargetVersion, "the minimal version covering every finding")
	assert.Len(t, pp.Steps[0].Resolves, 3, "the step must name every finding it covers")
	assert.Equal(t, 0, pp.Steps[0].ResidualCount)
	assert.Empty(t, pp.Residual)
	requirePlanInvariants(t, pp, 3)
}

// no single version clears everything (fixes live on different release lines):
// the plan is a sequence ordered by residual severity then count, and every
// leftover finding carries its reason.
func TestPlan_ConflictingReleaseLines(t *testing.T) {
	p := testPkg("id-1", "libfoo", "1.0.0", syftPkg.NpmPkg)
	matches := match.NewMatches(
		testMatch(p, "CVE-0001", "high", vulnerability.FixStateFixed, "1.1.5"),
		testMatch(p, "CVE-0002", "medium", vulnerability.FixStateFixed, "1.2.3"),
		testMatch(p, "CVE-0003", "low", vulnerability.FixStateFixed, "1.3.1"),
		testMatch(p, "CVE-0004", "medium", vulnerability.FixStateNotFixed),
		testMatch(p, "CVE-0005", "low", vulnerability.FixStateWontFix),
		testMatch(p, "CVE-0006", "negligible", vulnerability.FixStateUnknown),
	)

	plan := NewPlan(matches)
	require.Len(t, plan.Packages, 1)
	pp := plan.Packages[0]

	assert.Equal(t, StatusPlanned, pp.Status)
	require.Equal(t, []string{"1.1.5", "1.2.3", "1.3.1"}, stepTargets(pp),
		"steps must be ordered by residual severity, then residual count, then version")

	// upgrading to 1.1.5 leaves the medium findings behind; the other two
	// targets leave a high finding behind, so 1.1.5 ranks first
	assert.Equal(t, "medium", pp.Steps[0].ResidualMaxSeverity)
	assert.Equal(t, 5, pp.Steps[0].ResidualCount)
	assert.Equal(t, "high", pp.Steps[1].ResidualMaxSeverity)
	assert.Equal(t, "high", pp.Steps[2].ResidualMaxSeverity)

	// each step clears exactly the finding on its own release line
	for i, id := range []string{"CVE-0001", "CVE-0002", "CVE-0003"} {
		require.Len(t, pp.Steps[i].Resolves, 1)
		assert.Equal(t, id, pp.Steps[i].Resolves[0].VulnerabilityID)
	}

	// the three non-fixable findings remain, each with its own reason
	reasons := residualReasons(pp)
	assert.Equal(t, ReasonNoFixAvailable, reasons["CVE-0004"])
	assert.Equal(t, ReasonWontFix, reasons["CVE-0005"])
	assert.Equal(t, ReasonInsufficientInfo, reasons["CVE-0006"])
	for _, r := range pp.Residual {
		assert.NotEmpty(t, r.Detail, "every residual must explain why it remains")
	}
	requirePlanInvariants(t, pp, 6)
}

// a fix on one release line must not be claimed by an upgrade to another line
func TestPlan_FixOnOtherLineDoesNotCount(t *testing.T) {
	p := testPkg("id-1", "libfoo", "1.1.0", syftPkg.NpmPkg)
	matches := match.NewMatches(
		testMatch(p, "CVE-0001", "high", vulnerability.FixStateFixed, "1.1.9"),
		testMatch(p, "CVE-0002", "high", vulnerability.FixStateFixed, "1.2.1"),
	)

	plan := NewPlan(matches)
	pp := plan.Packages[0]

	require.Len(t, pp.Steps, 2, "no single version clears both lines")
	assert.Equal(t, "1.1.9", pp.Steps[0].TargetVersion)
	assert.Equal(t, "1.2.1", pp.Steps[1].TargetVersion)
	assert.Equal(t, "CVE-0001", pp.Steps[0].Resolves[0].VulnerabilityID)
	assert.Equal(t, "CVE-0002", pp.Steps[1].Resolves[0].VulnerabilityID)
	requirePlanInvariants(t, pp, 2)
}

// unparseable installed version: the whole package is marked for manual
// review, no upgrade is suggested, and no finding is dropped.
func TestPlan_UnparseableInstalledVersion(t *testing.T) {
	p := testPkg("id-1", "libfoo", "!!not-a-version!!", syftPkg.NpmPkg)
	matches := match.NewMatches(
		testMatch(p, "CVE-0001", "high", vulnerability.FixStateFixed, "1.2.3"),
		testMatch(p, "CVE-0002", "high", vulnerability.FixStateNotFixed),
	)

	plan := NewPlan(matches)
	pp := plan.Packages[0]

	assert.Equal(t, StatusManualReview, pp.Status)
	assert.Contains(t, pp.StatusReason, "unable to parse installed version")
	assert.Empty(t, pp.Steps, "no suggestion may be produced for an unplannable package")
	require.Len(t, pp.Residual, 2)
	for _, r := range pp.Residual {
		assert.Equal(t, ReasonPackageUnplannable, r.Reason)
	}
	requirePlanInvariants(t, pp, 2)
}

// unparseable fix version: same degradation, package-level.
func TestPlan_UnparseableFixVersion(t *testing.T) {
	p := testPkg("id-1", "libfoo", "1.0.0", syftPkg.NpmPkg)
	matches := match.NewMatches(
		testMatch(p, "CVE-0001", "high", vulnerability.FixStateFixed, "not.a.version.at.all!!"),
	)

	plan := NewPlan(matches)
	pp := plan.Packages[0]

	assert.Equal(t, StatusManualReview, pp.Status)
	assert.Contains(t, pp.StatusReason, "unable to parse fix version")
	assert.Empty(t, pp.Steps)
	require.Len(t, pp.Residual, 1)
	assert.Equal(t, ReasonPackageUnplannable, pp.Residual[0].Reason)
}

// fix state says fixed but no versions are recorded: a data anomaly, which is
// not the same thing as "no fix available".
func TestPlan_FixedStateWithoutVersionsIsDataAnomaly(t *testing.T) {
	p := testPkg("id-1", "libfoo", "1.0.0", syftPkg.NpmPkg)
	matches := match.NewMatches(
		testMatch(p, "CVE-0001", "high", vulnerability.FixStateFixed),
		testMatch(p, "CVE-0002", "medium", vulnerability.FixStateNotFixed),
	)

	plan := NewPlan(matches)
	pp := plan.Packages[0]

	assert.Equal(t, StatusPlanned, pp.Status)
	reasons := residualReasons(pp)
	assert.Equal(t, ReasonDataAnomaly, reasons["CVE-0001"])
	assert.Equal(t, ReasonNoFixAvailable, reasons["CVE-0002"])
	requirePlanInvariants(t, pp, 2)
}

// fix versions at or below the installed version never produce a step.
func TestPlan_NeverSuggestsDowngrade(t *testing.T) {
	p := testPkg("id-1", "libfoo", "2.0.0", syftPkg.NpmPkg)
	matches := match.NewMatches(
		testMatch(p, "CVE-0001", "high", vulnerability.FixStateFixed, "1.9.9", "2.0.0"),
	)

	plan := NewPlan(matches)
	pp := plan.Packages[0]

	assert.Empty(t, pp.Steps)
	require.Len(t, pp.Residual, 1)
	assert.Equal(t, ReasonFixNotAboveCurrent, pp.Residual[0].Reason)
	requirePlanInvariants(t, pp, 1)
}

// same input in different insertion orders must produce byte-identical plans.
func TestPlan_Deterministic(t *testing.T) {
	p1 := testPkg("id-1", "libfoo", "1.0.0", syftPkg.NpmPkg)
	p2 := testPkg("id-2", "libbar", "3.1.0-1", syftPkg.DebPkg)
	ms := []match.Match{
		testMatch(p1, "CVE-0003", "low", vulnerability.FixStateFixed, "1.3.1"),
		testMatch(p1, "CVE-0001", "high", vulnerability.FixStateFixed, "1.1.5"),
		testMatch(p1, "CVE-0004", "medium", vulnerability.FixStateNotFixed),
		testMatch(p1, "CVE-0002", "medium", vulnerability.FixStateFixed, "1.2.3"),
		testMatch(p2, "CVE-0005", "high", vulnerability.FixStateFixed, "3.1.0-2", "3.2.0-1"),
		testMatch(p2, "CVE-0006", "low", vulnerability.FixStateWontFix),
	}

	reference, err := json.Marshal(NewPlan(match.NewMatches(ms...)))
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		// rotate the input to change insertion order
		ms = append(ms[1:], ms[0])
		got, err := json.Marshal(NewPlan(match.NewMatches(ms...)))
		require.NoError(t, err)
		require.JSONEq(t, string(reference), string(got), "plan must not depend on match insertion order")
	}
}

// two packages with the same name from different ecosystems are planned
// separately, never merged.
func TestPlan_SameNameDifferentSourceNotMerged(t *testing.T) {
	deb := testPkg("id-deb", "openssl", "1.1.1-1", syftPkg.DebPkg)
	npm := testPkg("id-npm", "openssl", "1.0.0", syftPkg.NpmPkg)
	matches := match.NewMatches(
		testMatch(deb, "CVE-0001", "high", vulnerability.FixStateFixed, "1.1.1-2"),
		testMatch(npm, "CVE-0002", "high", vulnerability.FixStateFixed, "1.0.1"),
	)

	plan := NewPlan(matches)
	require.Len(t, plan.Packages, 2, "same name from different sources must stay separate")

	byID := map[string]PackagePlan{}
	for _, pp := range plan.Packages {
		byID[pp.PackageID] = pp
	}
	assert.Equal(t, "1.1.1-2", byID["id-deb"].Steps[0].TargetVersion)
	assert.Equal(t, "1.0.1", byID["id-npm"].Steps[0].TargetVersion)
}

// a package type with no known version format cannot be planned.
func TestPlan_UnknownEcosystem(t *testing.T) {
	p := testPkg("id-1", "mystery", "1.0.0", syftPkg.BinaryPkg)
	matches := match.NewMatches(
		testMatch(p, "CVE-0001", "high", vulnerability.FixStateFixed, "1.0.1"),
	)

	plan := NewPlan(matches)
	pp := plan.Packages[0]

	assert.Equal(t, StatusManualReview, pp.Status)
	assert.Contains(t, pp.StatusReason, "unknown version format")
	assert.Empty(t, pp.Steps)
	require.Len(t, pp.Residual, 1)
	assert.Equal(t, ReasonPackageUnplannable, pp.Residual[0].Reason)
}

// planning must not modify the match data it was given.
func TestPlan_DoesNotMutateMatches(t *testing.T) {
	p := testPkg("id-1", "libfoo", "1.0.0", syftPkg.NpmPkg)
	m := testMatch(p, "CVE-0001", "high", vulnerability.FixStateFixed, "1.2.9", "1.2.10", "1.1.5")
	matches := match.NewMatches(m)

	_ = NewPlan(matches)

	got := matches.Sorted()
	require.Len(t, got, 1)
	assert.Equal(t, []string{"1.2.9", "1.2.10", "1.1.5"}, got[0].Vulnerability.Fix.Versions,
		"the original fix version list must be untouched")
}

// pre-release and build-metadata versions are handled per policy and annotated.
func TestPlan_PrereleaseAndBuildMetadataAnnotated(t *testing.T) {
	p := testPkg("id-1", "libfoo", "1.2.3-rc.1+build.5", syftPkg.NpmPkg)
	matches := match.NewMatches(
		testMatch(p, "CVE-0001", "high", vulnerability.FixStateFixed, "1.2.3"),
	)

	plan := NewPlan(matches)
	pp := plan.Packages[0]

	require.Len(t, pp.Steps, 1)
	assert.Equal(t, "1.2.3", pp.Steps[0].TargetVersion, "a pre-release is below its release per semver rules")
	assert.Len(t, pp.Annotations, 2, "both the pre-release and the build metadata must be annotated")
	requirePlanInvariants(t, pp, 1)
}

// a fix version equal to the installed version is not an upgrade.
func TestPlan_FixEqualToCurrentIsNotAnUpgrade(t *testing.T) {
	p := testPkg("id-1", "libfoo", "1.2.3", syftPkg.NpmPkg)
	matches := match.NewMatches(
		testMatch(p, "CVE-0001", "high", vulnerability.FixStateFixed, "1.2.3"),
	)

	plan := NewPlan(matches)
	pp := plan.Packages[0]

	assert.Empty(t, pp.Steps)
	require.Len(t, pp.Residual, 1)
	assert.Equal(t, ReasonFixNotAboveCurrent, pp.Residual[0].Reason)
}

// the multi-step order is by residual severity first: a target that clears a
// low finding but leaves a critical residual ranks below one that clears the
// critical finding, even when it clears more findings overall.
func TestPlan_StepOrderPrefersResidualSeverityOverCount(t *testing.T) {
	p := testPkg("id-1", "libfoo", "1.0.0", syftPkg.NpmPkg)
	matches := match.NewMatches(
		testMatch(p, "CVE-0001", "critical", vulnerability.FixStateFixed, "1.1.5"),
		testMatch(p, "CVE-0002", "low", vulnerability.FixStateFixed, "1.2.3"),
		testMatch(p, "CVE-0003", "low", vulnerability.FixStateFixed, "1.2.4"),
	)

	plan := NewPlan(matches)
	pp := plan.Packages[0]

	// 1.2.3 is dominated by 1.2.4 (same line, covers one more finding)
	require.Len(t, pp.Steps, 2)
	assert.Equal(t, "1.1.5", pp.Steps[0].TargetVersion,
		"clearing the critical finding leaves only low residuals and must rank first")
	assert.Equal(t, "low", pp.Steps[0].ResidualMaxSeverity)
	assert.Equal(t, "1.2.4", pp.Steps[1].TargetVersion)
	assert.Equal(t, "critical", pp.Steps[1].ResidualMaxSeverity)
}

// dominated targets are pruned: a candidate whose coverage is a subset of
// another's is never offered, and identical coverage keeps only the smallest
// version.
func TestPlan_DominatedTargetsPruned(t *testing.T) {
	p := testPkg("id-1", "libfoo", "1.0.0", syftPkg.NpmPkg)
	matches := match.NewMatches(
		testMatch(p, "CVE-0001", "high", vulnerability.FixStateFixed, "1.2.4"),
		testMatch(p, "CVE-0002", "medium", vulnerability.FixStateFixed, "1.2.5"),
		testMatch(p, "CVE-0003", "low", vulnerability.FixStateFixed, "1.3.1"),
	)

	plan := NewPlan(matches)
	pp := plan.Packages[0]

	// 1.2.4 covers only CVE-0001 and is strictly dominated by 1.2.5
	require.Equal(t, []string{"1.2.5", "1.3.1"}, stepTargets(pp))
	requirePlanInvariants(t, pp, 3)
}

// identical coverage from two versions of one finding keeps only the smallest.
func TestPlan_IdenticalCoverageKeepsSmallest(t *testing.T) {
	p := testPkg("id-1", "libfoo", "1.0.0", syftPkg.NpmPkg)
	matches := match.NewMatches(
		testMatch(p, "CVE-0001", "high", vulnerability.FixStateFixed, "1.2.4", "1.2.5"),
		testMatch(p, "CVE-0002", "medium", vulnerability.FixStateFixed, "1.3.1"),
	)

	plan := NewPlan(matches)
	pp := plan.Packages[0]

	require.Equal(t, []string{"1.2.4", "1.3.1"}, stepTargets(pp))
	requirePlanInvariants(t, pp, 2)
}

func TestPlan_EmptyMatches(t *testing.T) {
	plan := NewPlan(match.NewMatches())
	assert.Empty(t, plan.Packages)
}

// every fixable finding is reachable by its own minimal fix version, so the
// not-covered reason should never fire in practice; guard the invariant.
func TestPlan_NoFixableFindingLeftUncovered(t *testing.T) {
	p := testPkg("id-1", "libfoo", "1.0.0", syftPkg.NpmPkg)
	var ms []match.Match
	for i := 0; i < 10; i++ {
		ms = append(ms, testMatch(p, fmt.Sprintf("CVE-%04d", i), "high",
			vulnerability.FixStateFixed, fmt.Sprintf("1.%d.1", i), fmt.Sprintf("1.%d.2", i)))
	}
	plan := NewPlan(match.NewMatches(ms...))
	for _, r := range plan.Packages[0].Residual {
		assert.NotEqual(t, ReasonNotCoveredByPlan, r.Reason)
	}
	requirePlanInvariants(t, plan.Packages[0], 10)
}
