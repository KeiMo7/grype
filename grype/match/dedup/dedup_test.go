package dedup

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
	syftSource "github.com/anchore/syft/syft/source"
)

const testCVE = "CVE-2024-9999"

// matchBuilder assures matches differ only in the fields a test names; everything else is fixed
// so two builders with the same inputs yield the same fingerprint.
type matchBuilder struct {
	id          string
	vulnID      string
	namespace   string
	pkgName     string
	pkgVersion  string
	pkgType     syftPkg.Type
	locations   []file.Location
	archMeta    any
	constraint  string
	fixVersions []string
	status      string
	unaffected  bool
	detailType  match.Type
}

func newMatchBuilder(id string) *matchBuilder {
	return &matchBuilder{
		id:         id,
		vulnID:     testCVE,
		namespace:  "ubuntu:distro:ubuntu:22.04",
		pkgName:    "openssl",
		pkgVersion: "3.0.2-0ubuntu1",
		pkgType:    syftPkg.DebPkg,
		locations:  []file.Location{file.NewLocation("/usr/lib/ssl/" + id + "/libssl.so")},
		constraint: "< 3.0.2-0ubuntu1.10",
		detailType: match.ExactDirectMatch,
	}
}

func (b *matchBuilder) build(t *testing.T) match.Match {
	t.Helper()
	c, err := version.GetConstraint(b.constraint, version.DebFormat)
	require.NoError(t, err)

	p := pkg.Package{
		ID:        pkg.ID(b.id),
		Name:      b.pkgName,
		Version:   b.pkgVersion,
		Type:      b.pkgType,
		Locations: file.NewLocationSet(b.locations...),
		Metadata:  b.archMeta,
	}

	return match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference:  vulnerability.Reference{ID: b.vulnID, Namespace: b.namespace},
			Status:     b.status,
			Constraint: c,
			Unaffected: b.unaffected,
			Fix:        vulnerability.Fix{Versions: append([]string(nil), b.fixVersions...)},
		},
		Package: p,
		Details: match.Details{{
			Type:    b.detailType,
			Matcher: "test-matcher",
			Found:   "found-" + b.id,
		}},
	}
}

func findingConfig() Config {
	t := true
	return Config{Mode: ModeFinding, MaxPaths: DefaultMaxPaths, IncludePackageType: &t}
}

func imageContext(arch string) pkg.Context {
	if arch == "" {
		return pkg.Context{}
	}
	return pkg.Context{Source: &syftSource.Description{
		Metadata: syftSource.ImageMetadata{Architecture: arch},
	}}
}

// TestDedup_LegacyIsPassthrough pins the default: legacy mode must return the input collection
// untouched, with no audit content, so existing grype behavior is byte-for-byte preserved.
func TestDedup_LegacyIsPassthrough(t *testing.T) {
	m1 := newMatchBuilder("a").build(t)
	m2 := newMatchBuilder("b").build(t)
	in := match.NewMatches(m1, m2)

	out, report := Dedup(in, pkg.Context{}, DefaultConfig())

	require.Equal(t, in.Count(), out.Count())
	require.Equal(t, string(ModeLegacy), report.Mode)
	require.Empty(t, report.MergedGroups)
	require.Zero(t, report.MergedGroupCount)
	for _, m := range out.Sorted() {
		assert.Nil(t, m.MergeAudit, "legacy mode must never attach a merge audit")
	}
}

// TestDedup_MultiplePathsMerge is the headline scenario: one package reached through several
// paths (here a symlink) becomes one finding listing every path, with a full audit trail.
func TestDedup_MultiplePathsMerge(t *testing.T) {
	real := file.NewLocation("/opt/app/libssl.so")
	link := file.NewVirtualLocation("/opt/app/libssl.so", "/opt/app/link/libssl.so")

	b1 := newMatchBuilder("a")
	b1.locations = []file.Location{real}
	b2 := newMatchBuilder("b")
	b2.locations = []file.Location{link}

	in := match.NewMatches(b1.build(t), b2.build(t))
	out, report := Dedup(in, pkg.Context{}, findingConfig())

	require.Equal(t, 1, out.Count(), "same package via two paths must be one finding")
	require.Equal(t, 2, report.InputCount)
	require.Equal(t, 1, report.OutputCount)
	require.Equal(t, 1, report.MergedGroupCount)

	got := out.Sorted()[0]
	paths := locationStrings(got.Package.Locations)
	assert.ElementsMatch(t, []string{
		"/opt/app/libssl.so",
		"/opt/app/libssl.so (via /opt/app/link/libssl.so)",
	}, paths)

	require.NotNil(t, got.MergeAudit)
	assert.Equal(t, ReasonFindingKey, got.MergeAudit.Reason)
	require.Len(t, got.MergeAudit.MergedFrom, 1)
	merged := got.MergeAudit.MergedFrom[0]
	assert.Equal(t, "3.0.2-0ubuntu1", merged.PackageVersion)
	expectedConstraint, err := version.GetConstraint("< 3.0.2-0ubuntu1.10", version.DebFormat)
	require.NoError(t, err)
	assert.Equal(t, expectedConstraint.String(), merged.Constraint)
	assert.Contains(t, merged.Paths[0], "/opt/app/libssl.so")

	require.Len(t, report.MergedGroups, 1)
	assert.Equal(t, testCVE, report.MergedGroups[0].Kept.VulnerabilityID)
}

// TestDedup_DifferentPackageTypesStaySeparate guards the fix-path rule: the same CVE on a
// system package and a language package are two findings because their remediation differs.
func TestDedup_DifferentPackageTypesStaySeparate(t *testing.T) {
	b1 := newMatchBuilder("os")
	b1.pkgType = syftPkg.DebPkg
	b2 := newMatchBuilder("lang")
	b2.pkgType = syftPkg.PythonPkg
	b2.pkgVersion = "3.0.2-0ubuntu1" // same name+version, only type differs

	in := match.NewMatches(b1.build(t), b2.build(t))
	out, report := Dedup(in, pkg.Context{}, findingConfig())

	require.Equal(t, 2, out.Count(), "different package ecosystems must not merge")
	assert.Zero(t, report.MergedGroupCount)
}

// TestDedup_NamespacesStaySeparate keeps source identity in the key: records from different
// providers carry different version schemes and must never union fix versions.
func TestDedup_NamespacesStaySeparate(t *testing.T) {
	b1 := newMatchBuilder("a")
	b1.namespace = "redhat:distro:redhat:9"
	b1.fixVersions = []string{"1:1.0.2-1.el9"}
	b2 := newMatchBuilder("b")
	b2.namespace = "nvd:cpe"
	b2.fixVersions = []string{"1.1.0"}

	in := match.NewMatches(b1.build(t), b2.build(t))
	out, _ := Dedup(in, pkg.Context{}, findingConfig())

	require.Equal(t, 2, out.Count())
	seen := map[string][]string{}
	for _, m := range out.Sorted() {
		seen[m.Vulnerability.Namespace] = m.Vulnerability.Fix.Versions
	}
	assert.Equal(t, []string{"1:1.0.2-1.el9"}, seen["redhat:distro:redhat:9"],
		"fix versions from different sources must never be unioned")
	assert.Equal(t, []string{"1.1.0"}, seen["nvd:cpe"])
}

// TestDedup_DifferentVersionsStaySeparate: the same CVE against two package versions is two
// findings; only multiple records of one version collapse.
func TestDedup_DifferentVersionsStaySeparate(t *testing.T) {
	b1 := newMatchBuilder("a")
	b2 := newMatchBuilder("b")
	b2.pkgVersion = "3.0.2-0ubuntu1.5"

	in := match.NewMatches(b1.build(t), b2.build(t))
	out, report := Dedup(in, pkg.Context{}, findingConfig())

	require.Equal(t, 2, out.Count())
	assert.Zero(t, report.MergedGroupCount)
}

// TestDedup_CrossArchitectureNeverMerges is the dedicated multi-arch case: two scans of the
// amd64 and arm64 variants produce two findings, and the fix versions never cross.
func TestDedup_CrossArchitectureNeverMerges(t *testing.T) {
	mk := func(arch, id string, fix string) match.Match {
		b := newMatchBuilder(id)
		b.archMeta = pkg.RpmMetadata{Arch: arch}
		b.fixVersions = []string{fix}
		b.pkgType = syftPkg.RpmPkg
		return b.build(t)
	}

	amd := mk("x86_64", "amd", "1:3.0.2-1.amd64")
	arm := mk("aarch64", "arm", "1:3.0.2-1.arm64")

	// simulate the two variants' findings landing in one result set
	in := match.NewMatches(amd, arm)
	out, report := Dedup(in, pkg.Context{}, findingConfig())

	require.Equal(t, 2, out.Count(), "findings from different architectures must never merge")
	assert.Zero(t, report.MergedGroupCount)

	byArch := map[string]match.Match{}
	for _, m := range out.Sorted() {
		meta := m.Package.Metadata.(pkg.RpmMetadata)
		byArch[meta.Arch] = m
	}
	require.Contains(t, byArch, "x86_64")
	require.Contains(t, byArch, "aarch64")
	assert.Equal(t, []string{"1:3.0.2-1.amd64"}, byArch["x86_64"].Vulnerability.Fix.Versions)
	assert.Equal(t, []string{"1:3.0.2-1.arm64"}, byArch["aarch64"].Vulnerability.Fix.Versions)
}

// TestDedup_CrossArchitectureFromSource covers packages whose metadata carries no arch: the
// scan source architecture still keeps the two variants apart.
func TestDedup_CrossArchitectureFromSource(t *testing.T) {
	b1 := newMatchBuilder("a")
	b1.archMeta = nil
	b2 := newMatchBuilder("b")
	b2.archMeta = nil

	amdOut, _ := Dedup(match.NewMatches(b1.build(t)), imageContext("amd64"), findingConfig())
	armOut, _ := Dedup(match.NewMatches(b2.build(t)), imageContext("arm64"), findingConfig())

	require.Equal(t, 1, amdOut.Count())
	require.Equal(t, 1, armOut.Count())

	// the two scans' findings carry different source-architecture keys, so even when their
	// packages are otherwise identical they remain two findings in any combined set
	amdKey := keyFor(amdOut.Sorted()[0], findingConfig(), "amd64")
	armKey := keyFor(armOut.Sorted()[0], findingConfig(), "arm64")
	assert.NotEqual(t, amdKey, armKey)
}

// TestDedup_ArchNeutralPackagesUseSourceArch guards noarch/all/src packages: they carry no CPU
// architecture themselves, so in two architecture variants the source architecture must keep
// them apart; within one arch-less source they still merge on the neutral token.
func TestDedup_ArchNeutralPackagesUseSourceArch(t *testing.T) {
	mk := func(id string) match.Match {
		b := newMatchBuilder(id)
		b.archMeta = pkg.RpmMetadata{Arch: "noarch"}
		b.pkgType = syftPkg.RpmPkg
		return b.build(t)
	}

	// within one image variant, the source arch disambiguates two noarch findings from merging
	// across variants: keys differ even though both package metadata says noarch
	amdKey := keyFor(mk("a"), findingConfig(), "amd64")
	armKey := keyFor(mk("b"), findingConfig(), "arm64")
	assert.NotEqual(t, amdKey, armKey)
	assert.Equal(t, "amd64", amdKey.architecture)
	assert.Equal(t, "arm64", armKey.architecture)

	// without a source architecture the neutral token itself is used, so same-scan noarch
	// findings still collapse on the rest of the key
	neutralKey := keyFor(mk("c"), findingConfig(), "")
	assert.Equal(t, "noarch", neutralKey.architecture)
}

// TestDedup_DialectAliasesCollapse proves the canonicalization reuse: x86_64 metadata against
// an amd64 source resolves to one token and does merge.
func TestDedup_DialectAliasesCollapse(t *testing.T) {
	b1 := newMatchBuilder("a")
	b1.archMeta = pkg.RpmMetadata{Arch: "x86_64"}
	b1.pkgType = syftPkg.RpmPkg
	b2 := newMatchBuilder("b")
	b2.archMeta = pkg.RpmMetadata{Arch: "amd64"}
	b2.pkgType = syftPkg.RpmPkg

	out, report := Dedup(match.NewMatches(b1.build(t), b2.build(t)), pkg.Context{}, findingConfig())
	require.Equal(t, 1, out.Count(), "x86_64 and amd64 are one architecture and must merge")
	require.Equal(t, 1, report.MergedGroupCount)
}

// TestDedup_UnaffectedLosesAuthority: when an unaffected and an affected record describe the
// same finding, the affected record must survive and the unaffected one is recorded as merged.
func TestDedup_UnaffectedLosesAuthority(t *testing.T) {
	b1 := newMatchBuilder("affected")
	b1.unaffected = false
	b1.detailType = match.ExactDirectMatch
	b2 := newMatchBuilder("unaffected")
	b2.unaffected = true
	b2.detailType = match.ExactIndirectMatch

	out, _ := Dedup(match.NewMatches(b1.build(t), b2.build(t)), pkg.Context{}, findingConfig())
	require.Equal(t, 1, out.Count())
	got := out.Sorted()[0]
	assert.False(t, got.Vulnerability.Unaffected, "the affected record must describe the finding")
	require.NotNil(t, got.MergeAudit)
	require.Len(t, got.MergeAudit.MergedFrom, 1)
	assert.True(t, got.MergeAudit.MergedFrom[0].Unaffected)
}

// TestDedup_PathTruncationAnnotated checks the cap: beyond MaxPaths the sorted prefix survives,
// truncation is flagged, and the dropped count is exact.
func TestDedup_PathTruncationAnnotated(t *testing.T) {
	const n = 8
	var locsA, locsB []file.Location
	for i := 0; i < n; i++ {
		locsA = append(locsA, file.NewLocation(fmt.Sprintf("/a/%d", i)))
		locsB = append(locsB, file.NewLocation(fmt.Sprintf("/b/%d", i)))
	}
	b1 := newMatchBuilder("a")
	b1.locations = locsA
	b2 := newMatchBuilder("b")
	b2.locations = locsB

	cfg := findingConfig()
	cfg.MaxPaths = 10
	out, report := Dedup(match.NewMatches(b1.build(t), b2.build(t)), pkg.Context{}, cfg)

	require.Equal(t, 1, out.Count())
	got := out.Sorted()[0]
	require.NotNil(t, got.MergeAudit)
	assert.True(t, got.MergeAudit.PathsTruncated)
	assert.Equal(t, 6, got.MergeAudit.PathsDropped, "16 paths capped at 10 means 6 dropped")
	assert.Len(t, got.Package.Locations.ToSlice(), 10)
	assert.Equal(t, 1, report.PathsTruncated)
}

// TestDedup_UnlimitedPaths disables truncation.
func TestDedup_UnlimitedPaths(t *testing.T) {
	var locs []file.Location
	for i := 0; i < 60; i++ {
		locs = append(locs, file.NewLocation(fmt.Sprintf("/x/%02d", i)))
	}
	b1 := newMatchBuilder("a")
	b1.locations = locs[:30]
	b2 := newMatchBuilder("b")
	b2.locations = locs[30:]

	cfg := findingConfig()
	cfg.MaxPaths = UnlimitedPaths
	out, _ := Dedup(match.NewMatches(b1.build(t), b2.build(t)), pkg.Context{}, cfg)
	require.Equal(t, 1, out.Count())
	got := out.Sorted()[0]
	assert.False(t, got.MergeAudit.PathsTruncated)
	assert.Len(t, got.Package.Locations.ToSlice(), 60)
}

// TestDedup_NoFindingIsLost is the no-false-deletion guarantee: every input
// (vuln, namespace, name, version) quadruple is present in the output exactly once, and every
// output match traces to an input.
func TestDedup_NoFindingIsLost(t *testing.T) {
	builders := []*matchBuilder{
		newMatchBuilder("m1"),
		newMatchBuilder("m2"), // merges with m1 (different path only)
		newMatchBuilder("m3"),
	}
	builders[2].pkgVersion = "4.0.0-1" // separate version -> separate finding

	var inputs []match.Match
	for _, b := range builders {
		inputs = append(inputs, b.build(t))
	}
	out, _ := Dedup(match.NewMatches(inputs...), pkg.Context{}, findingConfig())

	type quadruple struct{ id, ns, name, version string }
	inputSet := map[quadruple]struct{}{}
	for _, m := range inputs {
		inputSet[quadruple{m.Vulnerability.ID, m.Vulnerability.Namespace, m.Package.Name, m.Package.Version}] = struct{}{}
	}
	outputSet := map[quadruple]struct{}{}
	for _, m := range out.Sorted() {
		q := quadruple{m.Vulnerability.ID, m.Vulnerability.Namespace, m.Package.Name, m.Package.Version}
		_, duplicated := outputSet[q]
		assert.False(t, duplicated, "an output finding identity must appear exactly once")
		outputSet[q] = struct{}{}
	}
	assert.Equal(t, inputSet, outputSet, "every input finding identity must survive, none added")
	assert.Equal(t, 2, out.Count())

	// and every survivor traces back to an input via its audit (the merged one) or directly
	for _, m := range out.Sorted() {
		if m.MergeAudit != nil {
			assert.Equal(t, ReasonFindingKey, m.MergeAudit.Reason)
			require.Len(t, m.MergeAudit.MergedFrom, 1)
		}
	}
}

// TestDedup_OrderIndependent: survivor and merged set must not depend on arrival order.
func TestDedup_OrderIndependent(t *testing.T) {
	mk := func(id string, ty match.Type) match.Match {
		b := newMatchBuilder(id)
		b.detailType = ty
		return b.build(t)
	}
	weak := mk("w", match.CPEMatch)
	strong := mk("s", match.ExactDirectMatch)

	one, _ := Dedup(match.NewMatches(weak, strong), pkg.Context{}, findingConfig())
	two, _ := Dedup(match.NewMatches(strong, weak), pkg.Context{}, findingConfig())

	require.Equal(t, 1, one.Count())
	require.Equal(t, 1, two.Count())
	a := one.Sorted()[0]
	b := two.Sorted()[0]
	assert.Equal(t, a.Details.Types()[0], b.Details.Types()[0])
	assert.Equal(t, match.ExactDirectMatch, a.Details.Types()[0], "strongest record always survives")
	assert.Len(t, a.MergeAudit.MergedFrom, len(b.MergeAudit.MergedFrom))
}

// TestDedup_KeyFailureKeepsEntry exercises the degradation rule: when key computation fails,
// the entry survives unmerged and the failure is recorded rather than the finding being dropped.
func TestDedup_KeyFailureKeepsEntry(t *testing.T) {
	good := newMatchBuilder("good").build(t)
	bad := newMatchBuilder("bad").build(t)

	orig := keyForFunc
	t.Cleanup(func() { keyForFunc = orig })
	keyForFunc = func(m match.Match, cfg Config, sourceArch string) findingKey {
		if m.Package.ID == pkg.ID("bad") {
			panic("intentional key failure")
		}
		return keyFor(m, cfg, sourceArch)
	}

	out, report := Dedup(match.NewMatches(good, bad), pkg.Context{}, findingConfig())

	require.Equal(t, 2, out.Count(), "a key failure must never drop a finding")
	require.Len(t, report.Failures, 1)
	assert.Equal(t, testCVE, report.Failures[0].VulnerabilityID)
	assert.Contains(t, report.Failures[0].Error, "dedup key computation failed")

	// the failed match carries no merge audit: it passed through untouched
	for _, m := range out.Sorted() {
		if m.Package.ID == pkg.ID("bad") {
			assert.Nil(t, m.MergeAudit)
		}
	}
}

// TestDedup_ThreeWayMergeAccumulates proves a group of three path variants folds into one
// survivor that keeps every record's fix versions and details rather than losing the middle
// record through repeated merges.
func TestDedup_ThreeWayMergeAccumulates(t *testing.T) {
	mk := func(id, fix string, ty match.Type) match.Match {
		b := newMatchBuilder(id)
		b.fixVersions = []string{fix}
		b.detailType = ty
		b.locations = []file.Location{file.NewLocation("/p/" + id)}
		return b.build(t)
	}

	inputs := []match.Match{
		mk("a", "1.0.0", match.CPEMatch),
		mk("b", "2.0.0", match.ExactIndirectMatch),
		mk("c", "3.0.0", match.ExactDirectMatch),
	}
	out, report := Dedup(match.NewMatches(inputs...), pkg.Context{}, findingConfig())

	require.Equal(t, 1, out.Count())
	got := out.Sorted()[0]
	assert.ElementsMatch(t, []string{"1.0.0", "2.0.0", "3.0.0"}, got.Vulnerability.Fix.Versions,
		"all three records' fix versions must survive")
	require.NotNil(t, got.MergeAudit)
	require.Len(t, got.MergeAudit.MergedFrom, 2, "the survivor is excluded from the folded list")
	assert.Equal(t, match.ExactDirectMatch, got.Details.Types()[0], "strongest record describes the finding")
	assert.Len(t, got.Package.Locations.ToSlice(), 3, "all three paths unioned")
	require.Len(t, report.MergedGroups, 1)
}
func TestDedup_IncludePackageTypeDisabled(t *testing.T) {
	off := false
	cfg := Config{Mode: ModeFinding, MaxPaths: DefaultMaxPaths, IncludePackageType: &off}

	b1 := newMatchBuilder("os")
	b1.pkgType = syftPkg.DebPkg
	b2 := newMatchBuilder("lang")
	b2.pkgType = syftPkg.PythonPkg

	out, report := Dedup(match.NewMatches(b1.build(t), b2.build(t)), pkg.Context{}, cfg)
	require.Equal(t, 1, out.Count(), "with type excluded from the key, the variants merge")
	require.Equal(t, 1, report.MergedGroupCount)
}

func TestDedup_ConfigValidation(t *testing.T) {
	t.Run("empty mode defaults to legacy", func(t *testing.T) {
		cfg := Config{}
		require.NoError(t, cfg.Validate())
		assert.Equal(t, ModeLegacy, cfg.Mode)
		assert.Equal(t, DefaultMaxPaths, cfg.MaxPaths)
	})
	t.Run("rejects bad mode", func(t *testing.T) {
		cfg := Config{Mode: "nope"}
		assert.Error(t, cfg.Validate())
	})
	t.Run("rejects bad max paths", func(t *testing.T) {
		cfg := Config{Mode: ModeFinding, MaxPaths: -7}
		assert.Error(t, cfg.Validate())
	})
	t.Run("unlimited is accepted", func(t *testing.T) {
		cfg := Config{Mode: ModeFinding, MaxPaths: UnlimitedPaths}
		assert.NoError(t, cfg.Validate())
	})
}

// TestDedup_UnknownArchMergesWithinScan: two arch-less findings in an arch-less source merge on
// the shared unknown token, which is safe because one scan has one artifact.
func TestDedup_UnknownArchMergesWithinScan(t *testing.T) {
	b1 := newMatchBuilder("a")
	b1.archMeta = nil
	b2 := newMatchBuilder("b")
	b2.archMeta = nil
	out, report := Dedup(match.NewMatches(b1.build(t), b2.build(t)), pkg.Context{}, findingConfig())
	require.Equal(t, 1, out.Count())
	require.Equal(t, 1, report.MergedGroupCount)
	assert.Contains(t, report.MergedGroups[0].Key, unknownArch)
}
