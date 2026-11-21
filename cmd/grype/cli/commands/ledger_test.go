package commands

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/grype/cmd/grype/cli/options"
	"github.com/anchore/grype/grype/ledger"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func testGrypeOptions(path string) *options.Grype {
	opts := options.DefaultGrype(clio.Identification{Name: "grype", Version: "test"})
	opts.Ledger = path
	opts.LedgerTimestamps = false
	return opts
}

// TestRecordLedgerPreservesReportInputs verifies the wiring from the matcher results
// into the ledger: the report's remaining matches become unfixed entries, ignored
// matches stay ignored, and matcher suppressions become assessments. It also
// confirms recording does not mutate the inputs it is given.
func TestRecordLedgerPreservesReportInputs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")

	p := pkg.Package{Name: "openssl", Version: "3.0.1", Type: syftPkg.DebPkg}
	open := match.Match{
		Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2026-C1", Namespace: "debian:distro:debian:12"}},
		Package:       p,
	}
	ignoredM := match.Match{
		Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2026-C2", Namespace: "debian:distro:debian:12"}},
		Package:       p,
	}
	suppressedM := match.Match{
		Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2026-C3", Namespace: "debian:distro:debian:12"}},
		Package:       p,
	}

	matches := match.NewMatches(open)
	ignoredMatches := []match.IgnoredMatch{{
		Match:              ignoredM,
		AppliedIgnoreRules: []match.IgnoreRule{{Vulnerability: "CVE-2026-C2", Reason: "accepted"}},
	}}
	suppressed := []match.IgnoredMatch{{
		Match:              suppressedM,
		AppliedIgnoreRules: []match.IgnoreRule{{Vulnerability: "CVE-2026-C3", Reason: "distro-fixed"}},
	}}

	matchesBefore := matches.Count()
	err := recordLedger(t.Context(), testGrypeOptions(path), "example:1.0", matches, ignoredMatches, suppressed, nil)
	require.NoError(t, err)
	assert.Equal(t, matchesBefore, matches.Count(), "recording must not modify the report matches")
	assert.Len(t, ignoredMatches, 1, "recording must not modify the ignored matches")

	l, err := ledger.LoadQuery(path)
	require.NoError(t, err)
	byVuln := map[string]ledger.State{}
	for _, entry := range l.Entries {
		byVuln[entry.VulnerabilityID] = entry.State
	}
	assert.Equal(t, ledger.StateUnfixed, byVuln["CVE-2026-C1"])
	assert.Equal(t, ledger.StateIgnored, byVuln["CVE-2026-C2"])
	assert.Equal(t, ledger.StateFixed, byVuln["CVE-2026-C3"])
}

// TestRecordLedgerConcurrentImages exercises the multi-image batch path: several
// images finishing in the same batch record into one ledger without corruption.
func TestRecordLedgerConcurrentImages(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ledger.jsonl")

	const images = 6
	done := make(chan error, images)
	for i := 0; i < images; i++ {
		go func(i int) {
			p := pkg.Package{Name: "pkg" + string(rune('a'+i)), Version: "1.0", Type: syftPkg.DebPkg}
			m := match.Match{
				Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2026-M1", Namespace: "nvd:cpe"}},
				Package:       p,
			}
			opts := testGrypeOptions(path)
			opts.LedgerBatch = "shared-batch"
			done <- recordLedger(t.Context(), opts, "image-"+string(rune('a'+i)), match.NewMatches(m), nil, nil, nil)
		}(i)
	}
	for i := 0; i < images; i++ {
		require.NoError(t, <-done)
	}

	l, err := ledger.LoadQuery(path)
	require.NoError(t, err)
	assert.Len(t, l.Entries, images)
	assert.Len(t, l.Batches, 1, "all images must share one batch")
	assert.Len(t, l.Batches[0].Images, images)
}
