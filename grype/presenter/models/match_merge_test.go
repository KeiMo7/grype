package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
)

func TestNewMerge_NilWhenNoAudit(t *testing.T) {
	assert.Nil(t, newMerge(nil), "matches without a dedup audit must not emit a merge block")
}

func TestNewMerge_ProjectsAudit(t *testing.T) {
	audit := &match.MergeAudit{
		Reason:         "same-vulnerability-package-multiple-paths",
		PathsTruncated: true,
		PathsDropped:   3,
		MergedFrom: []match.MergedRecord{
			{
				Fingerprint:    "fp-1234",
				PackageVersion: "1.2.3",
				Constraint:     "< 2.0",
				FixVersions:    []string{"2.0"},
				Paths:          []string{"/a/lib.jar", "/b/lib.jar (via /link/lib.jar)"},
				Status:         "active",
			},
		},
	}

	got := newMerge(audit)
	require.NotNil(t, got)
	assert.Equal(t, "same-vulnerability-package-multiple-paths", got.Reason)
	assert.True(t, got.PathsTruncated)
	assert.Equal(t, 3, got.PathsDropped)
	require.Len(t, got.MergedFrom, 1)
	assert.Equal(t, "fp-1234", got.MergedFrom[0].Fingerprint)
	assert.Equal(t, []string{"2.0"}, got.MergedFrom[0].FixVersions)
	assert.False(t, got.MergedFrom[0].Unaffected)
}

// TestMatchJSON_OmitsMergeWithoutAudit pins the report-shape guarantee: the merge field is
// absent (not null) for ordinary findings, so legacy-mode reports stay byte-compatible.
func TestMatchJSON_OmitsMergeWithoutAudit(t *testing.T) {
	m := Match{
		Vulnerability: Vulnerability{
			VulnerabilityMetadata: VulnerabilityMetadata{ID: "CVE-2024-1"},
		},
		Artifact:     Package{ID: "p1"},
		MatchDetails: []MatchDetails{},
	}
	raw, err := json.Marshal(m)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"merge"`)
}
