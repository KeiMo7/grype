package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match/dedup"
)

func TestDedupConfig_Defaults(t *testing.T) {
	cfg := defaultDedupConfig()

	lib, err := cfg.ToDedupConfig()
	require.NoError(t, err)
	assert.Equal(t, dedup.ModeLegacy, lib.Mode)
	assert.Equal(t, dedup.DefaultMaxPaths, lib.MaxPaths)
	require.NotNil(t, lib.IncludePackageType)
	assert.True(t, *lib.IncludePackageType)
}

func TestDedupConfig_PostLoad(t *testing.T) {
	tests := []struct {
		name    string
		cfg     dedupConfig
		wantErr bool
	}{
		{name: "legacy", cfg: dedupConfig{Mode: "legacy"}},
		{name: "finding", cfg: dedupConfig{Mode: "finding", MaxPaths: 10}},
		{name: "empty mode resolves to legacy", cfg: dedupConfig{}},
		{name: "invalid mode", cfg: dedupConfig{Mode: "bogus"}, wantErr: true},
		{name: "invalid max paths", cfg: dedupConfig{Mode: "finding", MaxPaths: -99}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.PostLoad()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestDedupConfig_FindingMapping(t *testing.T) {
	off := false
	cfg := dedupConfig{
		Mode:               "finding",
		MaxPaths:           5,
		IncludePackageType: &off,
		AuditReport:        "/tmp/audit.json",
	}

	lib, err := cfg.ToDedupConfig()
	require.NoError(t, err)
	assert.Equal(t, dedup.ModeFinding, lib.Mode)
	assert.Equal(t, 5, lib.MaxPaths)
	require.NotNil(t, lib.IncludePackageType)
	assert.False(t, *lib.IncludePackageType)
}
