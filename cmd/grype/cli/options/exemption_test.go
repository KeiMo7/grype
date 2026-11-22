package options

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/grype/grype/match"
)

// loadExemptionConfig loads a real .grype.yaml through the same fangs/viper path
// grype uses. fangs invokes PostLoad, so decoding (including YAML timestamps)
// and validation are covered end to end.
func loadExemptionConfig(t *testing.T, contents string) (*Grype, error) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".grype.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(contents), 0o600))

	opts := DefaultGrype(clio.Identification{Name: "grype"})
	cfg := fangs.NewConfig("grype")
	cfg.Files = []string{configPath}

	return opts, fangs.Load(cfg, &cobra.Command{}, opts)
}

//nolint:funlen // table-driven configuration loading cases
func TestGrype_PostLoad_Exemptions(t *testing.T) {
	tests := []struct {
		name          string
		config        string
		wantErr       string
		wantIgnores   int
		wantWarning   int
		wantFirstFrom string
		wantFirstTo   string
		wantInvalid   bool
	}{
		{
			name: "quoted RFC3339 window is accepted",
			config: `ignore:
  - vulnerability: CVE-2021-1
    effective-from: "2025-01-01T00:00:00Z"
    expires-on: "2025-06-30T00:00:00Z"
    owner: security-team
    reason: accepted
    assessment-id: ASMT-1
`,
			wantIgnores:   1,
			wantWarning:   match.DefaultExemptionWarningDays,
			wantFirstFrom: "2025-01-01T00:00:00Z",
			wantFirstTo:   "2025-06-30T00:00:00Z",
		},
		{
			name: "unquoted YAML timestamp is accepted",
			config: `ignore:
  - vulnerability: CVE-2021-1
    effective-from: 2025-01-01T00:00:00Z
    expires-on: 2025-06-30T00:00:00Z
    owner: security-team
    reason: accepted
    assessment-id: ASMT-1
`,
			wantIgnores:   1,
			wantWarning:   match.DefaultExemptionWarningDays,
			wantFirstFrom: "2025-01-01T00:00:00Z",
			wantFirstTo:   "2025-06-30T00:00:00Z",
		},
		{
			name: "offsets are normalized to UTC",
			config: `ignore:
  - vulnerability: CVE-2021-1
    effective-from: 2025-01-01T08:00:00+08:00
    expires-on: 2025-06-30T08:00:00+08:00
    owner: security-team
    reason: accepted
    assessment-id: ASMT-1
`,
			wantIgnores:   1,
			wantWarning:   match.DefaultExemptionWarningDays,
			wantFirstFrom: "2025-01-01T00:00:00Z",
			wantFirstTo:   "2025-06-30T00:00:00Z",
		},
		{
			name: "legacy rule without dates keeps working",
			config: `ignore:
  - vulnerability: CVE-2021-1
    reason: legacy
`,
			wantIgnores: 1,
			wantWarning: match.DefaultExemptionWarningDays,
		},
		{
			name: "warning days configurable",
			config: `exemption-warning-days: 3
ignore:
  - vulnerability: CVE-2021-1
    effective-from: "2025-01-01T00:00:00Z"
    expires-on: "2025-06-30T00:00:00Z"
    owner: security-team
    reason: accepted
    assessment-id: ASMT-1
`,
			wantIgnores:   1,
			wantWarning:   3,
			wantFirstFrom: "2025-01-01T00:00:00Z",
			wantFirstTo:   "2025-06-30T00:00:00Z",
		},
		{
			name: "invalid date refuses the configuration",
			config: `ignore:
  - vulnerability: CVE-2021-1
    effective-from: "not-a-date"
    expires-on: "2025-06-30T00:00:00Z"
    owner: security-team
    reason: accepted
    assessment-id: ASMT-1
`,
			wantErr: "invalid ignore rules",
		},
		{
			name: "inverted window refuses the configuration",
			config: `ignore:
  - vulnerability: CVE-2021-1
    effective-from: "2025-06-30T00:00:00Z"
    expires-on: "2025-01-01T00:00:00Z"
    owner: security-team
    reason: accepted
    assessment-id: ASMT-1
`,
			wantErr: "must be before",
		},
		{
			name: "missing expires-on refuses the configuration",
			config: `ignore:
  - vulnerability: CVE-2021-1
    effective-from: "2025-01-01T00:00:00Z"
    owner: security-team
    reason: accepted
    assessment-id: ASMT-1
`,
			wantErr: "missing expires-on",
		},
		{
			name: "missing owner is rejected but kept for reporting",
			config: `ignore:
  - vulnerability: CVE-2021-1
    effective-from: "2025-01-01T00:00:00Z"
    expires-on: "2025-06-30T00:00:00Z"
    reason: accepted
    assessment-id: ASMT-1
`,
			wantIgnores:   1,
			wantWarning:   match.DefaultExemptionWarningDays,
			wantFirstFrom: "2025-01-01T00:00:00Z",
			wantFirstTo:   "2025-06-30T00:00:00Z",
			wantInvalid:   true,
		},
		{
			name: "legacy rule with an un-migratable neighbour refuses the whole configuration",
			config: `ignore:
  - vulnerability: CVE-2021-1
    reason: legacy
  - vulnerability: CVE-2021-2
    effective-from: "2025-01-01T00:00:00Z"
    owner: security-team
    reason: accepted
    assessment-id: ASMT-1
`,
			wantErr: "missing expires-on",
		},
		{
			name: "negative warning days is rejected",
			config: `exemption-warning-days: -1
`,
			wantErr: "exemption-warning-days",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts, err := loadExemptionConfig(t, tt.config)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Len(t, opts.Ignore, tt.wantIgnores)
			assert.Equal(t, tt.wantWarning, opts.ExemptionWarningDays)
			if tt.wantFirstFrom != "" {
				assert.Equal(t, tt.wantFirstFrom, opts.Ignore[0].EffectiveFrom.String())
				assert.Equal(t, tt.wantFirstTo, opts.Ignore[0].ExpiresOn.String())
			}
			if tt.wantInvalid {
				// the rejected entry must be retained for reporting but never active
				assert.False(t, opts.Ignore[0].ActiveAt(time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)))
			}
		})
	}
}
