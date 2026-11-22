package options

import (
	"github.com/anchore/clio"

	"github.com/anchore/grype/grype/match/dedup"
)

// dedupConfig is the CLI/YAML projection of the second-stage match deduplication settings.
// The zero/default mode is "legacy", which leaves grype's existing dedup behavior unchanged.
type dedupConfig struct {
	Mode               string `yaml:"mode" json:"mode" mapstructure:"mode"`
	MaxPaths           int    `yaml:"max-paths" json:"max-paths" mapstructure:"max-paths"`
	IncludePackageType *bool  `yaml:"include-package-type" json:"include-package-type" mapstructure:"include-package-type"`
	// AuditReport, when non-empty, is a file path the full dedup audit report is written to
	// after a scan. Empty (default) writes nothing.
	AuditReport string `yaml:"audit-report" json:"audit-report" mapstructure:"audit-report"`
}

var _ interface {
	clio.FieldDescriber
	clio.PostLoader
} = (*dedupConfig)(nil)

func defaultDedupConfig() dedupConfig {
	t := true
	return dedupConfig{
		Mode:               string(dedup.ModeLegacy),
		MaxPaths:           dedup.DefaultMaxPaths,
		IncludePackageType: &t,
	}
}

// ToDedupConfig maps the CLI config onto the library config and validates it.
func (d dedupConfig) ToDedupConfig() (dedup.Config, error) {
	cfg := dedup.Config{
		Mode:               dedup.Mode(d.Mode),
		MaxPaths:           d.MaxPaths,
		IncludePackageType: d.IncludePackageType,
	}
	if err := cfg.Validate(); err != nil {
		return dedup.DefaultConfig(), err
	}
	return cfg, nil
}

func (d *dedupConfig) PostLoad() error {
	// validate through the library config so the accepted values live in exactly one place
	_, err := d.ToDedupConfig()
	return err
}

func (d *dedupConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&d.Mode, `match deduplication mode: "legacy" (default, current behavior) or "finding" (deterministic finding-level dedup that merges the same package reached through multiple paths)`)
	descriptions.Add(&d.MaxPaths, `maximum discovery paths retained on a merged finding before truncation (0=default 50, -1=unlimited)`)
	descriptions.Add(&d.IncludePackageType, `include the package ecosystem in the dedup key so system and language packages stay separate findings (default true)`)
	descriptions.Add(&d.AuditReport, `optional file path to write the JSON dedup audit report (which findings merged, on what rule, which record survived)`)
}
