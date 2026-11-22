// Package dedup applies a deterministic, configurable second-stage deduplication over a
// matched result set. It never participates in match decisions: it consumes the Matches
// collection produced by the matcher pipeline and only folds findings that describe the
// same vulnerability on what is, by configured identity, the same package.
//
// The zero Config is ModeLegacy, which performs no work at all so that default grype
// behavior is byte-identical to builds without this package.
package dedup

import (
	"fmt"
)

// Mode selects the deduplication identity applied to a result set.
type Mode string

const (
	// ModeLegacy keeps the existing fingerprint-only behavior of match.Matches: the input
	// collection is returned unchanged and no audit report is produced. This is the default.
	ModeLegacy Mode = "legacy"

	// ModeFinding groups findings by an explicit content key (vulnerability, source, package
	// name/version/type, architecture) that deliberately excludes discovery paths, so one
	// package reached through symlinks or multiple layer copies collapses into one finding
	// carrying the union of its paths.
	ModeFinding Mode = "finding"
)

const (
	// DefaultMaxPaths bounds how many discovery paths a merged finding records; paths beyond
	// the limit are dropped deterministically (sorted order) and the truncation is annotated.
	DefaultMaxPaths = 50
	// UnlimitedPaths disables path truncation.
	UnlimitedPaths = -1
)

// Config controls second-stage deduplication. The zero value is ModeLegacy.
type Config struct {
	// Mode is the deduplication identity: legacy (default, no behavior change) or finding.
	Mode Mode `yaml:"mode" json:"mode" mapstructure:"mode"`

	// MaxPaths is the maximum number of discovery paths retained on a merged finding.
	// 0 resolves to DefaultMaxPaths; UnlimitedPaths (-1) disables truncation.
	MaxPaths int `yaml:"max-paths" json:"max-paths" mapstructure:"max-paths"`

	// IncludePackageType keeps the package ecosystem in the finding key (default true in
	// validated configs). Disabling it allows, for example, an OS package and a language
	// package with the same name and version to merge; that is intentionally opt-in because
	// their fix paths differ.
	IncludePackageType *bool `yaml:"include-package-type" json:"include-package-type" mapstructure:"include-package-type"`
}

// DefaultConfig returns the config that preserves existing grype behavior.
func DefaultConfig() Config {
	t := true
	return Config{
		Mode:               ModeLegacy,
		MaxPaths:           DefaultMaxPaths,
		IncludePackageType: &t,
	}
}

// Validate fills defaults and rejects unsupported settings.
func (c *Config) Validate() error {
	switch c.Mode {
	case "":
		c.Mode = ModeLegacy
	case ModeLegacy, ModeFinding:
	default:
		return fmt.Errorf("invalid dedup mode %q (allowable: %s, %s)", c.Mode, ModeLegacy, ModeFinding)
	}

	if c.MaxPaths == 0 {
		c.MaxPaths = DefaultMaxPaths
	} else if c.MaxPaths < 0 && c.MaxPaths != UnlimitedPaths {
		return fmt.Errorf("invalid dedup max-paths %d: use %d for unlimited, 0 for the default", c.MaxPaths, UnlimitedPaths)
	}

	if c.IncludePackageType == nil {
		t := true
		c.IncludePackageType = &t
	}

	return nil
}

// includeType safely dereferences the option, treating nil as the default (true).
func (c Config) includeType() bool {
	return c.IncludePackageType == nil || *c.IncludePackageType
}
