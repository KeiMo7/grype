package remediation

import (
	"strings"

	"github.com/anchore/grype/grype/version"
)

// releaseLine computes the release line of a raw version: the version with its
// final component removed. A fix recorded for version v is considered effective
// for any target on the same release line at or above v -- i.e. within
// [v, start-of-next-line) -- and not for targets on other lines. This is what
// keeps "fixed in 1.1.5" from being claimed by an upgrade to 1.3.1.
//
// The line is derived from the raw string with per-ecosystem rules:
//
//   - epoch prefixes ("2:...") are stripped for deb/rpm-style versions
//   - build metadata ("+...") is stripped for semver-style ecosystems
//     (deb/rpm/apk may legitimately carry "+" in the upstream version, so it
//     is kept there)
//   - distro revisions are stripped at the LAST "-" for deb/rpm/apk/pacman/
//     portage ("1.2.3-4.el8" -> "1.2.3"); pre-release suffixes are stripped at
//     the FIRST "-" for the other ecosystems ("1.2.3-rc.1" -> "1.2.3")
//
// A version with a single component (e.g. "5") has an empty line, meaning the
// fix applies to that version and everything after it.
func releaseLine(raw string, format version.Format) string {
	s := raw

	switch format {
	case version.DebFormat, version.RpmFormat:
		if i := strings.Index(s, ":"); i > 0 && isAllDigits(s[:i]) {
			s = s[i+1:]
		}
	}

	switch format {
	case version.SemanticFormat, version.GolangFormat:
		if i := strings.Index(s, "+"); i >= 0 {
			s = s[:i]
		}
	}

	switch format {
	case version.DebFormat, version.RpmFormat, version.ApkFormat, version.PacmanFormat, version.PortageFormat:
		if i := strings.LastIndex(s, "-"); i > 0 {
			s = s[:i]
		}
	default:
		if i := strings.Index(s, "-"); i > 0 {
			s = s[:i]
		}
	}

	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[:len(parts)-1], ".")
}

// sameReleaseLine reports whether target lies on the release line that fixRaw's
// fix applies to: the target's line equals the fix version's line or is nested
// inside it (e.g. fix "1.2" covers target "1.2.3.4"; fix "1.2.3" does not cover
// target "1.3.0").
func sameReleaseLine(fixRaw, targetRaw string, format version.Format) bool {
	line := releaseLine(fixRaw, format)
	if line == "" {
		return true
	}
	target := releaseLine(targetRaw, format)
	return target == line || strings.HasPrefix(target, line+".")
}

// isPrerelease reports whether the raw version carries a pre-release marker
// for the given format. Only semver-style ecosystems use "-" for pre-releases;
// for deb/rpm/apk-style versions "-" introduces a distro revision instead.
func isPrerelease(raw string, format version.Format) bool {
	switch format {
	case version.DebFormat, version.RpmFormat, version.ApkFormat, version.PacmanFormat, version.PortageFormat:
		return false
	}
	core := raw
	if i := strings.Index(core, "+"); i >= 0 {
		core = core[:i]
	}
	return strings.Contains(core, "-")
}

// hasBuildMetadata reports whether the raw version carries semver build
// metadata, which the comparison policy ignores for ordering.
func hasBuildMetadata(raw string, format version.Format) bool {
	switch format {
	case version.SemanticFormat, version.GolangFormat:
		return strings.Contains(raw, "+")
	}
	return false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
