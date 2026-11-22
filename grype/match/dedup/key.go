package dedup

import (
	"fmt"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/pkg/qualifier/architecture"
	syftSource "github.com/anchore/syft/syft/source"
)

// unknownArch is the architecture token used when neither the package metadata nor the scan
// source reveals an architecture. Within one scan there is a single scanned artifact, so two
// unknown-arch findings may still merge on the rest of the key; two scans of different
// architecture variants each carry a concrete source architecture and never reach this token.
const unknownArch = "unknown-arch"

// findingKey is the explicit, content-based identity of a finding under ModeFinding. It is a
// plain comparable struct so grouping is ordinary map equality and never depends on hashing
// succeeding. Locations are intentionally absent: one package discovered through several
// paths must land in one group.
type findingKey struct {
	vulnerabilityID        string
	vulnerabilityNamespace string
	packageName            string
	packageVersion         string
	packageType            string // empty when IncludePackageType is disabled
	architecture           string
}

// keyFor computes the ModeFinding identity of one match. sourceArchitecture is the scan
// source's architecture already canonicalized, or "" when the source carries none.
func keyFor(m match.Match, cfg Config, sourceArchitecture string) findingKey {
	k := findingKey{
		vulnerabilityID:        m.Vulnerability.ID,
		vulnerabilityNamespace: m.Vulnerability.Namespace,
		packageName:            m.Package.Name,
		packageVersion:         m.Package.Version,
		architecture:           packageArchitecture(m.Package, sourceArchitecture),
	}
	if cfg.includeType() {
		k.packageType = string(m.Package.Type)
	}
	return k
}

// packageArchitecture resolves a stable, dialect-canonical architecture token for a package,
// reusing the architecture qualifier's alias table so RPM/GNU and Debian/OCI spellings of the
// same CPU (x86_64 vs amd64, aarch64 vs arm64) collapse onto one token. Package metadata wins
// over the scan source; when neither supplies one, unknownArch is used.
//
// Architecture-independent values (rpm "noarch", deb "all", source "src") are not CPU
// architectures: a noarch package installed in the amd64 variant and one installed in the
// arm64 variant are still distinct artifacts and must never merge across scans. Such a value
// is therefore only used when no concrete scan-source architecture is available; otherwise the
// source architecture disambiguates the two variants.
func packageArchitecture(p pkg.Package, sourceArchitecture string) string {
	raw := packageArchMetadata(p)
	if isArchNeutral(raw) {
		if sourceArchitecture != "" {
			return sourceArchitecture
		}
		return raw
	}
	if raw == "" {
		raw = sourceArchitecture
	}
	if raw == "" {
		return unknownArch
	}
	return architecture.Canonicalize(raw, architecture.DefaultAliases())
}

// isArchNeutral reports values that describe role or architecture-independence rather than a
// concrete CPU. The tokens mirror pkg/qualifier/architecture's source/noarch handling. An empty
// string is absent metadata, not a neutral value, and must fall through to the source/unknown
// fallback rather than be treated as a token.
func isArchNeutral(arch string) bool {
	switch arch {
	case "noarch", "all", "src", "binary-no-arch-specified":
		return true
	}
	return false
}

// packageArchMetadata reads the architecture off the package metadata contracts. It mirrors
// the unexported packageArch in pkg/qualifier/architecture (rpm, apk) and extends it to the Go
// metadata contracts, which carry GOARCH.
func packageArchMetadata(p pkg.Package) string {
	switch m := p.Metadata.(type) {
	case pkg.RpmMetadata:
		return m.Arch
	case pkg.ApkMetadata:
		return m.Arch
	case pkg.GolangBinMetadata:
		return m.Architecture
	case *pkg.GolangBinMetadata:
		if m == nil {
			return ""
		}
		return m.Architecture
	case pkg.GolangSourceMetadata:
		return m.Architecture
	case *pkg.GolangSourceMetadata:
		if m == nil {
			return ""
		}
		return m.Architecture
	}
	return ""
}

// sourceArchitecture extracts and canonicalizes the scan source architecture. Only image
// sources carry one; SBOM and directory sources return "".
func sourceArchitecture(ctx pkg.Context) string {
	if ctx.Source == nil {
		return ""
	}
	meta, ok := ctx.Source.Metadata.(syftSource.ImageMetadata)
	if !ok {
		return ""
	}
	if meta.Architecture == "" {
		return ""
	}
	return architecture.Canonicalize(meta.Architecture, architecture.DefaultAliases())
}

// String renders the key for audit output. It is descriptive, not used for identity.
func (k findingKey) String() string {
	return fmt.Sprintf("vuln=%q namespace=%q pkg=%s@%s type=%q arch=%q",
		k.vulnerabilityID, k.vulnerabilityNamespace, k.packageName, k.packageVersion,
		k.packageType, k.architecture)
}
