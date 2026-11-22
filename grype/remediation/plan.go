// Package remediation computes an executable upgrade plan on top of finished
// vulnerability match results. It never touches the vulnerability DB or the
// matching logic: given the same matches it always produces the same plan.
//
// Planning model:
//
//   - Matches are planned per package instance (keyed by package ID); two
//     packages that happen to share a name are never merged.
//   - A finding is resolved by an upgrade target T only when T is greater than
//     or equal to one of the finding's fix versions AND T sits on the same
//     release line as that fix version (see versions.go). A fix recorded only
//     for another release line does not count -- upgrading to the highest
//     branch must not silently claim findings fixed elsewhere.
//   - Upgrade targets are always strictly greater than the installed version;
//     the planner never recommends a downgrade or a lateral move.
//   - Version order always comes from the ecosystem comparator in
//     grype/version, never from string ordering. If the order of two versions
//     cannot be determined, the whole package is marked for manual review
//     instead of guessing.
//   - Pre-release versions and build metadata follow the ecosystem
//     comparator's own rules (semver build metadata is ignored for ordering,
//     pre-releases order before their release). Packages where the installed
//     version or a candidate target uses either are annotated, not treated
//     specially.
//   - Findings that cannot be cleared are never dropped: they are listed in
//     the package's residual set with an explicit reason.
package remediation

// ResidualReason explains why a finding remains after the planned upgrades.
type ResidualReason string

const (
	// ReasonNoFixAvailable: the vendor has not released a fix (fix state "not-fixed").
	ReasonNoFixAvailable ResidualReason = "no-fix-available"
	// ReasonWontFix: the vendor has stated the finding will not be fixed (fix state "wont-fix").
	ReasonWontFix ResidualReason = "wont-fix"
	// ReasonInsufficientInfo: the fix state is unknown; there is not enough information to plan.
	ReasonInsufficientInfo ResidualReason = "insufficient-info"
	// ReasonDataAnomaly: fix state is "fixed" but no fix versions are recorded.
	ReasonDataAnomaly ResidualReason = "data-anomaly"
	// ReasonFixNotAboveCurrent: fix versions exist but none is strictly above the installed version.
	ReasonFixNotAboveCurrent ResidualReason = "fix-not-above-current"
	// ReasonNotCoveredByPlan: a fix exists but no planned upgrade target covers this finding.
	ReasonNotCoveredByPlan ResidualReason = "not-covered-by-planned-upgrades"
	// ReasonPackageUnplannable: the package as a whole could not be planned (see the package status reason).
	ReasonPackageUnplannable ResidualReason = "package-unplannable"
)

// PackageStatus is the planning outcome for one package instance.
type PackageStatus string

const (
	// StatusPlanned: upgrade targets were computed (the residual set may still be non-empty).
	StatusPlanned PackageStatus = "planned"
	// StatusManualReview: the package could not be planned -- unknown ecosystem, unparseable
	// versions, or undeterminable version order. No upgrade is suggested; a human must look.
	StatusManualReview PackageStatus = "manual-review"
)

// Finding is the planner's view of a single vulnerability match. It carries a
// copy of the relevant match data; the original match is never modified.
type Finding struct {
	VulnerabilityID string   `json:"vulnerability"`
	Namespace       string   `json:"namespace"`
	Severity        string   `json:"severity"`
	FixState        string   `json:"fixState"`
	FixVersions     []string `json:"fixVersions,omitempty"`
}

// Step is one recommended upgrade target. When no single version clears every
// fixable finding, the plan holds several steps ordered by what each leaves
// behind: least severe residual first, then fewest residual findings. Each
// step reports exactly which findings it clears and summarizes what would
// remain, so the sequence can be executed (or rejected) step by step.
type Step struct {
	TargetVersion       string    `json:"targetVersion"`
	Resolves            []Finding `json:"resolves"`
	ResidualCount       int       `json:"residualCount"`
	ResidualMaxSeverity string    `json:"residualMaxSeverity"`
}

// Residual is a finding that no planned upgrade clears, with the reason why.
type Residual struct {
	Finding
	Reason ResidualReason `json:"reason"`
	Detail string         `json:"detail"`
}

// PackagePlan is the upgrade plan for one package instance.
type PackagePlan struct {
	PackageID     string        `json:"packageId"`
	Name          string        `json:"name"`
	Version       string        `json:"version"`
	Type          string        `json:"type"`
	PURL          string        `json:"purl,omitempty"`
	VersionFormat string        `json:"versionFormat"`
	Status        PackageStatus `json:"status"`
	// StatusReason explains a manual-review status (why no plan could be produced).
	StatusReason string `json:"statusReason,omitempty"`
	// Annotations notes pre-release versions and build metadata handled per policy.
	Annotations []string `json:"annotations,omitempty"`
	// Steps are the ordered upgrade targets; empty when nothing can be upgraded.
	Steps []Step `json:"steps,omitempty"`
	// Residual lists every finding that remains, each with its reason. A finding
	// is never silently dropped from the plan.
	Residual []Residual `json:"residual,omitempty"`
}

// Plan is the full remediation plan for a scan result.
type Plan struct {
	Packages []PackagePlan `json:"packages"`
}
