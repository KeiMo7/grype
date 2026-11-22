package dedup

import (
	"github.com/anchore/grype/grype/match"
)

// ReasonFindingKey is the audit reason recorded when findings merge under ModeFinding: they
// share one vulnerability from one source on one package identity across architectures, and
// differ only in the paths that discovered the package.
const ReasonFindingKey = "same-vulnerability-package-multiple-paths"

// Report is the audit trail of one Dedup run. Under ModeLegacy it is the zero value. It lets
// a reviewer answer: how many findings went in, how many came out, which records were folded
// together, on what rule, which record survived, and whether anything failed or was truncated.
type Report struct {
	// Mode is the dedup mode the run used.
	Mode string `json:"mode"`
	// InputCount is the number of matches handed to Dedup.
	InputCount int `json:"inputCount"`
	// OutputCount is the number of matches returned after deduplication.
	OutputCount int `json:"outputCount"`
	// MergedGroupCount is the number of groups that merged two or more findings.
	MergedGroupCount int `json:"mergedGroupCount"`
	// MergedGroups details every multi-member group, ordered deterministically.
	MergedGroups []MergedGroup `json:"mergedGroups,omitempty"`
	// Failures lists findings whose key could not be computed and which were therefore kept
	// unmerged; no finding is ever dropped on failure.
	Failures []KeyFailure `json:"failures,omitempty"`
	// PathsTruncated is the number of surviving matches whose path union was truncated.
	PathsTruncated int `json:"pathsTruncated,omitempty"`
}

// MergedGroup describes one second-stage merge for auditors.
type MergedGroup struct {
	// Key is the human-readable finding identity shared by the group.
	Key string `json:"key"`
	// Reason names the rule that grouped the findings.
	Reason string `json:"reason"`
	// Kept identifies the surviving match (the strongest record in the group).
	Kept MatchRef `json:"kept"`
	// Merged lists every folded finding with the fields needed to judge the merge.
	Merged []match.MergedRecord `json:"merged"`
}

// MatchRef identifies the survivor of a merge.
type MatchRef struct {
	VulnerabilityID string `json:"vulnerabilityId"`
	Namespace       string `json:"namespace"`
	PackageName     string `json:"packageName"`
	Version         string `json:"version"`
	Type            string `json:"packageType"`
	Architecture    string `json:"architecture"`
	Fingerprint     string `json:"fingerprint"`
}

// KeyFailure records a match that could not be assigned a finding key. The match is preserved
// unmerged rather than discarded.
type KeyFailure struct {
	// Fingerprint is the match's first-stage fingerprint, its best available identity.
	Fingerprint string `json:"fingerprint"`
	// VulnerabilityID and PackageName help locate the finding in output.
	VulnerabilityID string `json:"vulnerabilityId"`
	PackageName     string `json:"packageName"`
	// Error is the recovered failure reason.
	Error string `json:"error"`
}

func refOf(m match.Match, arch string) MatchRef {
	return MatchRef{
		VulnerabilityID: m.Vulnerability.ID,
		Namespace:       m.Vulnerability.Namespace,
		PackageName:     m.Package.Name,
		Version:         m.Package.Version,
		Type:            string(m.Package.Type),
		Architecture:    arch,
		Fingerprint:     m.Fingerprint().ID(),
	}
}
