package match

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
)

var ErrCannotMerge = fmt.Errorf("unable to merge vulnerability matches")

// Match represents a finding in the vulnerability matching process, pairing a single package and a single vulnerability object.
type Match struct {
	Vulnerability vulnerability.Vulnerability // The vulnerability details of the match.
	Package       pkg.Package                 // The package used to search for a match.
	Details       Details                     // all the ways this particular match was made.

	// MergeAudit records second-stage finding deduplication (grype/match/dedup): which
	// separate findings were folded into this one and why. It is nil on matches that were not
	// produced by a merge, including every match under the default legacy mode, so existing
	// output stays unchanged.
	MergeAudit *MergeAudit
}

// MergeAudit explains one second-stage merge: the rule that grouped the findings, the records
// folded in, and any truncation applied while collecting their paths.
type MergeAudit struct {
	// Reason is the configured identity rule that made the group one finding.
	Reason string `json:"reason,omitempty"`
	// MergedFrom lists every finding folded into the surviving match, strongest record excluded.
	MergedFrom []MergedRecord `json:"mergedFrom,omitempty"`
	// PathsTruncated is set when the unioned discovery paths exceeded the configured limit.
	PathsTruncated bool `json:"pathsTruncated,omitempty"`
	// PathsDropped counts paths removed by truncation.
	PathsDropped int `json:"pathsDropped,omitempty"`
}

// MergedRecord captures the identity and reconciliation-relevant fields of one finding folded
// into the survivor of a second-stage merge, so an auditor can see exactly what was combined.
type MergedRecord struct {
	// Fingerprint is the pre-merge fingerprint of the folded finding.
	Fingerprint string `json:"fingerprint"`
	// PackageVersion is the version of the folded finding's package.
	PackageVersion string `json:"packageVersion,omitempty"`
	// Constraint is the raw version constraint of the folded vulnerability record, when known.
	Constraint string `json:"constraint,omitempty"`
	// FixVersions are the fixed-in versions the folded record carried.
	FixVersions []string `json:"fixVersions,omitempty"`
	// Paths are the discovery paths (RealPath, with AccessPath annotated when it differs)
	// the folded finding contributed before union/truncation.
	Paths []string `json:"paths,omitempty"`
	// Status is the vulnerability record status of the folded finding.
	Status string `json:"status,omitempty"`
	// Unaffected marks records that declared the package not affected.
	Unaffected bool `json:"unaffected,omitempty"`
}

// String is the string representation of select match fields.
func (m Match) String() string {
	return fmt.Sprintf("Match(pkg=%s vuln=%q types=%q)", m.Package, m.Vulnerability.String(), m.Details.Types())
}

func (m Match) Fingerprint() Fingerprint {
	return Fingerprint{
		vulnerabilityID:        m.Vulnerability.ID,
		vulnerabilityNamespace: m.Vulnerability.Namespace,
		packageID:              m.Package.ID,
	}
}

// Merge folds another match for the same finding -- the same vulnerability, from the same source, on
// the same package -- into this one.
//
// Several records can describe one finding and disagree about the particulars: an NVD CVE listing
// two vulnerable CPEs that the package matches, or an advisory found both directly and through the
// package's upstream. Each is a separate record with its own constraint and fixed-in version, but to
// a user they are one finding, so they are reported as one match.
//
// The record that produced the strongest match supplies the fields that cannot be combined --
// severity metadata, package name, fix state -- and the remainder are unioned: fixed-in versions,
// constraints, advisories, aliases, CPEs and match details. Every record contributes its own detail,
// so how each one matched is preserved even though only one describes the finding as a whole.
func (m *Match) Merge(other Match) error {
	if other.Fingerprint() != m.Fingerprint() {
		return ErrCannotMerge
	}

	mergeFields(m, other)

	return nil
}

// MergeFields folds other into m as records of one finding without the equal-fingerprint
// precondition of Merge. It exists for second-stage result deduplication
// (grype/match/dedup), whose configured identity can group matches carrying different
// fingerprints. Callers must have already established that both records describe the same
// finding; ordinary collection code should keep using Merge.
func (m *Match) MergeFields(other Match) {
	mergeFields(m, other)
}

// mergeFields folds another record describing the same finding into the receiver without a
// fingerprint check. It is shared by Merge (same fingerprint) and by second-stage finding
// deduplication (grype/match/dedup), which groups records on a configured identity that can
// span several fingerprints. Callers are responsible for deciding the records are the same
// finding; everything here is field reconciliation, unchanged from Merge's body.
func mergeFields(m *Match, other Match) {
	// the record that matched most strongly describes the finding; the other only feeds the unions below
	base, secondary := m.Vulnerability, other.Vulnerability
	if compareRecordAuthority(other, *m) < 0 {
		base, secondary = other.Vulnerability, m.Vulnerability
	}

	base.Fix = mergeFix(base.Fix, secondary.Fix)

	// note: the combined constraint is informational -- whether each record applies was decided
	// before the match was created, and every record's own constraint is preserved on the detail it
	// contributed.
	base.Constraint = version.CombineConstraints(base.Constraint, secondary.Constraint)

	// there are cases related vulnerabilities are synthetic, for example when
	// orienting results by CVE. we need to keep track of these
	base.RelatedVulnerabilities = mergeReferences(base.RelatedVulnerabilities, secondary.RelatedVulnerabilities)
	base.Advisories = mergeAdvisories(base.Advisories, secondary.Advisories)

	// retain all unique CPEs for consistent output
	base.CPEs = cpe.Merge(base.CPEs, secondary.CPEs)
	if base.CPEs == nil {
		// ensure we always have a non-nil slice
		base.CPEs = []cpe.CPE{}
	}

	m.Vulnerability = base
	m.Details = mergeDetails(m.Details, other.Details)
}

// compareRecordAuthority orders two matches for the same finding by how well each describes it, best
// first, so that the winner does not depend on the order the matches were added in. That holds for any
// number of records, which needs both halves to survive a merge unchanged:
//
//   - rank is the strongest detail type in a set, and merging unions detail sets, so a merged record
//     ranks as the better of the two it came from. The best-ranked record wins whatever the order.
//   - the tiebreak compares only fields the winner keeps intact, so they read the same on a merged
//     record as on an input. Detail sets cannot serve here: merging unions them, so a third record
//     would be compared against a set that was never an input, and the winner would depend on order.
//
// CompareRecordAuthority exposes the record-authority ordering used by Merge for second-stage
// result deduplication (grype/match/dedup), which must select the same strongest record when
// merging matches that do not share a fingerprint. It returns a negative value when a is the
// stronger record, zero when they tie, positive when b is stronger.
func CompareRecordAuthority(a, b Match) int {
	return compareRecordAuthority(a, b)
}

func compareRecordAuthority(a, b Match) int {
	if c := cmp.Compare(a.Details.rank(), b.Details.rank()); c != 0 {
		return c
	}
	return compareUnmergedFields(a.Vulnerability, b.Vulnerability)
}

// compareUnmergedFields orders two records for one finding by the fields Merge takes from the winner
// rather than unioning. Everything else the winner supplies is either fixed by the fingerprint -- the
// ID, the namespace, and the metadata cached against them -- or already spent by the time a match
// exists, as package qualifiers are. So when these compare equal, either record can win and the merge
// produces the same match.
func compareUnmergedFields(a, b vulnerability.Vulnerability) int {
	if c := strings.Compare(a.PackageName, b.PackageName); c != 0 {
		return c
	}
	if c := strings.Compare(a.Status, b.Status); c != 0 {
		return c
	}
	if a.Unaffected != b.Unaffected {
		// a record calling the package unaffected describes the finding least well
		if a.Unaffected {
			return 1
		}
		return -1
	}
	return 0
}

// mergeFix unions the fix information of two records describing the same finding, with a fix reported
// by either record clearing it (see TestMergeFix_StateResolution for the whole state table).
func mergeFix(base, other vulnerability.Fix) vulnerability.Fix {
	out := vulnerability.Fix{
		State: base.State,
	}

	if versions := slices.Concat(base.Versions, other.Versions); len(versions) > 0 {
		slices.Sort(versions)
		out.Versions = slices.Compact(versions)
	}

	seen := make(map[vulnerability.FixAvailable]struct{}, len(base.Available)+len(other.Available))
	for _, a := range slices.Concat(base.Available, other.Available) {
		if _, exists := seen[a]; exists {
			continue
		}
		seen[a] = struct{}{}
		out.Available = append(out.Available, a)
	}

	out.State = mergeFixState(base.State, other.State)

	return out
}

// fixStatePrecedence ranks fix states from least to most informative, so that mergeFixState can take
// the higher of two rather than favouring whichever record happened to be the base. Without it the
// merged state depends on merge direction, and for three or more records that means it depends on the
// order they arrived in.
//
// not-fixed outranking wont-fix is the one judgement call here. Both say no fix is available, and
// merging should not make a finding easier to suppress than either record was on its own -- users
// routinely ignore `fix-state: wont-fix`, so promoting to it would hide a finding one of the records
// never claimed was closed.
var fixStatePrecedence = map[vulnerability.FixState]int{
	"":                             0, // a record that states nothing at all
	vulnerability.FixStateUnknown:  1,
	vulnerability.FixStateWontFix:  2,
	vulnerability.FixStateNotFixed: 3,
	vulnerability.FixStateFixed:    4,
}

// mergeFixState resolves the fix states of two records describing one finding, most informative first.
func mergeFixState(a, b vulnerability.FixState) vulnerability.FixState {
	if fixStatePrecedence[b] > fixStatePrecedence[a] {
		return b
	}
	return a
}

// mergeReferences unions two sets of vulnerability references (aliases), sorted for stable output.
func mergeReferences(base, other []vulnerability.Reference) []vulnerability.Reference {
	seen := make(map[vulnerability.Reference]struct{}, len(base)+len(other))
	var out []vulnerability.Reference
	for _, r := range slices.Concat(base, other) {
		// comparable without Internal reference
		key := vulnerability.Reference{ID: r.ID, Namespace: r.Namespace}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, r)
	}

	// for stable output
	slices.SortFunc(out, func(a, b vulnerability.Reference) int {
		if c := strings.Compare(a.Namespace, b.Namespace); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// mergeAdvisories unions two sets of advisories, sorted for stable output.
func mergeAdvisories(base, other []vulnerability.Advisory) []vulnerability.Advisory {
	// vulnerability.Advisory is comparable, so it keys the set on its own
	seen := make(map[vulnerability.Advisory]struct{}, len(base)+len(other))
	var out []vulnerability.Advisory
	for _, a := range slices.Concat(base, other) {
		if _, exists := seen[a]; exists {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}

	// for stable output
	slices.SortFunc(out, func(a, b vulnerability.Advisory) int {
		if c := strings.Compare(a.ID, b.ID); c != 0 {
			return c
		}
		return strings.Compare(a.Link, b.Link)
	})
	return out
}
