package models

import (
	"github.com/anchore/grype/grype/match"
)

// ExemptionReport is one configured exemption and its state at scan time. It
// makes expiring, expired, and un-migrated exemptions visible in the report
// rather than leaving them as a silent, permanent suppression.
type ExemptionReport struct {
	// Position is the rule's index in the configured ignore list, so an
	// operator can locate it.
	Position int `json:"position"`
	// State is one of: active, expiring, expired, pending, invalid,
	// missing-metadata (a legacy exemption with no effective/expiry dates).
	State           string `json:"state"`
	Vulnerability   string `json:"vulnerability,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	Package         string `json:"package,omitempty"`
	EffectiveFrom   string `json:"effective-from,omitempty"`
	ExpiresOn       string `json:"expires-on,omitempty"`
	Owner           string `json:"owner,omitempty"`
	Reason          string `json:"reason,omitempty"`
	AssessmentID    string `json:"assessment-id,omitempty"`
	DaysUntilExpiry int    `json:"days-until-expiry,omitempty"`
	Error           string `json:"error,omitempty"`
}

// NewExemptionReport converts match-level exemption summaries into the report
// model. Everything is derived from the summaries, which were evaluated against
// the same clock the matcher used.
func NewExemptionReport(summaries []match.ExemptionSummary) []ExemptionReport {
	if len(summaries) == 0 {
		return nil
	}
	out := make([]ExemptionReport, 0, len(summaries))
	for _, s := range summaries {
		report := ExemptionReport{
			Position:        s.Position,
			State:           string(s.State),
			Vulnerability:   s.Rule.Vulnerability,
			Namespace:       s.Rule.Namespace,
			Package:         s.Rule.Package.Name,
			EffectiveFrom:   s.Rule.EffectiveFrom.String(),
			ExpiresOn:       s.Rule.ExpiresOn.String(),
			Owner:           s.Rule.Owner,
			Reason:          s.Rule.Reason,
			AssessmentID:    s.Rule.AssessmentID,
			DaysUntilExpiry: s.DaysUntilExpiry,
		}
		if s.Err != nil {
			report.Error = s.Err.Error()
		}
		out = append(out, report)
	}
	return out
}

// ExemptionExpiryAnnotation returns a short human-readable annotation for a
// suppressed row that names the exemption's expiry, or "" when the applied
// rules carry no exemption metadata.
func ExemptionExpiryAnnotation(rules []IgnoreRule) string {
	if len(rules) == 0 {
		return ""
	}
	for _, rule := range rules {
		if rule.ExpiresOn == "" {
			continue
		}
		annotation := "exempt until " + rule.ExpiresOn
		if rule.Owner != "" {
			annotation += " (" + rule.Owner + ")"
		}
		return annotation
	}
	return ""
}
