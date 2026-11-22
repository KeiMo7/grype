package models

import "github.com/anchore/grype/grype/match"

type IgnoredMatch struct {
	Match
	AppliedIgnoreRules []IgnoreRule `json:"appliedIgnoreRules"`

	// Exemption answers "which exemption suppressed this match, and when does it
	// expire". It is empty for rules without exemption metadata (legacy rules and
	// matcher-internal suppressions), so the existing output shape is preserved.
	Exemption *AppliedExemption `json:"exemption,omitempty"`
}

// AppliedExemption describes the time-bound exemption that suppressed a match.
type AppliedExemption struct {
	EffectiveFrom string `json:"effective-from,omitempty"`
	ExpiresOn     string `json:"expires-on,omitempty"`
	Owner         string `json:"owner,omitempty"`
	Reason        string `json:"reason,omitempty"`
	AssessmentID  string `json:"assessment-id,omitempty"`
}

type IgnoreRule struct {
	Vulnerability    string             `json:"vulnerability,omitempty"`
	Reason           string             `json:"reason,omitempty"`
	Namespace        string             `json:"namespace"`
	FixState         string             `json:"fix-state,omitempty"`
	Package          *IgnoreRulePackage `json:"package,omitempty"`
	VexStatus        string             `json:"vex-status,omitempty"`
	VexJustification string             `json:"vex-justification,omitempty"`
	MatchType        string             `json:"match-type,omitempty"`
	EffectiveFrom    string             `json:"effective-from,omitempty"`
	ExpiresOn        string             `json:"expires-on,omitempty"`
	Owner            string             `json:"owner,omitempty"`
	AssessmentID     string             `json:"assessment-id,omitempty"`
}

type IgnoreRulePackage struct {
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	Language     string `json:"language"`
	Type         string `json:"type,omitempty"`
	Location     string `json:"location,omitempty"`
	UpstreamName string `json:"upstream-name,omitempty"`
}

func newIgnoreRule(r match.IgnoreRule) IgnoreRule {
	var ignoreRulePackage *IgnoreRulePackage

	// We'll only set the package part of the rule not to `nil` if there are any values to fill out.
	if p := r.Package; p.Name != "" || p.Version != "" || p.Type != "" || p.Location != "" {
		ignoreRulePackage = &IgnoreRulePackage{
			Name:         r.Package.Name,
			Version:      r.Package.Version,
			Language:     r.Package.Language,
			Type:         r.Package.Type,
			Location:     r.Package.Location,
			UpstreamName: r.Package.UpstreamName,
		}
	}

	return IgnoreRule{
		Vulnerability:    r.Vulnerability,
		Reason:           r.Reason,
		Namespace:        r.Namespace,
		FixState:         r.FixState,
		Package:          ignoreRulePackage,
		VexStatus:        r.VexStatus,
		VexJustification: r.VexJustification,
		MatchType:        string(r.MatchType),
		EffectiveFrom:    r.EffectiveFrom.String(),
		ExpiresOn:        r.ExpiresOn.String(),
		Owner:            r.Owner,
		AssessmentID:     r.AssessmentID,
	}
}

// newAppliedExemption returns the exemption that suppressed a match, or nil
// when no applied rule carries exemption metadata (legacy rules and
// matcher-internal suppressions), so the output shape is unchanged for them.
func newAppliedExemption(rules []match.IgnoreRule) *AppliedExemption {
	for _, rule := range rules {
		if rule.IsLegacy() {
			continue
		}
		return &AppliedExemption{
			EffectiveFrom: rule.EffectiveFrom.String(),
			ExpiresOn:     rule.ExpiresOn.String(),
			Owner:         rule.Owner,
			Reason:        rule.Reason,
			AssessmentID:  rule.AssessmentID,
		}
	}
	return nil
}

func mapIgnoreRules(rules []match.IgnoreRule) []IgnoreRule {
	var result []IgnoreRule

	for _, rule := range rules {
		result = append(result, newIgnoreRule(rule))
	}

	return result
}
