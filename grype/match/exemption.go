package match

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// ExemptionTimestamp is a timestamp string in an exemption window. It accepts
// either a quoted or an unquoted RFC3339 timestamp (which YAML may decode as a
// date) and normalizes it to UTC, so the same instant written in different
// zones compares identically.
type ExemptionTimestamp string

func (t ExemptionTimestamp) String() string { return string(t) }

// UnmarshalMapstructure implements mapstructure.Unmarshaler so configuration
// loading accepts YAML/JSON timestamps without requiring quotes.
func (t *ExemptionTimestamp) UnmarshalMapstructure(input any) error {
	switch v := input.(type) {
	case nil:
		*t = ""
	case string:
		*t = ExemptionTimestamp(strings.TrimSpace(v))
	case time.Time:
		*t = ExemptionTimestamp(v.UTC().Format(time.RFC3339Nano))
	default:
		return fmt.Errorf("expected a timestamp string, got %T", input)
	}
	return nil
}

// UnmarshalYAML implements yaml.Unmarshaler for configurations decoded with
// yaml.v3 directly (for example `grype config --load` consumers and tests).
func (t *ExemptionTimestamp) UnmarshalYAML(unmarshal func(any) error) error {
	var raw any
	if err := unmarshal(&raw); err != nil {
		return err
	}
	return t.UnmarshalMapstructure(raw)
}

// DefaultExemptionWarningDays is how many days before an exemption expires grype
// starts warning about it when no other value is configured.
const DefaultExemptionWarningDays = 14

// Clock supplies the current time to exemption evaluation. All comparisons are
// made in UTC, so the clock may return a time in any location.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// SystemClock is the default Clock implementation backed by time.Now.
var SystemClock Clock = systemClock{}

func clockNow(clock Clock) time.Time {
	if clock == nil {
		return time.Now()
	}
	return clock.Now()
}

// Now returns the time from clock, or the system time when clock is nil. It is
// the single place callers should read the clock so tests can inject a fixed
// clock and never depend on wall-clock time.
func Now(clock Clock) time.Time {
	return clockNow(clock)
}

// exemptionTimeLayouts are the accepted timestamp formats, in order. Timestamps
// with an explicit offset are normalized to UTC before comparison; date-only
// values are interpreted as midnight UTC.
var exemptionTimeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02",
}

// ParseExemptionTime parses an exemption timestamp and normalizes it to UTC.
func ParseExemptionTime(value string) (time.Time, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return time.Time{}, fmt.Errorf("timestamp is empty")
	}
	for _, layout := range exemptionTimeLayouts {
		if t, err := time.Parse(layout, v); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid timestamp %q: expected an RFC3339 timestamp with an explicit offset (for example 2025-01-31T00:00:00Z) or a date (YYYY-MM-DD)", value)
}

// ExemptionWindow is the half-open validity interval [Start, End) of an
// exemption. A moment exactly at End is expired, which makes the boundary
// behavior deterministic.
type ExemptionWindow struct {
	Start time.Time
	End   time.Time
}

// Contains reports whether now falls within [Start, End). The comparison is in
// UTC so timestamps written in different zones are comparable.
func (w ExemptionWindow) Contains(now time.Time) bool {
	n := now.UTC()
	return !n.Before(w.Start) && n.Before(w.End)
}

// hasExemptionMetadata reports whether any exemption-specific field is set. A
// rule without any (a legacy rule) keeps its previous, unbounded semantics.
// Reason is deliberately not considered: it is free text that legacy rules
// already carry and must never influence matching or classification.
func (r IgnoreRule) hasExemptionMetadata() bool {
	return strings.TrimSpace(r.EffectiveFrom.String()) != "" ||
		strings.TrimSpace(r.ExpiresOn.String()) != "" ||
		strings.TrimSpace(r.Owner) != "" ||
		strings.TrimSpace(r.AssessmentID) != ""
}

// IsLegacy reports whether the rule predates exemption windows, i.e. carries no
// exemption metadata at all. Legacy rules keep suppressing indefinitely until
// they are migrated.
func (r IgnoreRule) IsLegacy() bool {
	return !r.hasExemptionMetadata()
}

// ExemptionIssue records one configured exemption that was rejected, and why.
type ExemptionIssue struct {
	Position int
	Rule     IgnoreRule
	Err      error
}

// ValidateExemptionWindow checks that a rule carrying exemption metadata has a
// complete, parseable, non-inverted window. A failure is structural: the
// configuration cannot be trusted and loading it must be refused.
func (r IgnoreRule) ValidateExemptionWindow() error {
	if !r.hasExemptionMetadata() {
		return nil
	}
	if strings.TrimSpace(r.EffectiveFrom.String()) == "" {
		return fmt.Errorf("missing effective-from: effective-from and expires-on are both required for a time-bound exemption")
	}
	if strings.TrimSpace(r.ExpiresOn.String()) == "" {
		return fmt.Errorf("missing expires-on: effective-from and expires-on are both required for a time-bound exemption")
	}
	start, err := ParseExemptionTime(r.EffectiveFrom.String())
	if err != nil {
		return fmt.Errorf("effective-from: %w", err)
	}
	end, err := ParseExemptionTime(r.ExpiresOn.String())
	if err != nil {
		return fmt.Errorf("expires-on: %w", err)
	}
	if !start.Before(end) {
		return fmt.Errorf("effective-from (%s) must be before expires-on (%s)", start.Format(time.RFC3339), end.Format(time.RFC3339))
	}
	return nil
}

// ValidateExemptionAttribution checks the review metadata a time-bound
// exemption must carry. A failure rejects that entry only: the rule must not
// suppress, and it must be reported with its position.
func (r IgnoreRule) ValidateExemptionAttribution() error {
	if !r.hasExemptionMetadata() {
		return nil
	}
	if strings.TrimSpace(r.Owner) == "" {
		return fmt.Errorf("missing owner: a time-bound exemption must name who is responsible for it")
	}
	if strings.TrimSpace(r.Reason) == "" {
		return fmt.Errorf("missing reason: a time-bound exemption must record why it exists")
	}
	if strings.TrimSpace(r.AssessmentID) == "" {
		return fmt.Errorf("missing assessment-id: a time-bound exemption must reference the assessment that justified it")
	}
	return nil
}

// ValidateExemption checks the exemption window and its required metadata.
// Legacy rules (no exemption metadata) are valid. A rule that carries any
// exemption metadata must have a full, well-formed, non-inverted window and
// the owner, reason, and assessment reference that make it reviewable.
func (r IgnoreRule) ValidateExemption() error {
	if err := r.ValidateExemptionWindow(); err != nil {
		return err
	}
	return r.ValidateExemptionAttribution()
}

// ValidateIgnoreRulesConfig checks a configured rule list before it is used.
//
// A malformed window (unparseable date, missing bound, inverted bounds) is a
// structural error: the caller must refuse to load the whole configuration,
// which is signalled by a non-nil error. A rule with a valid window but no
// owner, reason, or assessment reference is reported in issues with its
// position; such a rule is never active (see ActiveAt), so it cannot suppress a
// match, and it stays in the rule list so the report can list it as invalid at
// its position. Legacy rules pass through unchanged.
func ValidateIgnoreRulesConfig(rules []IgnoreRule) ([]ExemptionIssue, error) {
	var structuralErrs []error
	var issues []ExemptionIssue
	for i, rule := range rules {
		if rule.IsLegacy() {
			continue
		}
		if err := rule.ValidateExemptionWindow(); err != nil {
			structuralErrs = append(structuralErrs, fmt.Errorf("ignore[%d]: %w", i, err))
			continue
		}
		if err := rule.ValidateExemptionAttribution(); err != nil {
			issues = append(issues, ExemptionIssue{Position: i, Rule: rule, Err: err})
		}
	}
	if len(structuralErrs) > 0 {
		return issues, fmt.Errorf("invalid ignore rule configuration: %w", errors.Join(structuralErrs...))
	}
	return issues, nil
}

// ExemptionWindow parses the rule's window. The boolean is false for legacy
// rules. An error means the window is malformed and the rule must never
// suppress a match.
func (r IgnoreRule) ExemptionWindow() (ExemptionWindow, bool, error) {
	if !r.hasExemptionMetadata() {
		return ExemptionWindow{}, false, nil
	}
	if err := r.ValidateExemptionWindow(); err != nil {
		return ExemptionWindow{}, false, err
	}
	start, err := ParseExemptionTime(r.EffectiveFrom.String())
	if err != nil {
		return ExemptionWindow{}, false, err
	}
	end, err := ParseExemptionTime(r.ExpiresOn.String())
	if err != nil {
		return ExemptionWindow{}, false, err
	}
	return ExemptionWindow{Start: start, End: end}, true, nil
}

// ActiveAt is the single predicate both ApplyIgnoreRulesAt (DB path) and the VEX
// processors consult, so no code path can suppress a match with an exemption the
// clock says is not active. The decision is recomputed from the rule and the
// supplied clock on every evaluation; nothing is cached, so a stale result
// cannot keep an expired exemption alive across runs. Legacy rules (no
// exemption metadata) are always active; a time-bound rule is active only
// within [effective-from, expires-on) and only when it is fully valid, so a
// malformed or incomplete exemption fails closed and never suppresses.
func (r IgnoreRule) ActiveAt(now time.Time) bool {
	if !r.hasExemptionMetadata() {
		return true
	}
	if err := r.ValidateExemption(); err != nil {
		return false
	}
	window, ok, err := r.ExemptionWindow()
	if err != nil || !ok {
		return false
	}
	return window.Contains(now)
}

// IgnoreMatchAt is IgnoreMatch evaluated against an explicit moment, so callers
// and tests never depend on wall-clock time. An expired exemption yields nil,
// which re-exposes the match to the caller.
func (r IgnoreRule) IgnoreMatchAt(match Match, now time.Time) []IgnoreRule {
	if !r.ActiveAt(now) {
		return nil
	}
	if conditionsApply(match, r.matchConditions()) {
		return []IgnoreRule{r}
	}
	return nil
}

// MatchesCriteria reports whether the match satisfies the rule's matching
// criteria, ignoring the exemption window. It exists for callers that have
// already decided the rule is active (or that evaluate the window themselves)
// and must not consult the clock, such as the VEX processors.
func (r IgnoreRule) MatchesCriteria(match Match) bool {
	return conditionsApply(match, r.matchConditions())
}

// An ExemptionState classifies an exemption relative to a moment in time.
type ExemptionState string

const (
	// ExemptionPending means the rule is not effective yet.
	ExemptionPending ExemptionState = "pending"
	// ExemptionActive means the rule currently suppresses matches.
	ExemptionActive ExemptionState = "active"
	// ExemptionExpiring means the rule is active but will expire within the warning period.
	ExemptionExpiring ExemptionState = "expiring"
	// ExemptionExpired means the rule no longer suppresses matches.
	ExemptionExpired ExemptionState = "expired"
	// ExemptionLegacy means the rule has no window and suppresses indefinitely.
	ExemptionLegacy ExemptionState = "missing-metadata"
	// ExemptionInvalid means the rule's window is malformed and it never suppresses.
	ExemptionInvalid ExemptionState = "invalid"
)

// ExemptionSummary describes the state of one configured exemption at a moment
// in time, for reporting and warnings.
type ExemptionSummary struct {
	Position        int
	Rule            IgnoreRule
	State           ExemptionState
	StartsAt        time.Time
	EndsAt          time.Time
	DaysUntilExpiry int
	// Err is set only when State is ExemptionInvalid, and explains why.
	Err error
}

// SummarizeExemptions classifies every rule as of now. Rules are returned in
// configuration order so reports are stable.
func SummarizeExemptions(rules []IgnoreRule, now time.Time, warningDays int) []ExemptionSummary {
	n := now.UTC()
	out := make([]ExemptionSummary, 0, len(rules))
	for i, rule := range rules {
		summary := ExemptionSummary{Position: i, Rule: rule}

		window, ok, err := rule.ExemptionWindow()
		if err == nil {
			err = rule.ValidateExemptionAttribution()
		}
		switch {
		case err != nil:
			summary.State = ExemptionInvalid
			summary.Err = err
		case !ok:
			summary.State = ExemptionLegacy
		default:
			summary.StartsAt = window.Start
			summary.EndsAt = window.End
			switch {
			case n.Before(window.Start):
				summary.State = ExemptionPending
			case !n.Before(window.End):
				summary.State = ExemptionExpired
			default:
				summary.DaysUntilExpiry = int(math.Ceil(window.End.Sub(n).Hours() / 24))
				if warningDays > 0 && summary.DaysUntilExpiry <= warningDays {
					summary.State = ExemptionExpiring
				} else {
					summary.State = ExemptionActive
				}
			}
		}

		out = append(out, summary)
	}
	return out
}

// MigrateIgnoreRules resolves rules written before exemption windows existed.
// Rules without any exemption metadata are kept unchanged (and so keep their
// previous suppression behavior) and reported by index as needing migration.
// A rule whose window cannot be parsed makes the migration fail atomically: the
// input rules are returned unmodified along with every error, so a failed
// migration can never leave a half-migrated list that suppresses differently.
// Missing attribution is not a migration failure: such a rule is inert (see
// ActiveAt) and is reported separately by ValidateIgnoreRulesConfig.
func MigrateIgnoreRules(rules []IgnoreRule) ([]IgnoreRule, []int, []error) {
	legacy := make([]int, 0)
	var errs []error
	for i, rule := range rules {
		if rule.IsLegacy() {
			legacy = append(legacy, i)
			continue
		}
		if err := rule.ValidateExemptionWindow(); err != nil {
			errs = append(errs, fmt.Errorf("ignore[%d]: %w", i, err))
		}
	}
	if len(errs) > 0 {
		return rules, nil, errs
	}
	return rules, legacy, nil
}

// ActiveIgnoreRules returns the rules that may suppress a match at now.
func ActiveIgnoreRules(rules []IgnoreRule, now time.Time) []IgnoreRule {
	out := make([]IgnoreRule, 0, len(rules))
	for _, rule := range rules {
		if rule.ActiveAt(now) {
			out = append(out, rule)
		}
	}
	return out
}
