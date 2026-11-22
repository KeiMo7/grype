package match

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

const (
	testVulnID     = "CVE-2025-1"
	testStart      = "2025-01-01T00:00:00Z"
	testEnd        = "2025-06-30T00:00:00Z"
	testEndOfYear  = "2025-12-31T00:00:00Z"
	testLegacyVuln = "CVE-legacy"
	testAnyVuln    = "CVE-1"
	testPkgVersion = "1.0.0"
)

// fixedClock is a deterministic Clock for exemption tests.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := ParseExemptionTime(value)
	require.NoError(t, err)
	return parsed
}

func exemptionRule(vuln, from, until string) IgnoreRule {
	return IgnoreRule{
		Vulnerability: vuln,
		EffectiveFrom: ExemptionTimestamp(from),
		ExpiresOn:     ExemptionTimestamp(until),
		Owner:         "security-team",
		Reason:        "accepted for now",
		AssessmentID:  "ASMT-1",
	}
}

func exemptionMatch(vuln, name string) Match {
	return Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: vuln, Namespace: "debian-vulns"},
		},
		Package: pkg.Package{
			ID:      pkg.ID(uuid.NewString()),
			Name:    name,
			Version: testPkgVersion,
			Type:    "deb",
		},
	}
}

func TestParseExemptionTime_NormalizesToUTC(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Time
		wantErr  bool
	}{
		{name: "zulu", input: "2025-03-01T00:00:00Z", expected: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)},
		{name: "positive offset", input: "2025-03-01T08:00:00+08:00", expected: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)},
		{name: "negative offset", input: "2025-02-28T19:00:00-05:00", expected: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)},
		{name: "date only is midnight UTC", input: "2025-03-01", expected: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)},
		{name: "nanoseconds", input: "2025-03-01T00:00:00.123456789Z", expected: time.Date(2025, 3, 1, 0, 0, 0, 123456789, time.UTC)},
		{name: "empty", input: "", wantErr: true},
		{name: "garbage", input: "not-a-date", wantErr: true},
		{name: "missing offset", input: "2025-03-01T00:00:00", wantErr: true},
		{name: "invalid day", input: "2025-02-30", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual, err := ParseExemptionTime(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.True(t, tt.expected.Equal(actual), "expected %s, got %s", tt.expected, actual)
			assert.Equal(t, time.UTC, actual.Location())
		})
	}
}

func TestExemptionWindow_SameInstantDifferentZonesAreEqual(t *testing.T) {
	utc, err := ParseExemptionTime("2025-06-30T12:00:00Z")
	require.NoError(t, err)
	plusEight, err := ParseExemptionTime("2025-06-30T20:00:00+08:00")
	require.NoError(t, err)
	assert.True(t, utc.Equal(plusEight), "the same instant written in different zones must compare equal")
}

func TestIgnoreRule_ActiveAt_FourStates(t *testing.T) {
	rule := exemptionRule(testVulnID, testStart, testEnd)

	tests := []struct {
		name   string
		now    string
		active bool
	}{
		{name: "before effective-from is pending", now: "2024-12-31T23:59:59Z", active: false},
		{name: "exactly at effective-from is active", now: testStart, active: true},
		{name: "inside the window is active", now: "2025-03-15T00:00:00Z", active: true},
		{name: "one second before expiry is active", now: "2025-06-29T23:59:59Z", active: true},
		{name: "exactly at expires-on is expired", now: testEnd, active: false},
		{name: "after expiry is expired", now: "2025-06-30T00:00:01Z", active: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := mustTime(t, tt.now)
			assert.Equal(t, tt.active, rule.ActiveAt(now))
			got := rule.IgnoreMatchAt(exemptionMatch(testVulnID, "pkg"), now)
			if tt.active {
				assert.Len(t, got, 1)
			} else {
				assert.Empty(t, got)
			}
		})
	}
}

func TestIgnoreRule_ActiveAt_LegacyAlwaysActive(t *testing.T) {
	legacy := IgnoreRule{Vulnerability: testVulnID, Reason: "old exemption"}
	assert.True(t, legacy.IsLegacy())
	assert.True(t, legacy.ActiveAt(time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)))
	assert.True(t, legacy.ActiveAt(time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)))
	assert.Len(t, legacy.IgnoreMatchAt(exemptionMatch(testVulnID, "pkg"), time.Now()), 1)
}

func TestIgnoreRule_ActiveAt_MalformedFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		rule IgnoreRule
	}{
		{name: "missing expires-on", rule: IgnoreRule{Vulnerability: testVulnID, EffectiveFrom: testStart, Owner: "o", Reason: "r", AssessmentID: "a"}},
		{name: "missing effective-from", rule: IgnoreRule{Vulnerability: testVulnID, ExpiresOn: testEnd, Owner: "o", Reason: "r", AssessmentID: "a"}},
		{name: "invalid date", rule: IgnoreRule{Vulnerability: testVulnID, EffectiveFrom: "nope", ExpiresOn: testEnd, Owner: "o", Reason: "r", AssessmentID: "a"}},
		{name: "inverted bounds", rule: IgnoreRule{Vulnerability: testVulnID, EffectiveFrom: testEnd, ExpiresOn: testStart, Owner: "o", Reason: "r", AssessmentID: "a"}},
		{name: "equal bounds", rule: IgnoreRule{Vulnerability: testVulnID, EffectiveFrom: testStart, ExpiresOn: testStart, Owner: "o", Reason: "r", AssessmentID: "a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.False(t, tt.rule.ActiveAt(time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)), "malformed exemptions must never be active")
		})
	}
}

func TestApplyIgnoreRulesAt_ExpiredExemptionNoLongerSuppresses(t *testing.T) {
	rules := []IgnoreRule{exemptionRule(testVulnID, testStart, testEnd)}
	matches := NewMatches(exemptionMatch(testVulnID, "pkg"))

	beforeExpiry := mustTime(t, "2025-06-29T00:00:00Z")
	remaining, ignored := ApplyIgnoreRulesAt(matches, rules, beforeExpiry)
	assert.Equal(t, 0, remaining.Count())
	require.Len(t, ignored, 1)
	require.Len(t, ignored[0].AppliedIgnoreRules, 1)
	assert.Equal(t, "ASMT-1", ignored[0].AppliedIgnoreRules[0].AssessmentID)

	// one second later the same rule must stop suppressing, with the match returning
	// to the results and the reason still traceable on a re-application
	atExpiry := mustTime(t, testEnd)
	remaining, ignored = ApplyIgnoreRulesAt(matches, rules, atExpiry)
	assert.Equal(t, 1, remaining.Count(), "the match must reappear once the exemption expires")
	assert.Empty(t, ignored)

	// and it must stay gone on a later run, without any cache to reset
	afterExpiry := mustTime(t, "2026-01-01T00:00:00Z")
	remaining, ignored = ApplyIgnoreRulesAt(matches, rules, afterExpiry)
	assert.Equal(t, 1, remaining.Count())
	assert.Empty(t, ignored)
}

func TestApplyIgnoreRulesAt_OverlappingExemptionsOnlyActiveOneApplies(t *testing.T) {
	// two rules for the same vulnerability and package, one expired, one still valid
	rules := []IgnoreRule{
		exemptionRule("CVE-2025-2", "2024-01-01T00:00:00Z", "2024-12-31T00:00:00Z"), // expired
		{
			Vulnerability: "CVE-2025-2",
			EffectiveFrom: testStart,
			ExpiresOn:     testEndOfYear,
			Owner:         "other-team",
			Reason:        "still tolerated",
			AssessmentID:  "ASMT-2",
		},
	}
	matches := NewMatches(exemptionMatch("CVE-2025-2", "pkg"))

	remaining, ignored := ApplyIgnoreRulesAt(matches, rules, mustTime(t, "2025-06-01T00:00:00Z"))
	assert.Equal(t, 0, remaining.Count())
	require.Len(t, ignored, 1)
	require.Len(t, ignored[0].AppliedIgnoreRules, 1)
	assert.Equal(t, "ASMT-2", ignored[0].AppliedIgnoreRules[0].AssessmentID, "only the unexpired exemption should apply")
}

func TestApplyIgnoreRulesAt_SameVulnerabilityDifferentPackagesIndependent(t *testing.T) {
	// the same vulnerability on two packages: expiring the first must not
	// release the second
	rules := []IgnoreRule{
		{
			Vulnerability: "CVE-2025-3",
			Package:       IgnoreRulePackage{Name: "pkg-a"},
			EffectiveFrom: testStart,
			ExpiresOn:     testEnd,
			Owner:         "team-a",
			Reason:        "a",
			AssessmentID:  "ASMT-A",
		},
		{
			Vulnerability: "CVE-2025-3",
			Package:       IgnoreRulePackage{Name: "pkg-b"},
			EffectiveFrom: testStart,
			ExpiresOn:     "2026-12-31T00:00:00Z",
			Owner:         "team-b",
			Reason:        "b",
			AssessmentID:  "ASMT-B",
		},
	}
	matches := NewMatches(
		exemptionMatch("CVE-2025-3", "pkg-a"),
		exemptionMatch("CVE-2025-3", "pkg-b"),
	)

	// after rule A expires, only pkg-a's match returns
	remaining, ignored := ApplyIgnoreRulesAt(matches, rules, mustTime(t, "2025-07-01T00:00:00Z"))
	require.Equal(t, 1, remaining.Count())
	assert.Equal(t, "pkg-a", remaining.Sorted()[0].Package.Name)
	require.Len(t, ignored, 1)
	assert.Equal(t, "pkg-b", ignored[0].Package.Name)
	assert.Equal(t, "ASMT-B", ignored[0].AppliedIgnoreRules[0].AssessmentID)
}

func TestSummarizeExemptions_StatesAndWarningDays(t *testing.T) {
	rules := []IgnoreRule{
		exemptionRule("CVE-pending", "2025-07-01T00:00:00Z", "2025-12-01T00:00:00Z"),
		exemptionRule("CVE-active", testStart, testEndOfYear),
		exemptionRule("CVE-expiring", testStart, "2025-06-10T00:00:00Z"),
		exemptionRule("CVE-expired", testStart, "2025-02-01T00:00:00Z"),
		{Vulnerability: testLegacyVuln},
	}

	summaries := SummarizeExemptions(rules, mustTime(t, "2025-06-01T00:00:00Z"), 14)
	require.Len(t, summaries, 5)

	assert.Equal(t, ExemptionPending, summaries[0].State)
	assert.Equal(t, ExemptionActive, summaries[1].State)
	assert.Equal(t, ExemptionExpiring, summaries[2].State)
	assert.Equal(t, 9, summaries[2].DaysUntilExpiry)
	assert.Equal(t, ExemptionExpired, summaries[3].State)
	assert.Equal(t, ExemptionLegacy, summaries[4].State)
}

func TestSummarizeExemptions_WarningDaysConfigurable(t *testing.T) {
	rules := []IgnoreRule{exemptionRule(testAnyVuln, testStart, "2025-06-10T00:00:00Z")}
	now := mustTime(t, "2025-06-01T00:00:00Z")

	assert.Equal(t, ExemptionActive, SummarizeExemptions(rules, now, 5)[0].State, "5-day warning must not flag a 9-day-out exemption")
	assert.Equal(t, ExemptionExpiring, SummarizeExemptions(rules, now, 14)[0].State)
	assert.Equal(t, ExemptionActive, SummarizeExemptions(rules, now, 0)[0].State, "zero disables the warning")
}

func TestValidateIgnoreRulesConfig_StructuralErrorsRefuseConfiguration(t *testing.T) {
	tests := []struct {
		name string
		rule IgnoreRule
	}{
		{name: "invalid date", rule: IgnoreRule{Vulnerability: testAnyVuln, EffectiveFrom: "2025-13-01", ExpiresOn: testEndOfYear, Owner: "o", Reason: "r", AssessmentID: "a"}},
		{name: "inverted window", rule: IgnoreRule{Vulnerability: testAnyVuln, EffectiveFrom: testEndOfYear, ExpiresOn: testStart, Owner: "o", Reason: "r", AssessmentID: "a"}},
		{name: "missing expires-on", rule: IgnoreRule{Vulnerability: testAnyVuln, EffectiveFrom: testStart, Owner: "o", Reason: "r", AssessmentID: "a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateIgnoreRulesConfig([]IgnoreRule{tt.rule})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "ignore[0]")
		})
	}
}

func TestValidateIgnoreRulesConfig_ReportsEntryMissingOwner(t *testing.T) {
	rule := IgnoreRule{
		Vulnerability: testAnyVuln,
		EffectiveFrom: testStart,
		ExpiresOn:     testEndOfYear,
		Reason:        "r",
		AssessmentID:  "a",
	}
	issues, err := ValidateIgnoreRulesConfig([]IgnoreRule{rule})
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, 0, issues[0].Position, "the issue must point at the rule's position")
	assert.Contains(t, issues[0].Err.Error(), "missing owner")
	assert.False(t, rule.ActiveAt(time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)), "a rule missing its owner must never suppress")
}

func TestValidateIgnoreRulesConfig_AcceptsLegacyAndValidRules(t *testing.T) {
	legacy := IgnoreRule{Vulnerability: testLegacyVuln}
	valid := exemptionRule("CVE-valid", testStart, testEndOfYear)

	issues, err := ValidateIgnoreRulesConfig([]IgnoreRule{legacy, valid})
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestMigrateIgnoreRules_ListsLegacyWithoutChangingBehavior(t *testing.T) {
	legacy := IgnoreRule{Vulnerability: testLegacyVuln, Reason: "old"}
	valid := exemptionRule("CVE-valid", testStart, testEndOfYear)

	rules, pending, errs := MigrateIgnoreRules([]IgnoreRule{legacy, valid})
	assert.Empty(t, errs)
	assert.Equal(t, []int{0}, pending, "the legacy rule must be listed for migration")
	assert.Equal(t, []IgnoreRule{legacy, valid}, rules, "migration must not rewrite rules it cannot bound")

	// the legacy rule keeps its previous suppression behavior
	assert.Len(t, legacy.IgnoreMatchAt(exemptionMatch(testLegacyVuln, "pkg"), time.Now()), 1)
}

func TestMigrateIgnoreRules_FailureKeepsOriginalRules(t *testing.T) {
	input := []IgnoreRule{
		{Vulnerability: testLegacyVuln},
		{Vulnerability: "CVE-missing-end", EffectiveFrom: testStart, Owner: "o", Reason: "r", AssessmentID: "a"},
		{Vulnerability: "CVE-inverted", EffectiveFrom: testEnd, ExpiresOn: testStart, Owner: "o", Reason: "r", AssessmentID: "a"},
	}

	rules, pending, errs := MigrateIgnoreRules(input)
	assert.Nil(t, pending, "no partial migration list may be produced on failure")
	require.Len(t, errs, 2)
	assert.Equal(t, input, rules, "on failure the original rule list must be returned unchanged")
}

func TestClockIsInjectable(t *testing.T) {
	// Clock is the only source of time for ApplyIgnoreRules, proved by moving the
	// fixed clock across the boundary of a single rule
	rule := exemptionRule("CVE-2025-9", testStart, testEnd)
	matches := NewMatches(exemptionMatch("CVE-2025-9", "pkg"))

	active := fixedClock{now: mustTime(t, "2025-06-01T00:00:00Z")}
	expired := fixedClock{now: mustTime(t, "2025-07-01T00:00:00Z")}

	remaining, _ := ApplyIgnoreRulesAt(matches, []IgnoreRule{rule}, active.Now())
	assert.Equal(t, 0, remaining.Count())
	remaining, _ = ApplyIgnoreRulesAt(matches, []IgnoreRule{rule}, expired.Now())
	assert.Equal(t, 1, remaining.Count())
}

func TestFreeTextNeverParticipatesInMatching(t *testing.T) {
	m := exemptionMatch(testVulnID, "pkg")

	// owner, reason, and assessment-id must not affect whether a rule matches;
	// identical criteria with wildly different attribution match identically
	a := exemptionRule(testVulnID, testStart, testEndOfYear)
	b := a
	b.Owner = "another owner"
	b.Reason = "a completely different sentence"
	b.AssessmentID = "ASMT-999999"

	now := mustTime(t, "2025-06-01T00:00:00Z")
	assert.Equal(t, len(a.IgnoreMatchAt(m, now)), len(b.IgnoreMatchAt(m, now)))

	// and a free-text value that looks like a criterion is not treated as one
	c := IgnoreRule{
		Vulnerability: testVulnID,
		EffectiveFrom: testStart,
		ExpiresOn:     testEndOfYear,
		Owner:         "CVE-9999-9999",
		Reason:        "pkg",
		AssessmentID:  "nvd:cpe",
	}
	other := exemptionMatch(testVulnID, "some-other-package")
	assert.Len(t, c.IgnoreMatchAt(other, now), 1, "free text must not narrow the match either")
}
