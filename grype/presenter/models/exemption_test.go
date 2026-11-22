package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
)

const (
	reportExpires = "2025-06-30T00:00:00Z"
	reportVuln    = "CVE-1"
)

func reportRule(vuln string) match.IgnoreRule {
	return match.IgnoreRule{
		Vulnerability: vuln,
		EffectiveFrom: "2025-01-01T00:00:00Z",
		ExpiresOn:     reportExpires,
		Owner:         "security-team",
		Reason:        "accepted risk",
		AssessmentID:  "ASMT-42",
	}
}

func TestNewExemptionReport_AnswersWhichAndWhen(t *testing.T) {
	rules := []match.IgnoreRule{
		reportRule("CVE-2025-1"),
		{Vulnerability: "CVE-2025-2"},
	}
	now, err := match.ParseExemptionTime("2025-06-20T00:00:00Z")
	require.NoError(t, err)

	report := NewExemptionReport(match.SummarizeExemptions(rules, now, 14))
	require.Len(t, report, 2)

	assert.Equal(t, "expiring", report[0].State)
	assert.Equal(t, "CVE-2025-1", report[0].Vulnerability)
	assert.Equal(t, reportExpires, report[0].ExpiresOn)
	assert.Equal(t, "security-team", report[0].Owner)
	assert.Equal(t, "ASMT-42", report[0].AssessmentID)
	assert.Equal(t, 10, report[0].DaysUntilExpiry)

	// the legacy rule is listed, so pending migration is visible in the report
	assert.Equal(t, "missing-metadata", report[1].State)
	assert.Equal(t, "CVE-2025-2", report[1].Vulnerability)
}

func TestNewExemptionReport_InvalidEntryCarriesReason(t *testing.T) {
	rules := []match.IgnoreRule{{
		Vulnerability: "CVE-2025-3",
		EffectiveFrom: "not-a-date",
		ExpiresOn:     reportExpires,
		Owner:         "o",
		Reason:        "r",
		AssessmentID:  "a",
	}}
	report := NewExemptionReport(match.SummarizeExemptions(rules, time.Now(), 14))
	require.Len(t, report, 1)
	assert.Equal(t, "invalid", report[0].State)
	assert.NotEmpty(t, report[0].Error)
}

func TestDocument_WithExemptionsPreservesShapeWithoutExemptions(t *testing.T) {
	// a scan with no exemptions must not gain an "exemptions" key
	doc := Document{}
	encoded, err := json.Marshal(doc)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "exemptions")

	doc = doc.WithExemptions(nil)
	encoded, err = json.Marshal(doc)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "exemptions")
}

func TestDocument_ExemptionsSerialized(t *testing.T) {
	rules := []match.IgnoreRule{reportRule("CVE-2025-1")}
	now, err := match.ParseExemptionTime("2025-03-01T00:00:00Z")
	require.NoError(t, err)

	doc := Document{}.WithExemptions(match.SummarizeExemptions(rules, now, 14))
	encoded, err := json.Marshal(doc)
	require.NoError(t, err)

	payload := string(encoded)
	for _, expected := range []string{
		`"exemptions":[`,
		`"state":"active"`,
		`"expires-on":"` + reportExpires + `"`,
		`"owner":"security-team"`,
		`"assessment-id":"ASMT-42"`,
	} {
		assert.True(t, strings.Contains(payload, expected), "expected %s in %s", expected, payload)
	}
}

func TestNewAppliedExemption_OnlyForTimeBoundRules(t *testing.T) {
	// a legacy rule must not introduce the exemption field on an ignored match
	assert.Nil(t, newAppliedExemption([]match.IgnoreRule{{Vulnerability: reportVuln, Reason: "old"}}))
	assert.Nil(t, newAppliedExemption(nil))

	got := newAppliedExemption([]match.IgnoreRule{reportRule(reportVuln)})
	require.NotNil(t, got)
	assert.Equal(t, reportExpires, got.ExpiresOn)
	assert.Equal(t, "security-team", got.Owner)
}

func TestExemptionExpiryAnnotation(t *testing.T) {
	assert.Empty(t, ExemptionExpiryAnnotation([]IgnoreRule{{Vulnerability: reportVuln}}))
	assert.Equal(
		t,
		"exempt until 2025-06-30T00:00:00Z (security-team)",
		ExemptionExpiryAnnotation([]IgnoreRule{{Vulnerability: reportVuln, ExpiresOn: reportExpires, Owner: "security-team"}}),
	)
}

func TestNewIgnoreRule_IncludesExemptionFields(t *testing.T) {
	got := newIgnoreRule(reportRule("CVE-2025-1"))
	assert.Equal(t, "2025-01-01T00:00:00Z", got.EffectiveFrom)
	assert.Equal(t, reportExpires, got.ExpiresOn)
	assert.Equal(t, "security-team", got.Owner)
	assert.Equal(t, "ASMT-42", got.AssessmentID)
}
