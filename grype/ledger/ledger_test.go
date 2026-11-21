package ledger

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func testDB(built string) DatabaseIdentity {
	return DatabaseIdentity{SchemaVersion: "v6.0.0", Built: built}
}

func obs(vuln, pkgName string, state State, opts ...func(*Observation)) Observation {
	o := Observation{
		Identity: Identity{
			VulnerabilityID: vuln,
			PackageName:     pkgName,
			PackageType:     string(syftPkg.DebPkg),
			Image:           "example:1.0",
		},
		PackageVersion: "1.0.0",
		Aliases:        []string{vuln},
		Namespaces:     []string{"debian:distro:debian:12"},
		State:          state,
		Database:       testDB("2026-01-01T00:00:00Z"),
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store := NewStore(filepath.Join(t.TempDir(), "ledger.jsonl"))
	store.Clock = func() time.Time { return time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC) }
	store.Timestamps = false
	return store
}

func recordBatchOf(t *testing.T, store *Store, batch string, observations ...Observation) Summary {
	t.Helper()
	summary, err := store.Record(context.Background(), batch, "example:1.0", testDB("2026-01-01T00:00:00Z"), observations)
	require.NoError(t, err)
	return summary
}

// TestFourStatesEachQueryable covers the requirement that each of the four states
// has a case, and that entries absent from the report are classified into a
// specific state rather than lumped together as "not reported".
func TestFourStatesEachQueryable(t *testing.T) {
	store := newTestStore(t)

	// Batch 1: everything is open.
	recordBatchOf(t, store,
		BatchID([]string{"b1"}),
		obs("CVE-2026-0001", "openssl", StateUnfixed),
		obs("CVE-2026-0002", "openssl", StateUnfixed),
		obs("CVE-2026-0003", "openssl", StateUnfixed),
		obs("CVE-2026-0004", "openssl", StateUnfixed),
	)

	// Batch 2:
	//  - 0001 is still reported (unfixed)
	//  - 0002 disappears from the report (fixed)
	//  - 0003 is reported by VEX as not affected
	//  - 0004 is explicitly ignored
	recordBatchOf(t, store,
		BatchID([]string{"b2"}),
		obs("CVE-2026-0001", "openssl", StateUnfixed),
		Observation{
			Identity: Identity{VulnerabilityID: "CVE-2026-0003", PackageName: "openssl", PackageType: string(syftPkg.DebPkg), Image: "example:1.0"},
			State:    StateNotAffected,
			Ignore: &IgnoreInfo{Rules: []IgnoreRuleInfo{{
				Vulnerability:    "CVE-2026-0003",
				Namespace:        "vex",
				VexStatus:        "not_affected",
				VexJustification: "vulnerable_code_not_present",
			}}},
			Aliases: []string{"CVE-2026-0003"},
		},
		Observation{
			Identity: Identity{VulnerabilityID: "CVE-2026-0004", PackageName: "openssl", PackageType: string(syftPkg.DebPkg), Image: "example:1.0"},
			State:    StateIgnored,
			Ignore:   &IgnoreInfo{Rules: []IgnoreRuleInfo{{Vulnerability: "CVE-2026-0004", Reason: "risk accepted"}}},
			Aliases:  []string{"CVE-2026-0004"},
		},
	)

	l, err := ReadFile(store.Path)
	require.NoError(t, err)

	want := map[string]State{
		"CVE-2026-0001": StateUnfixed,
		"CVE-2026-0002": StateFixed,
		"CVE-2026-0003": StateNotAffected,
		"CVE-2026-0004": StateIgnored,
	}
	for vuln, state := range want {
		entries := l.entriesForVulnerability(vuln)
		require.Len(t, entries, 1, "vulnerability %s", vuln)
		assert.Equal(t, state, entries[0].State, "vulnerability %s", vuln)
	}

	// Each state is individually queryable.
	for _, state := range AllStates() {
		result := RunQuery(l, Query{Kind: QueryByImage, Value: "example:1.0", States: []State{state}})
		require.Len(t, result.Entries, 1, "state %s should have exactly one entry", state)
		assert.Equal(t, state, result.Entries[0].State)
	}

	// The counts distinguish the four cases.
	counts := l.CountByState()
	assert.Equal(t, 1, counts[StateUnfixed])
	assert.Equal(t, 1, counts[StateFixed])
	assert.Equal(t, 1, counts[StateNotAffected])
	assert.Equal(t, 1, counts[StateIgnored])
}

// TestRecurrenceIsSameEntryWithIncrementedCount covers: a finding that is fixed and
// then reported again is the same account, with the recurrence count and time
// recorded, not a brand-new finding.
func TestRecurrenceIsSameEntryWithIncrementedCount(t *testing.T) {
	store := newTestStore(t)
	store.Timestamps = true
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.Clock = func() time.Time { return clock }

	vuln := "CVE-2026-1111"
	batch1 := BatchID([]string{"b1"})
	batch2 := BatchID([]string{"b2"})
	batch3 := BatchID([]string{"b3"})

	recordBatchOf(t, store, batch1, obs(vuln, "zlib", StateUnfixed))

	// Batch 2 does not report it: fixed.
	recordBatchOf(t, store, batch2)

	l, err := ReadFile(store.Path)
	require.NoError(t, err)
	require.Len(t, l.Entries, 1)
	assert.Equal(t, StateFixed, l.Entries[0].State)
	idBefore := l.Entries[0].ID

	// Batch 3 reports it again: recurrence, same entry.
	clock = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	summary := recordBatchOf(t, store, batch3, obs(vuln, "zlib", StateUnfixed))

	l, err = ReadFile(store.Path)
	require.NoError(t, err)
	require.Len(t, l.Entries, 1, "recurrence must not create a second entry")
	entry := l.Entries[0]
	assert.Equal(t, idBefore, entry.ID)
	assert.Equal(t, StateUnfixed, entry.State)
	assert.Equal(t, 1, entry.RecurrenceCount())
	assert.Equal(t, batch3, entry.Recurrences[0].Batch)
	assert.Equal(t, "2026-04-01T00:00:00Z", entry.Recurrences[0].At)
	assert.Equal(t, RecurrenceCauseReappeared, entry.Recurrences[0].Cause)
	assert.Equal(t, 1, summary.Recurrences)
	assert.Equal(t, 0, summary.NewEntries, "a recurrence is not a new entry")

	// A second recurrence increments the count.
	clock = time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	recordBatchOf(t, store, BatchID([]string{"b4"}))
	recordBatchOf(t, store, BatchID([]string{"b5"}), obs(vuln, "zlib", StateUnfixed))

	l, err = ReadFile(store.Path)
	require.NoError(t, err)
	require.Len(t, l.Entries, 1)
	assert.Equal(t, 2, l.Entries[0].RecurrenceCount())
}

// TestIdentityStableAcrossRerunsAndOrder covers: the same scan run twice, with the
// output order shuffled, produces a byte-identical ledger.
func TestIdentityStableAcrossRerunsAndOrder(t *testing.T) {
	dir := t.TempDir()

	first := filepath.Join(dir, "first.jsonl")
	second := filepath.Join(dir, "second.jsonl")

	batch := BatchID([]string{"same-batch"})
	observations := []Observation{
		obs("CVE-2026-2001", "alpha", StateUnfixed),
		obs("CVE-2026-2002", "beta", StateFixed, func(o *Observation) {
			o.Aliases = []string{"CVE-2026-2002", "GHSA-aaaa-bbbb-cccc"}
		}),
		obs("CVE-2026-2003", "gamma", StateIgnored, func(o *Observation) {
			o.Ignore = &IgnoreInfo{Rules: []IgnoreRuleInfo{{Vulnerability: "CVE-2026-2003", Reason: "accepted"}}}
		}),
		obs("CVE-2026-2004", "delta", StateNotAffected),
	}

	storeA := NewStore(first)
	storeA.Clock = func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) }
	_, err := storeA.Record(context.Background(), batch, "example:1.0", testDB("2026-01-01T00:00:00Z"), observations)
	require.NoError(t, err)

	// Same records, reversed order, different store instance, same batch identity.
	shuffled := make([]Observation, len(observations))
	for i := range observations {
		shuffled[i] = observations[len(observations)-1-i]
	}
	storeB := NewStore(second)
	storeB.Clock = func() time.Time { return time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC) }
	_, err = storeB.Record(context.Background(), batch, "example:1.0", testDB("2026-01-01T00:00:00Z"), shuffled)
	require.NoError(t, err)

	a, err := os.ReadFile(first)
	require.NoError(t, err)
	b, err := os.ReadFile(second)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(a, b), "ledgers should be byte-identical:\n--- first ---\n%s\n--- second ---\n%s", a, b)

	// Re-running the same scan into the same ledger must not change a byte either.
	before, err := os.ReadFile(first)
	require.NoError(t, err)
	_, err = storeA.Record(context.Background(), batch, "example:1.0", testDB("2026-01-01T00:00:00Z"), shuffled)
	require.NoError(t, err)
	after, err := os.ReadFile(first)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(before, after), "re-recording the same scan should be a no-op\nbefore:\n%s\nafter:\n%s", before, after)
}

// TestDatabaseChangeDoesNotCountAsNew covers: when the vulnerability database
// changes, findings that were already on the ledger are not counted as new, and
// accounts that first appear in a changed-database batch are annotated as such.
func TestDatabaseChangeDoesNotCountAsNew(t *testing.T) {
	store := newTestStore(t)
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store.Clock = func() time.Time { return clock }

	oldDB := testDB("2026-01-01T00:00:00Z")
	newDB := testDB("2026-02-01T00:00:00Z")

	// Batch 1 against the old database.
	summary, err := store.Record(context.Background(), BatchID([]string{"b1"}), "example:1.0", oldDB, []Observation{
		obs("CVE-2026-3001", "alpha", StateUnfixed),
	})
	require.NoError(t, err)
	require.Equal(t, 1, summary.NewEntries)
	require.False(t, summary.DatabaseChanged)

	// Batch 2 against a new database; the same finding is still present. It must not
	// be counted as new.
	summary, err = store.Record(context.Background(), BatchID([]string{"b2"}), "example:1.0", newDB, []Observation{
		obs("CVE-2026-3001", "alpha", StateUnfixed),
	})
	require.NoError(t, err)
	assert.True(t, summary.DatabaseChanged)
	assert.Equal(t, 0, summary.NewEntries, "an existing finding must not be counted as new after a DB change")
	assert.Equal(t, 0, summary.NewFromDatabaseChange)

	l, err := ReadFile(store.Path)
	require.NoError(t, err)
	require.Len(t, l.Entries, 1)
	assert.Equal(t, FirstSeenCauseInitial, l.Entries[0].FirstSeenCause)
	// The batch carrying the change is annotated.
	batch2 := l.BatchByID(BatchID([]string{"b2"}))
	require.NotNil(t, batch2)
	assert.True(t, batch2.DatabaseChanged)

	// Batch 3 against the same new database: a finding that genuinely first appears
	// here is new, but the older one is still not.
	summary, err = store.Record(context.Background(), BatchID([]string{"b3"}), "example:1.0", newDB, []Observation{
		obs("CVE-2026-3001", "alpha", StateUnfixed),
		obs("CVE-2026-3002", "alpha", StateUnfixed),
	})
	require.NoError(t, err)
	assert.Equal(t, 1, summary.NewEntries)
	assert.Equal(t, 0, summary.NewFromDatabaseChange)
}

// TestFirstAppearanceDuringDatabaseChangeIsAnnotated covers the other half: an
// account that first appears in a changed-database batch is recorded with the
// database-change cause, so it is reported separately rather than as newly disclosed.
func TestFirstAppearanceDuringDatabaseChangeIsAnnotated(t *testing.T) {
	store := newTestStore(t)

	_, err := store.Record(context.Background(), BatchID([]string{"b1"}), "example:1.0", testDB("2026-01-01T00:00:00Z"), []Observation{
		obs("CVE-2026-4001", "alpha", StateUnfixed),
	})
	require.NoError(t, err)

	summary, err := store.Record(context.Background(), BatchID([]string{"b2"}), "example:1.0", testDB("2026-02-01T00:00:00Z"), []Observation{
		obs("CVE-2026-4001", "alpha", StateUnfixed),
		obs("CVE-2026-4002", "alpha", StateUnfixed),
	})
	require.NoError(t, err)
	assert.Equal(t, 0, summary.NewEntries)
	assert.Equal(t, 1, summary.NewFromDatabaseChange)

	l, err := ReadFile(store.Path)
	require.NoError(t, err)
	entries := l.entriesForVulnerability("CVE-2026-4002")
	require.Len(t, entries, 1)
	assert.Equal(t, FirstSeenCauseDatabaseChange, entries[0].FirstSeenCause)
}

// TestDisallowedTransitionIsRejectedAndRecorded covers: fixed -> not-affected is
// refused, the entry keeps its state, and the attempt is recorded.
func TestDisallowedTransitionIsRejectedAndRecorded(t *testing.T) {
	store := newTestStore(t)
	vuln := "CVE-2026-5001"

	recordBatchOf(t, store, BatchID([]string{"b1"}), obs(vuln, "alpha", StateUnfixed))
	// Not observed -> fixed.
	recordBatchOf(t, store, BatchID([]string{"b2"}))
	// Now assessed not-affected: must be rejected.
	summary := recordBatchOf(t, store, BatchID([]string{"b3"}), obs(vuln, "alpha", StateNotAffected))

	l, err := ReadFile(store.Path)
	require.NoError(t, err)
	require.Len(t, l.Entries, 1)
	assert.Equal(t, StateFixed, l.Entries[0].State, "the entry must keep its previous state")
	assert.Equal(t, 1, summary.RejectedTransitions)
	require.Len(t, l.Rejections, 1)
	assert.Equal(t, StateFixed, l.Rejections[0].From)
	assert.Equal(t, StateNotAffected, l.Rejections[0].To)
	assert.Equal(t, vuln, l.Rejections[0].VulnerabilityID)
}

// TestIgnoreExpiryReturnsToUnfixed covers: a temporary ignore expires back to the
// unfixed state, while a permanent ignore keeps its reason for audit.
func TestIgnoreExpiryReturnsToUnfixed(t *testing.T) {
	store := newTestStore(t)
	store.Timestamps = true
	vuln := "CVE-2026-6001"
	other := "CVE-2026-6002"

	ignored := func(v string, rule IgnoreRuleInfo) Observation {
		o := obs(v, "alpha", StateIgnored)
		o.Ignore = &IgnoreInfo{Rules: []IgnoreRuleInfo{rule}}
		return o
	}

	// The ignore is in force as of March 1.
	store.Clock = func() time.Time { return time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC) }
	recordBatchOf(t, store, BatchID([]string{"b1"}),
		ignored(vuln, IgnoreRuleInfo{Vulnerability: vuln, Reason: "temporary", Expires: "2026-03-15"}),
		ignored(other, IgnoreRuleInfo{Vulnerability: other, Reason: "permanent risk acceptance"}),
	)

	l, err := ReadFile(store.Path)
	require.NoError(t, err)
	require.Len(t, l.entriesForVulnerability(vuln), 1)
	assert.Equal(t, StateIgnored, l.entriesForVulnerability(vuln)[0].State)

	// By April 1 the temporary ignore has expired; the permanent one has not.
	store.Clock = func() time.Time { return time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC) }
	summary := recordBatchOf(t, store, BatchID([]string{"b2"}),
		ignored(vuln, IgnoreRuleInfo{Vulnerability: vuln, Reason: "temporary", Expires: "2026-03-15"}),
		ignored(other, IgnoreRuleInfo{Vulnerability: other, Reason: "permanent risk acceptance"}),
	)

	l, err = ReadFile(store.Path)
	require.NoError(t, err)
	expired := l.entriesForVulnerability(vuln)[0]
	assert.Equal(t, StateUnfixed, expired.State, "an expired ignore returns the finding to unfixed")
	require.NotNil(t, expired.Ignore)
	assert.True(t, expired.Ignore.Expired)
	// fixed -> unfixed path must not have fabricated a recurrence here
	assert.Equal(t, 0, expired.RecurrenceCount())

	permanent := l.entriesForVulnerability(other)[0]
	assert.Equal(t, StateIgnored, permanent.State)
	assert.True(t, len(permanent.Ignore.Rules) > 0)
	assert.Equal(t, "permanent risk acceptance", permanent.Ignore.Rules[0].Reason)

	assert.Equal(t, 1, summary.Issues, "the expiry is recorded as an issue")
}

// TestMissingLedgerIsCreatedNotTreatedAsEmptyPrevPeriod covers: a missing ledger file
// is reported as newly created rather than silently treated as an empty previous
// period.
func TestMissingLedgerIsCreatedNotTreatedAsEmptyPrevPeriod(t *testing.T) {
	store := newTestStore(t)
	require.NoFileExists(t, store.Path)

	summary, err := store.Record(context.Background(), BatchID([]string{"b1"}), "example:1.0", DatabaseIdentity{}, []Observation{
		obs("CVE-2026-7001", "alpha", StateUnfixed),
	})
	require.NoError(t, err)
	assert.True(t, summary.Created)
	assert.Contains(t, summary.String(), "new ledger created")
	require.FileExists(t, store.Path)

	// A second record into an existing ledger is not reported as created.
	summary, err = store.Record(context.Background(), BatchID([]string{"b2"}), "example:1.0", DatabaseIdentity{}, []Observation{
		obs("CVE-2026-7001", "alpha", StateUnfixed),
	})
	require.NoError(t, err)
	assert.False(t, summary.Created)
}

// TestCorruptLedgerIsRefused covers: a truncated or corrupt ledger names the bad
// record and refuses to append, so no half-ledger is computed.
func TestCorruptLedgerIsRefused(t *testing.T) {
	store := newTestStore(t)
	recordBatchOf(t, store, BatchID([]string{"b1"}), obs("CVE-2026-8001", "alpha", StateUnfixed))

	valid, err := os.ReadFile(store.Path)
	require.NoError(t, err)

	// Chop off the last few bytes: a truncated final record.
	truncated := valid[:len(valid)-10]
	require.NoError(t, os.WriteFile(store.Path, truncated, 0o644))

	_, err = ReadFile(store.Path)
	var corrupt *CorruptError
	require.ErrorAs(t, err, &corrupt)

	// Append must be refused, and the file must be left untouched.
	_, err = store.Record(context.Background(), BatchID([]string{"b2"}), "example:1.0", DatabaseIdentity{}, []Observation{
		obs("CVE-2026-8002", "alpha", StateUnfixed),
	})
	require.ErrorAs(t, err, &corrupt)

	after, readErr := os.ReadFile(store.Path)
	require.NoError(t, readErr)
	assert.Equal(t, truncated, after, "a corrupt ledger must not be modified")
}

// TestCorruptRecordIsNamed covers: the error identifies which record could not be
// read.
func TestCorruptRecordIsNamed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	content := `{"schema":"grype-ledger/v1","fileVersion":1}
{"type":"entry","entry":{"id":"abc","vulnerabilityId":"CVE-2026-9001","package":{"name":"alpha"},"image":"example:1.0","state":"unfixed","firstSeenBatch":"b1","lastSeenBatch":"b1"}}
{"type":"entry","entry":{"id":"def","vulnerabilityId":"CVE-2026-9002", BROKEN
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	_, err := ReadFile(path)
	var corrupt *CorruptError
	require.ErrorAs(t, err, &corrupt)
	assert.Equal(t, 3, corrupt.Line)
	assert.Contains(t, err.Error(), "line 3")
}

// TestIncompatibleSchemaIsRejected covers: a ledger written by an older/newer schema
// yields an incompatibility explanation, not a silent empty read.
func TestIncompatibleSchemaIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	content := `{"schema":"grype-ledger/v0","fileVersion":1}
{"type":"entry","entry":{"id":"abc"}}
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	l, err := ReadFile(path)
	assert.Nil(t, l)
	var incompatible *IncompatibleError
	require.ErrorAs(t, err, &incompatible)
	assert.Contains(t, err.Error(), "incompatible")
	assert.Contains(t, err.Error(), "move the file aside")

	// And it is not silently overwritten.
	store := NewStore(path)
	_, err = store.Record(context.Background(), "b1", "example:1.0", DatabaseIdentity{}, nil)
	require.ErrorAs(t, err, &incompatible)

	after, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	assert.Equal(t, content, string(after))
}

// TestConcurrentWritersAreSerialized covers: several images finishing in the same
// batch do not corrupt the ledger.
func TestConcurrentWritersAreSerialized(t *testing.T) {
	store := newTestStore(t)
	batch := BatchID([]string{"multi"})
	const images = 8
	const vulnsPerImage = 5

	done := make(chan error, images)
	for i := 0; i < images; i++ {
		go func(i int) {
			var observations []Observation
			for j := 0; j < vulnsPerImage; j++ {
				o := obs("CVE-2026-90"+strconv.Itoa(i)+"-"+strconv.Itoa(j), "pkg-"+strconv.Itoa(i), StateUnfixed)
				o.Identity.Image = "image-" + strconv.Itoa(i)
				observations = append(observations, o)
			}
			_, err := store.Record(context.Background(), batch, "image-"+strconv.Itoa(i), DatabaseIdentity{}, observations)
			done <- err
		}(i)
	}
	for i := 0; i < images; i++ {
		require.NoError(t, <-done)
	}

	l, err := ReadFile(store.Path)
	require.NoError(t, err)
	assert.Len(t, l.Entries, images*vulnsPerImage)
	batchRecord := l.BatchByID(batch)
	require.NotNil(t, batchRecord)
	assert.Len(t, batchRecord.Images, images)
}

// TestQueries covers the three query dimensions.
func TestQueries(t *testing.T) {
	store := newTestStore(t)

	o1 := obs("CVE-2026-A", "openssl", StateUnfixed)
	o1.Identity.Image = "image-a"
	o1.Aliases = []string{"CVE-2026-A", "GHSA-1111-2222-3333"}
	o2 := obs("CVE-2026-B", "openssl", StateFixed)
	o2.Identity.Image = "image-b"
	o3 := obs("CVE-2026-A", "curl", StateIgnored)
	o3.Identity.Image = "image-b"
	o3.Ignore = &IgnoreInfo{Rules: []IgnoreRuleInfo{{Vulnerability: "CVE-2026-A", Reason: "accepted"}}}

	_, err := store.Record(context.Background(), BatchID([]string{"b1"}), "image-a", DatabaseIdentity{}, []Observation{o1})
	require.NoError(t, err)
	_, err = store.Record(context.Background(), BatchID([]string{"b1"}), "image-b", DatabaseIdentity{}, []Observation{o2, o3})
	require.NoError(t, err)

	l, err := ReadFile(store.Path)
	require.NoError(t, err)

	// By vulnerability (and by alias).
	byVuln := RunQuery(l, Query{Kind: QueryByVulnerability, Value: "CVE-2026-A"})
	assert.Len(t, byVuln.Entries, 2)
	byAlias := RunQuery(l, Query{Kind: QueryByVulnerability, Value: "GHSA-1111-2222-3333"})
	assert.Len(t, byAlias.Entries, 1)

	// By package: openssl's history.
	byPackage := RunQuery(l, Query{Kind: QueryByPackage, Value: "openssl"})
	assert.Len(t, byPackage.Entries, 2)
	assert.Equal(t, 1, byPackage.StateCounts[StateUnfixed])
	assert.Equal(t, 1, byPackage.StateCounts[StateFixed])

	// By image, defaulting to currently-open entries in the CLI: query unfixed.
	byImage := RunQuery(l, Query{Kind: QueryByImage, Value: "image-a"})
	assert.Len(t, byImage.Entries, 1)
	assert.Equal(t, "CVE-2026-A", byImage.Entries[0].VulnerabilityID)

	// The ignored entry is not in the unfixed view of image-b.
	open := RunQuery(l, Query{Kind: QueryByImage, Value: "image-b", States: []State{StateUnfixed}})
	assert.Empty(t, open.Entries)
	assert.Equal(t, 1, open.StateCounts[StateIgnored])
}

// TestObserverClassifiesSuppressionsAndVex covers the translation from the existing
// matcher results, ensuring the ledger records what the ignore/VEX machinery
// decided rather than re-deciding it.
func TestObserverClassifiesSuppressionsAndVex(t *testing.T) {
	observer := NewObserver("example:1.0")

	pkgA := pkg.Package{Name: "openssl", Version: "3.0.1", Type: syftPkg.DebPkg}
	matchA := match.Match{
		Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2026-C", Namespace: "debian:distro:debian:12"}},
		Package:       pkgA,
	}
	matchB := match.Match{
		Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2026-D", Namespace: "debian:distro:debian:12"}},
		Package:       pkgA,
	}
	matchE := match.Match{
		Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-2026-E", Namespace: "nvd:cpe"}},
		Package:       pkgA,
	}

	suppressed := []match.IgnoredMatch{
		{Match: matchB, AppliedIgnoreRules: []match.IgnoreRule{{Vulnerability: "CVE-2026-D", Reason: "distro-fixed"}}},
	}
	ignored := []match.IgnoredMatch{
		{Match: matchE, AppliedIgnoreRules: []match.IgnoreRule{{Vulnerability: "CVE-2026-E", VexStatus: "not_affected", VexJustification: "vulnerable_code_not_present"}}},
	}

	observations := observer.Observe([]match.Match{matchA}, ignored, suppressed, testDB("2026-01-01T00:00:00Z"))
	byVuln := map[string]Observation{}
	for _, o := range observations {
		byVuln[o.Identity.VulnerabilityID] = o
	}

	assert.Equal(t, StateUnfixed, byVuln["CVE-2026-C"].State)
	assert.Equal(t, StateFixed, byVuln["CVE-2026-D"].State, "a distro-fixed suppression is an assessment, not an absence")
	assert.Equal(t, StateNotAffected, byVuln["CVE-2026-E"].State)
}

// TestStateTransitions pins the allowed paths.
func TestStateTransitions(t *testing.T) {
	allowed := map[[2]State]bool{
		{StateUnfixed, StateFixed}:       true,
		{StateUnfixed, StateIgnored}:     true,
		{StateUnfixed, StateNotAffected}: true,
		{StateFixed, StateUnfixed}:       true,
		{StateIgnored, StateUnfixed}:     true,
		{StateNotAffected, StateUnfixed}: true,
		{StateNotAffected, StateFixed}:   true,
		{StateFixed, StateFixed}:         true,
		{StateFixed, StateNotAffected}:   false,
		{StateFixed, StateIgnored}:       false,
		{StateIgnored, StateNotAffected}: false,
		{StateNotAffected, StateIgnored}: false,
	}
	for transition, want := range allowed {
		assert.Equal(t, want, TransitionAllowed(transition[0], transition[1]), "%s -> %s", transition[0], transition[1])
	}
}

// TestLedgerIsDeterministicJSON verifies the on-disk contents are valid JSONL with a
// header first, so external tooling can read it.
func TestLedgerIsDeterministicJSON(t *testing.T) {
	store := newTestStore(t)
	recordBatchOf(t, store, BatchID([]string{"b1"}), obs("CVE-2026-F", "alpha", StateUnfixed))

	data, err := os.ReadFile(store.Path)
	require.NoError(t, err)
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	require.GreaterOrEqual(t, len(lines), 2)

	var h header
	require.NoError(t, json.Unmarshal(lines[0], &h))
	assert.Equal(t, Schema, h.Schema)
	assert.Equal(t, FileVersion, h.FileVersion)

	for _, line := range lines[1:] {
		var rec record
		require.NoError(t, json.Unmarshal(line, &rec))
		assert.NotEmpty(t, rec.Type)
	}
}

func TestNotFoundError(t *testing.T) {
	_, err := LoadQuery(filepath.Join(t.TempDir(), "missing.jsonl"))
	var notFound *NotFoundError
	require.ErrorAs(t, err, &notFound)
	assert.False(t, errors.Is(err, os.ErrNotExist))
}

// TestAliasSpellingChangeKeepsOneAccount covers the original complaint: the same
// vulnerability written with a different ID in two rounds (an advisory ID in one
// report, its CVE alias in the next) must remain one account, not appear as a new
// finding plus a fix.
func TestAliasSpellingChangeKeepsOneAccount(t *testing.T) {
	store := newTestStore(t)

	first := obs("GHSA-aaaa-bbbb-cccc", "libfoo", StateUnfixed, func(o *Observation) {
		o.Aliases = []string{"GHSA-aaaa-bbbb-cccc", "CVE-2026-7777"}
	})
	recordBatchOf(t, store, BatchID([]string{"b1"}), first)

	// The next round writes the same finding under its CVE ID instead.
	second := obs("CVE-2026-7777", "libfoo", StateUnfixed, func(o *Observation) {
		o.Aliases = []string{"CVE-2026-7777", "GHSA-aaaa-bbbb-cccc"}
	})
	summary := recordBatchOf(t, store, BatchID([]string{"b2"}), second)

	l, err := ReadFile(store.Path)
	require.NoError(t, err)
	require.Len(t, l.Entries, 1, "the same finding must not become two accounts")
	entry := l.Entries[0]
	assert.Equal(t, "GHSA-aaaa-bbbb-cccc", entry.VulnerabilityID, "the first-seen spelling stays canonical")
	assert.Equal(t, StateUnfixed, entry.State)
	assert.Equal(t, 0, entry.RecurrenceCount())
	assert.Equal(t, 0, summary.NewEntries, "a spelling change is not a new finding")
	assert.Equal(t, 0, summary.Fixed, "a spelling change must not look like a fix")

	// Both spellings find the account.
	assert.Len(t, l.entriesForVulnerability("CVE-2026-7777"), 1)
	assert.Len(t, l.entriesForVulnerability("GHSA-aaaa-bbbb-cccc"), 1)
}

// TestClosureDuringDatabaseChangeIsAnnotated covers: a finding that closes in a
// batch whose database changed is annotated so it is not mistaken for a verified
// fix. The closure is still recorded (the ledger must not invent a fix).
func TestClosureDuringDatabaseChangeIsAnnotated(t *testing.T) {
	store := newTestStore(t)

	oldDB := testDB("2026-01-01T00:00:00Z")
	newDB := testDB("2026-02-01T00:00:00Z")

	_, err := store.Record(context.Background(), BatchID([]string{"b1"}), "example:1.0", oldDB, []Observation{
		obs("CVE-2026-A001", "alpha", StateUnfixed),
	})
	require.NoError(t, err)

	// The new database no longer reports it.
	_, err = store.Record(context.Background(), BatchID([]string{"b2"}), "example:1.0", newDB, nil)
	require.NoError(t, err)

	l, err := ReadFile(store.Path)
	require.NoError(t, err)
	entries := l.entriesForVulnerability("CVE-2026-A001")
	require.Len(t, entries, 1)
	assert.Equal(t, StateFixed, entries[0].State)
	require.NotNil(t, entries[0].FixedAtBatch)
	assert.Equal(t, FirstSeenCauseInitial, entries[0].FirstSeenCause)
	// the batch that carried the database change is annotated
	batch := l.BatchByID(BatchID([]string{"b2"}))
	require.NotNil(t, batch)
	assert.True(t, batch.DatabaseChanged)
}

// TestIgnoredThenGoneBecomesFixed covers: an account that was ignored and then stops
// being reported is closed as fixed, not left stuck in ignored or rejected.
func TestIgnoredThenGoneBecomesFixed(t *testing.T) {
	store := newTestStore(t)
	vuln := "CVE-2026-B001"

	ignored := obs(vuln, "alpha", StateIgnored)
	ignored.Ignore = &IgnoreInfo{Rules: []IgnoreRuleInfo{{Vulnerability: vuln, Reason: "risk accepted"}}}
	recordBatchOf(t, store, BatchID([]string{"b1"}), ignored)

	summary := recordBatchOf(t, store, BatchID([]string{"b2"}))
	assert.Equal(t, 1, summary.Fixed)
	assert.Equal(t, 0, summary.RejectedTransitions)

	l, err := ReadFile(store.Path)
	require.NoError(t, err)
	require.Len(t, l.Entries, 1)
	assert.Equal(t, StateFixed, l.Entries[0].State)
}

// TestExpiredIgnoreOnFirstObservation covers: a finding first seen under an already
// expired ignore is recorded as unfixed, with the expired rule kept for audit.
func TestExpiredIgnoreOnFirstObservation(t *testing.T) {
	store := newTestStore(t)
	store.Clock = func() time.Time { return time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC) }

	o := obs("CVE-2026-E001", "alpha", StateIgnored)
	o.Ignore = &IgnoreInfo{Rules: []IgnoreRuleInfo{{Vulnerability: "CVE-2026-E001", Expires: "2020-01-01"}}}
	recordBatchOf(t, store, BatchID([]string{"b"}), o)

	l, err := ReadFile(store.Path)
	require.NoError(t, err)
	entries := l.entriesForVulnerability("CVE-2026-E001")
	require.Len(t, entries, 1)
	assert.Equal(t, StateUnfixed, entries[0].State)
	require.NotNil(t, entries[0].Ignore)
	assert.True(t, entries[0].Ignore.Expired)
	require.Len(t, l.Issues, 1)
	assert.Equal(t, IssueIgnoreExpired, l.Issues[0].Kind)
}
