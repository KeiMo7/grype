// Package ledger implements a persistent vulnerability ledger: a record of every
// finding Grype has produced across scan batches, its first and most recent batch,
// and what happened to it (still open, fixed, assessed not-affected, or ignored).
//
// The ledger is opt-in (see the --ledger CLI flag). It observes the verdicts the
// existing matcher and ignore/VEX machinery already produced; it does not change any
// of those verdicts, the report, or the process exit code.
package ledger

import (
	"fmt"
	"sort"
	"strings"
)

// Schema is the schema identifier written as the first line of a ledger file. A
// file written with a different schema is rejected rather than read as if it were
// this one (see IncompatibleError).
const Schema = "grype-ledger/v1"

const schemaPrefix = "grype-ledger/"

// SupportedSchemaVersion is the ledger record layout this build reads and writes.
const SupportedSchemaVersion = 1

// FileVersion is the on-disk envelope version, independent of Schema.
const FileVersion = 1

// State is the lifecycle state of a ledger entry.
type State string

const (
	// StateUnfixed means the finding is on the ledger as still open. It may or may
	// not have a fix available; the point is that it is still being reported.
	StateUnfixed State = "unfixed"
	// StateFixed means the finding is no longer reported for this image, or was
	// assessed as fixed (a VEX "fixed" statement). It is an account that was
	// closed, not one that never existed.
	StateFixed State = "fixed"
	// StateNotAffected means the finding was assessed as not affecting this
	// package (a VEX not_affected statement, a distro not-vulnerable record, or an
	// unaffected-package entry). It stays on the ledger under this state rather
	// than disappearing.
	StateNotAffected State = "not-affected"
	// StateIgnored means an explicit ignore rule suppressed the finding.
	StateIgnored State = "ignored"
)

// AllStates returns every state, in display order.
func AllStates() []State {
	return []State{StateUnfixed, StateFixed, StateNotAffected, StateIgnored}
}

// ParseState parses a state name (case-insensitive, hyphens or underscores).
func ParseState(s string) (State, bool) {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
	for _, state := range AllStates() {
		if string(state) == normalized {
			return state, true
		}
	}
	return "", false
}

// statePriority decides which state wins when several records describe the same
// ledger entry in one batch. An open finding outranks every assessment; a "fixed"
// assessment outranks "not affected", which outranks a plain ignore.
func statePriority(s State) int {
	switch s {
	case StateUnfixed:
		return 4
	case StateFixed:
		return 3
	case StateNotAffected:
		return 2
	case StateIgnored:
		return 1
	default:
		return 0
	}
}

// TransitionAllowed reports whether moving from one state to another is allowed.
//
// The allowed paths are:
//
//	unfixed      -> fixed, ignored, not-affected
//	fixed        -> unfixed (a recurrence)
//	ignored      -> fixed (no longer reported), unfixed (expired or removed ignore)
//	not-affected -> fixed (no longer reported), unfixed
//
// Staying in the same state is always allowed. In particular fixed -> not-affected
// is forbidden: a closed account cannot be rewritten as one that never applied.
func TransitionAllowed(from, to State) bool {
	if from == "" || from == to {
		return true
	}
	switch from {
	case StateUnfixed:
		return to == StateFixed || to == StateIgnored || to == StateNotAffected
	case StateFixed:
		return to == StateUnfixed
	case StateIgnored:
		return to == StateFixed || to == StateUnfixed
	case StateNotAffected:
		return to == StateFixed || to == StateUnfixed
	default:
		return false
	}
}

// DatabaseIdentity describes the vulnerability database used for a batch. It is
// recorded on batches (never in entry identity), so a database change can be
// annotated separately from newly disclosed vulnerabilities.
type DatabaseIdentity struct {
	SchemaVersion string `json:"schemaVersion,omitempty"`
	// Built is the database build time, RFC3339 in UTC.
	Built string `json:"built,omitempty"`
}

func (d DatabaseIdentity) IsZero() bool {
	return d.SchemaVersion == "" && d.Built == ""
}

func (d DatabaseIdentity) Equal(other DatabaseIdentity) bool {
	return d.SchemaVersion == other.SchemaVersion && d.Built == other.Built
}

// PackageIdentity identifies the package a finding is on. Version is recorded for
// context but is deliberately not part of the ledger entry identity: a finding
// fixed by upgrading the package must keep its identity so it can move to the fixed
// state, and a finding that returns after a downgrade must be recognizable as a
// recurrence rather than a new entry.
type PackageIdentity struct {
	Name    string `json:"name"`
	Type    string `json:"type,omitempty"`
	Version string `json:"version,omitempty"`
}

// Recurrence records one return of a previously fixed finding.
type Recurrence struct {
	Batch string `json:"batch"`
	At    string `json:"at"`
	// Cause is RecurrenceCauseReappeared for a genuine return, or
	// RecurrenceCauseDatabaseChange when the vulnerability database changed since
	// the previous batch and may simply be classifying the finding differently.
	Cause string `json:"cause"`
}

const (
	RecurrenceCauseReappeared     = "reappeared"
	RecurrenceCauseDatabaseChange = "database-change"

	FirstSeenCauseInitial        = "initial"
	FirstSeenCauseDatabaseChange = "database-change"

	IssuePermanentIgnoreNoReason = "permanent-ignore-without-reason"
	IssueInvalidIgnoreExpiry     = "invalid-ignore-expiry"
	IssueIgnoreExpired           = "ignore-expired"

	RejectionReasonDisallowedState = "state transition is not allowed"
)

// IgnoreRuleInfo is the ledger's record of an applied ignore rule, kept so that a
// long-lived ignore always has its reason and expiry available for audit.
type IgnoreRuleInfo struct {
	Vulnerability    string `json:"vulnerability,omitempty"`
	Namespace        string `json:"namespace,omitempty"`
	Reason           string `json:"reason,omitempty"`
	FixState         string `json:"fix-state,omitempty"`
	PackageName      string `json:"package-name,omitempty"`
	PackageVersion   string `json:"package-version,omitempty"`
	PackageType      string `json:"package-type,omitempty"`
	VexStatus        string `json:"vex-status,omitempty"`
	VexJustification string `json:"vex-justification,omitempty"`
	Expires          string `json:"expires,omitempty"`
}

// IgnoreInfo is the last ignore assessment recorded on an entry.
type IgnoreInfo struct {
	Rules []IgnoreRuleInfo `json:"rules"`
	// Expired is true when every applicable ignore rule had an expiry that had
	// passed at the time of the batch, so the ledger returned the finding to the
	// unfixed state. The report itself is unaffected.
	Expired bool `json:"expired,omitempty"`
}

// Entry is one vulnerability account: a vulnerability on one package in one image.
type Entry struct {
	ID              string          `json:"id"`
	VulnerabilityID string          `json:"vulnerabilityId"`
	Aliases         []string        `json:"aliases,omitempty"`
	Namespaces      []string        `json:"namespaces,omitempty"`
	Package         PackageIdentity `json:"package"`
	Image           string          `json:"image"`

	State State `json:"state"`

	// FirstSeenBatch is the batch in which the account was opened.
	FirstSeenBatch string `json:"firstSeenBatch"`
	// LastSeenBatch is the most recent batch in which the finding was still
	// observed (open, ignored or assessed not-affected). It is not advanced when
	// the finding stops being observed; that is what FixedAtBatch records.
	LastSeenBatch string `json:"lastSeenBatch"`
	// FirstSeenCause is "initial", or "database-change" when the account opened in
	// a batch whose database differed from the previous batch. The latter must be
	// reported separately, not as a newly disclosed vulnerability.
	FirstSeenCause string `json:"firstSeenCause,omitempty"`

	Recurrences []Recurrence `json:"recurrences,omitempty"`

	// FixedAtBatch is the most recent batch in which the entry became fixed.
	FixedAtBatch string `json:"fixedAtBatch,omitempty"`

	Ignore *IgnoreInfo `json:"ignore,omitempty"`
	// Database is the database used when the entry was last observed.
	Database DatabaseIdentity `json:"database,omitempty"`
}

// RecurrenceCount is the number of times the finding returned after being fixed.
func (e Entry) RecurrenceCount() int { return len(e.Recurrences) }

// Batch is one scan batch: a group of images scanned together against one database.
type Batch struct {
	Sequence   int              `json:"sequence"`
	ID         string           `json:"id"`
	RecordedAt string           `json:"recordedAt"`
	Images     []string         `json:"images"`
	Database   DatabaseIdentity `json:"database,omitempty"`
	// DatabaseChanged is true when this batch's database differs from the previous
	// batch's database.
	DatabaseChanged bool   `json:"databaseChanged,omitempty"`
	PreviousBatch   string `json:"previousBatch,omitempty"`
}

// Rejection records a state transition that was refused because it is not on the
// allowed path set. The entry keeps its previous state; the attempt stays visible.
type Rejection struct {
	EntryID         string          `json:"entryId"`
	Batch           string          `json:"batch"`
	VulnerabilityID string          `json:"vulnerabilityId"`
	Package         PackageIdentity `json:"package"`
	Image           string          `json:"image"`
	From            State           `json:"from"`
	To              State           `json:"to"`
	Reason          string          `json:"reason"`
}

// Issue is a non-fatal ledger observation, recorded rather than silently dropped.
type Issue struct {
	EntryID string `json:"entryId,omitempty"`
	Batch   string `json:"batch"`
	Kind    string `json:"kind"`
	Detail  string `json:"detail,omitempty"`
}

// Ledger is the materialized contents of a ledger file.
type Ledger struct {
	Path       string      `json:"-"`
	Created    bool        `json:"-"`
	Batches    []Batch     `json:"batches,omitempty"`
	Entries    []Entry     `json:"entries"`
	Rejections []Rejection `json:"rejections,omitempty"`
	Issues     []Issue     `json:"issues,omitempty"`
}

// EntryByID returns the entry with the given id, or nil.
func (l *Ledger) EntryByID(id string) *Entry {
	for i := range l.Entries {
		if l.Entries[i].ID == id {
			return &l.Entries[i]
		}
	}
	return nil
}

// BatchByID returns the batch with the given id, or nil.
func (l *Ledger) BatchByID(id string) *Batch {
	for i := range l.Batches {
		if l.Batches[i].ID == id {
			return &l.Batches[i]
		}
	}
	return nil
}

// CountByState returns the number of entries in each state.
func (l *Ledger) CountByState() map[State]int {
	counts := make(map[State]int, len(AllStates()))
	for _, state := range AllStates() {
		counts[state] = 0
	}
	for _, entry := range l.Entries {
		counts[entry.State]++
	}
	return counts
}

// Summary describes the effect of recording one image into a batch.
type Summary struct {
	LedgerPath string
	Batch      string
	Image      string
	// Created is true when the ledger file did not exist and was created.
	Created bool
	// DatabaseChanged is true when this batch's database differs from the previous.
	DatabaseChanged bool

	// NewEntries counts genuinely new accounts (firstSeenCause=initial).
	NewEntries int
	// NewFromDatabaseChange counts accounts that first appeared in a batch whose
	// database changed. They are reported separately so a database refresh does not
	// inflate the new-finding count.
	NewFromDatabaseChange int
	Recurrences           int
	Fixed                 int
	RejectedTransitions   int
	Issues                int

	Counts map[State]int
}

// String renders a one-line, human-readable summary suitable for stderr.
func (s Summary) String() string {
	status := "updated"
	if s.Created {
		status = "new ledger created"
	}
	dbChange := ""
	if s.DatabaseChanged {
		dbChange = ", database changed"
	}
	total := 0
	for _, count := range s.Counts {
		total += count
	}
	return fmt.Sprintf(
		"ledger %s: %s; batch %q image %q%s; entries %d (unfixed %d, fixed %d, not-affected %d, ignored %d), new %d, new-from-database-change %d, recurrences %d, fixed %d",
		s.LedgerPath, status, s.Batch, s.Image, dbChange,
		total,
		s.Counts[StateUnfixed], s.Counts[StateFixed], s.Counts[StateNotAffected], s.Counts[StateIgnored],
		s.NewEntries, s.NewFromDatabaseChange, s.Recurrences, s.Fixed,
	)
}

func sortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
}

func sortBatches(batches []Batch) {
	sort.Slice(batches, func(i, j int) bool {
		if batches[i].Sequence != batches[j].Sequence {
			return batches[i].Sequence < batches[j].Sequence
		}
		return batches[i].ID < batches[j].ID
	})
}

func sortRejections(rejections []Rejection) {
	sort.Slice(rejections, func(i, j int) bool {
		a, b := rejections[i], rejections[j]
		if a.Batch != b.Batch {
			return a.Batch < b.Batch
		}
		if a.EntryID != b.EntryID {
			return a.EntryID < b.EntryID
		}
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
}

func sortIssues(issues []Issue) {
	sort.Slice(issues, func(i, j int) bool {
		a, b := issues[i], issues[j]
		if a.Batch != b.Batch {
			return a.Batch < b.Batch
		}
		if a.EntryID != b.EntryID {
			return a.EntryID < b.EntryID
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Detail < b.Detail
	})
}
