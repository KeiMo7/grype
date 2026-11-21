package ledger

import (
	"fmt"
	"sort"
	"strings"
)

// QueryKind selects which ledger view to render.
type QueryKind string

const (
	// QueryByVulnerability answers: which packages and images has this vulnerability
	// been recorded against, and in what state?
	QueryByVulnerability QueryKind = "vulnerability"
	// QueryByPackage answers: which vulnerabilities has this package carried, and
	// what happened to them?
	QueryByPackage QueryKind = "package"
	// QueryByImage answers: which findings are currently open on this image?
	QueryByImage QueryKind = "image"
)

// ParseQueryKind parses a query kind name.
func ParseQueryKind(value string) (QueryKind, bool) {
	switch QueryKind(strings.ToLower(strings.TrimSpace(value))) {
	case QueryByVulnerability:
		return QueryByVulnerability, true
	case QueryByPackage:
		return QueryByPackage, true
	case QueryByImage:
		return QueryByImage, true
	default:
		return "", false
	}
}

// Query is a read-only request against a ledger.
type Query struct {
	Kind QueryKind
	// Value is a vulnerability ID, package name, or image reference, depending on
	// Kind.
	Value string
	// States optionally restricts results to the given states. When empty all states
	// are included.
	States []State
}

// QueryResult is the rendered outcome of a Query.
type QueryResult struct {
	Kind    QueryKind
	Value   string
	Entries []Entry
	// StateCounts describes each state over the entries that matched the query's
	// non-state filters, before the optional state filter was applied. This is what
	// lets a caller say "ignored 2, not-affected 1" without adding those to the
	// unfixed count.
	StateCounts map[State]int
	// BatchSequences maps a batch ID to its ordinal, so displays can show "seq 3"
	// rather than an opaque hash.
	BatchSequences map[string]int
}

// RunQuery applies q to the ledger. When the query kind is by-image, the value may
// be an image reference or any substring of one that occurs only once in the ledger
// (for example the tag or digest of a referenced image); the single match is used.
func RunQuery(l *Ledger, q Query) QueryResult {
	result := QueryResult{Kind: q.Kind, Value: q.Value, StateCounts: map[State]int{}, BatchSequences: map[string]int{}}
	for _, batch := range l.Batches {
		result.BatchSequences[batch.ID] = batch.Sequence
	}

	value := q.Value
	candidates := l.entriesForImage(value)
	if q.Kind == QueryByImage && len(candidates) == 0 {
		if resolved, ok := l.resolveImage(value); ok {
			value = resolved
			result.Value = resolved
			candidates = l.entriesForImage(value)
		}
	}

	switch q.Kind {
	case QueryByVulnerability:
		candidates = l.entriesForVulnerability(q.Value)
	case QueryByPackage:
		candidates = l.entriesForPackage(q.Value)
	}

	for _, entry := range candidates {
		result.StateCounts[entry.State]++
		if !stateAllowed(entry.State, q.States) {
			continue
		}
		result.Entries = append(result.Entries, entry)
	}

	sort.Slice(result.Entries, func(i, j int) bool {
		a, b := result.Entries[i], result.Entries[j]
		if a.VulnerabilityID != b.VulnerabilityID {
			return a.VulnerabilityID < b.VulnerabilityID
		}
		if a.Image != b.Image {
			return a.Image < b.Image
		}
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		return a.ID < b.ID
	})
	return result
}

func stateAllowed(state State, states []State) bool {
	if len(states) == 0 {
		return true
	}
	for _, allowed := range states {
		if allowed == state {
			return true
		}
	}
	return false
}

func (l *Ledger) entriesForVulnerability(value string) []Entry {
	value = strings.TrimSpace(value)
	var out []Entry
	for _, entry := range l.Entries {
		if strings.EqualFold(entry.VulnerabilityID, value) {
			out = append(out, entry)
			continue
		}
		for _, alias := range entry.Aliases {
			if strings.EqualFold(alias, value) {
				out = append(out, entry)
				break
			}
		}
	}
	return out
}

func (l *Ledger) entriesForPackage(value string) []Entry {
	value = strings.TrimSpace(value)
	var out []Entry
	for _, entry := range l.Entries {
		if strings.EqualFold(entry.Package.Name, value) {
			out = append(out, entry)
		}
	}
	return out
}

func (l *Ledger) entriesForImage(value string) []Entry {
	value = strings.TrimSpace(value)
	var out []Entry
	for _, entry := range l.Entries {
		if entry.Image == value {
			out = append(out, entry)
		}
	}
	return out
}

// resolveImage resolves a query value that is not an exact image reference to the
// single image it identifies, by case-insensitive substring match. It returns false
// when zero or more than one image matches, so ambiguity is never guessed at.
func (l *Ledger) resolveImage(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "", false
	}
	matched := ""
	for _, entry := range l.Entries {
		if !strings.Contains(strings.ToLower(entry.Image), value) {
			continue
		}
		if matched != "" && matched != entry.Image {
			return "", false
		}
		matched = entry.Image
	}
	return matched, matched != ""
}

// String renders a query result as an aligned text table.
func (r QueryResult) String() string {
	var b strings.Builder

	switch r.Kind {
	case QueryByVulnerability:
		fmt.Fprintf(&b, "vulnerability %s\n", r.Value)
	case QueryByPackage:
		fmt.Fprintf(&b, "package %s\n", r.Value)
	case QueryByImage:
		fmt.Fprintf(&b, "image %s\n", r.Value)
	}
	fmt.Fprintf(&b, "states: unfixed %d, fixed %d, not-affected %d, ignored %d\n",
		r.StateCounts[StateUnfixed], r.StateCounts[StateFixed],
		r.StateCounts[StateNotAffected], r.StateCounts[StateIgnored])

	if len(r.Entries) == 0 {
		b.WriteString("no matching entries\n")
		return b.String()
	}

	rows := make([][]string, 0, len(r.Entries))
	for _, entry := range r.Entries {
		rows = append(rows, []string{
			entry.VulnerabilityID,
			entry.State.String(),
			entry.Package.Name,
			entry.Package.Version,
			entry.Package.Type,
			entry.Image,
			r.batchLabel(entry.FirstSeenBatch),
			r.batchLabel(entry.LastSeenBatch),
			fmt.Sprintf("%d", entry.RecurrenceCount()),
		})
	}
	writeTable(&b, []string{"VULNERABILITY", "STATE", "PACKAGE", "VERSION", "TYPE", "IMAGE", "FIRST SEEN", "LAST SEEN", "RECURRENCES"}, rows)
	return b.String()
}

// batchLabel renders a batch ID as "seq N (short-id)" when the sequence is known.
func (r QueryResult) batchLabel(batchID string) string {
	if batchID == "" {
		return ""
	}
	if sequence, ok := r.BatchSequences[batchID]; ok {
		return fmt.Sprintf("seq %d (%s)", sequence, shortID(batchID))
	}
	return shortID(batchID)
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func writeTable(b *strings.Builder, header []string, rows [][]string) {
	widths := make([]int, len(header))
	for i, h := range header {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	writeRow := func(row []string) {
		for i, cell := range row {
			if i > 0 {
				b.WriteString("  ")
			}
			b.WriteString(cell)
			if i < len(row)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-len(cell)))
			}
		}
		b.WriteString("\n")
	}
	writeRow(header)
	separator := make([]string, len(header))
	for i := range separator {
		separator[i] = strings.Repeat("-", widths[i])
	}
	writeRow(separator)
	for _, row := range rows {
		writeRow(row)
	}
}

// String returns the state name.
func (s State) String() string { return string(s) }
