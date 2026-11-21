package ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// header is the first line of every ledger file.
type header struct {
	Schema      string `json:"schema"`
	FileVersion int    `json:"fileVersion"`
	// CreatedAt is informational and never feeds entry identity.
	CreatedAt string `json:"createdAt,omitempty"`
}

// Record types for the lines after the header.
const (
	recordBatch     = "batch"
	recordEntry     = "entry"
	recordRejection = "rejection"
	recordIssue     = "issue"
)

// record is one line of a ledger file after the header.
type record struct {
	Type      string     `json:"type"`
	Sequence  int        `json:"sequence,omitempty"` // batches only
	Batch     *Batch     `json:"batch,omitempty"`
	Entry     *Entry     `json:"entry,omitempty"`
	Rejection *Rejection `json:"rejection,omitempty"`
	Issue     *Issue     `json:"issue,omitempty"`
}

// CorruptError reports a ledger file that cannot be read in full. It names the line
// and, where possible, the record that could not be decoded. Callers must refuse to
// append to a ledger that produced this error: a partial read would compute a
// half-ledger.
type CorruptError struct {
	Path string
	Line int
	// Record is a best-effort identification of the unreadable record.
	Record string
	Err    error
}

func (e *CorruptError) Error() string {
	where := fmt.Sprintf("%s line %d", e.Path, e.Line)
	if e.Record != "" {
		where += fmt.Sprintf(" (%s)", e.Record)
	}
	return fmt.Sprintf("ledger file is corrupt or truncated at %s: %v", where, e.Err)
}

func (e *CorruptError) Unwrap() error { return e.Err }

// IncompatibleError reports an existing ledger written with a different, unsupported
// schema. It is returned instead of silently reading the file as if it were the
// current schema (which would yield empty values).
type IncompatibleError struct {
	Path      string
	Found     string
	Supported string
}

func (e *IncompatibleError) Error() string {
	remedy := "run a grype that understands this ledger, or move the file aside and start a new ledger with --ledger"
	return fmt.Sprintf("ledger file %s was written by an incompatible version (%s; this build supports %s); %s",
		e.Path, e.Found, e.Supported, remedy)
}

// ReadFile reads and validates a ledger file. It returns:
//
//   - (nil, nil) when the file does not exist (a new ledger);
//   - an *IncompatibleError when the schema is not supported;
//   - a *CorruptError when any line cannot be decoded or the file is truncated.
//
// A successfully returned ledger is complete: every record in the file was decoded.
func ReadFile(path string) (*Ledger, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("unable to read ledger file %s: %w", path, err)
	}
	ledger, err := decode(path, data)
	if err != nil {
		return nil, err
	}
	ledger.Path = path
	return ledger, nil
}

func decode(path string, data []byte) (*Ledger, error) {
	ledger := &Ledger{Entries: []Entry{}}

	if len(data) == 0 {
		return nil, &CorruptError{Path: path, Line: 1, Record: "header", Err: errors.New("file is empty")}
	}
	// Every record, including the header, is written with a trailing newline. A file
	// that does not end with one was truncated mid-record.
	if !bytes.HasSuffix(data, []byte("\n")) {
		return nil, &CorruptError{
			Path:   path,
			Line:   bytes.Count(data, []byte("\n")) + 1,
			Record: "partial record",
			Err:    errors.New("file does not end with a complete record (possibly truncated)"),
		}
	}

	lines := bytes.Split(data[:len(data)-1], []byte("\n"))
	sawHeader := false

	for i, raw := range lines {
		lineNo := i + 1
		line := bytes.TrimSpace(raw)
		if len(line) == 0 {
			continue
		}

		if !sawHeader {
			h, err := decodeHeader(line)
			if err != nil {
				return nil, &CorruptError{Path: path, Line: lineNo, Record: "header", Err: err}
			}
			if h.Schema != Schema {
				return nil, &IncompatibleError{Path: path, Found: h.Schema, Supported: Schema}
			}
			if h.FileVersion != FileVersion {
				return nil, &IncompatibleError{
					Path:      path,
					Found:     fmt.Sprintf("%s fileVersion %d", h.Schema, h.FileVersion),
					Supported: fmt.Sprintf("%s fileVersion %d", Schema, FileVersion),
				}
			}
			sawHeader = true
			continue
		}

		var rec record
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, &CorruptError{Path: path, Line: lineNo, Record: sniffRecord(line), Err: err}
		}
		switch rec.Type {
		case recordBatch:
			if rec.Batch == nil {
				return nil, &CorruptError{Path: path, Line: lineNo, Record: "batch", Err: errors.New("missing batch payload")}
			}
			ledger.Batches = append(ledger.Batches, *rec.Batch)
		case recordEntry:
			if rec.Entry == nil {
				return nil, &CorruptError{Path: path, Line: lineNo, Record: "entry", Err: errors.New("missing entry payload")}
			}
			ledger.Entries = append(ledger.Entries, *rec.Entry)
		case recordRejection:
			if rec.Rejection == nil {
				return nil, &CorruptError{Path: path, Line: lineNo, Record: "rejection", Err: errors.New("missing rejection payload")}
			}
			ledger.Rejections = append(ledger.Rejections, *rec.Rejection)
		case recordIssue:
			if rec.Issue == nil {
				return nil, &CorruptError{Path: path, Line: lineNo, Record: "issue", Err: errors.New("missing issue payload")}
			}
			ledger.Issues = append(ledger.Issues, *rec.Issue)
		default:
			return nil, &CorruptError{
				Path:   path,
				Line:   lineNo,
				Record: "unknown",
				Err:    fmt.Errorf("unknown record type %q", rec.Type),
			}
		}
	}
	if !sawHeader {
		return nil, &CorruptError{Path: path, Line: 1, Record: "header", Err: errors.New("file does not start with a header")}
	}

	sortBatches(ledger.Batches)
	sortEntries(ledger.Entries)
	sortRejections(ledger.Rejections)
	sortIssues(ledger.Issues)
	return ledger, nil
}

func decodeHeader(line []byte) (header, error) {
	var h header
	if err := json.Unmarshal(line, &h); err != nil {
		return h, err
	}
	if h.Schema == "" {
		return h, errors.New(`missing "schema" field`)
	}
	if !strings.HasPrefix(h.Schema, schemaPrefix) {
		return h, fmt.Errorf("unrecognized schema %q", h.Schema)
	}
	return h, nil
}

// sniffRecord makes a best-effort attempt to name an unreadable record so the error
// can say which one could not be read.
func sniffRecord(line []byte) string {
	var partial struct {
		Type  string `json:"type"`
		Entry *struct {
			ID              string `json:"id"`
			VulnerabilityID string `json:"vulnerabilityId"`
		} `json:"entry"`
		Batch *struct {
			ID string `json:"id"`
		} `json:"batch"`
	}
	if err := json.Unmarshal(line, &partial); err != nil {
		return ""
	}
	switch partial.Type {
	case recordEntry:
		if partial.Entry != nil && partial.Entry.VulnerabilityID != "" {
			return fmt.Sprintf("entry %s/%s", partial.Entry.VulnerabilityID, partial.Entry.ID)
		}
	case recordBatch:
		if partial.Batch != nil && partial.Batch.ID != "" {
			return fmt.Sprintf("batch %s", partial.Batch.ID)
		}
	}
	return partial.Type
}

// encode renders the ledger deterministically. Entries, batches, rejections and
// issues are sorted, so two ledgers holding the same records are byte-identical
// regardless of the order the records were recorded in.
func encode(l *Ledger, createdAt string) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)

	if err := encoder.Encode(header{Schema: Schema, FileVersion: FileVersion, CreatedAt: createdAt}); err != nil {
		return nil, err
	}

	sortBatches(l.Batches)
	for _, batch := range l.Batches {
		batch := batch
		if err := encoder.Encode(record{Type: recordBatch, Sequence: batch.Sequence, Batch: &batch}); err != nil {
			return nil, err
		}
	}

	sortEntries(l.Entries)
	for _, entry := range l.Entries {
		entry := entry
		if err := encoder.Encode(record{Type: recordEntry, Entry: &entry}); err != nil {
			return nil, err
		}
	}

	sortRejections(l.Rejections)
	for _, rejection := range l.Rejections {
		rejection := rejection
		if err := encoder.Encode(record{Type: recordRejection, Rejection: &rejection}); err != nil {
			return nil, err
		}
	}

	sortIssues(l.Issues)
	for _, issue := range l.Issues {
		issue := issue
		if err := encoder.Encode(record{Type: recordIssue, Issue: &issue}); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// writeFileAtomic writes data to a temporary file beside path and renames it into
// place, so a reader never observes a partially written ledger.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".grype-ledger-*")
	if err != nil {
		return fmt.Errorf("unable to create temporary ledger file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("unable to write temporary ledger file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("unable to sync temporary ledger file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("unable to close temporary ledger file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("unable to replace ledger file: %w", err)
	}
	return nil
}

func formatTime(t time.Time) string {
	// The zero time would otherwise be rendered as "0001-01-01T00:00:00Z"; treat it
	// as unset so the field is omitted.
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
