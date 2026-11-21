package ledger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// Store reads and writes one ledger file, serializing writers with an advisory file
// lock. A Store is safe for concurrent use across goroutines and, because the lock
// is a file lock, across processes: when several images finish in the same batch and
// each records itself, their read-modify-write cycles are serialized rather than
// interleaved.
type Store struct {
	Path string
	// Clock returns the time used for expiry checks and, when a batch has no
	// timestamp, for timestamps. Tests set it to a fixed value.
	Clock func() time.Time
	// Timestamps controls whether wall-clock timestamps are written into the ledger.
	// It is false by default so that recording the same scan twice is byte-identical.
	Timestamps bool
}

// NewStore returns a Store for the given ledger path.
func NewStore(path string) *Store {
	return &Store{Path: path, Clock: time.Now}
}

func (s *Store) clock() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

func (s *Store) recordedAt(now time.Time) string {
	if !s.Timestamps {
		return ""
	}
	return formatTime(now)
}

// lockPath is the sidecar file used for locking. It is separate from the ledger so
// replacing the ledger file (which changes its inode) never drops the lock.
func (s *Store) lockPath() string {
	return s.Path + ".lock"
}

// withLock acquires the ledger lock, reads the current ledger (nil when the file
// does not exist), and writes back whatever fn returns. When fn returns an error, or
// the current ledger cannot be read completely, nothing is written: a corrupt ledger
// is never appended to.
func (s *Store) withLock(ctx context.Context, fn func(current *Ledger, now time.Time) (*Ledger, error)) (*Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o755); err != nil {
		return nil, fmt.Errorf("unable to create ledger directory: %w", err)
	}

	lock := flock.New(s.lockPath())
	// A lock is always available to a local process; the retry loop only bounds how
	// long one writer waits behind another. Bound it explicitly rather than relying
	// on the caller's context, which (for a scan run from the CLI) has no deadline.
	lockCtx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	locked, err := lock.TryLockContext(lockCtx, 10*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoLockAvailable, err)
	}
	if !locked {
		return nil, fmt.Errorf("%w for %s", ErrNoLockAvailable, s.Path)
	}
	defer func() {
		_ = lock.Unlock()
	}()

	current, err := ReadFile(s.Path)
	if err != nil {
		// IncompatibleError and CorruptError both mean "do not touch this file".
		return nil, err
	}

	created := false
	createdAt := ""
	now := s.clock()
	if current == nil {
		created = true
		if s.Timestamps {
			createdAt = formatTime(now)
		}
		current = &Ledger{Path: s.Path, Created: true, Entries: []Entry{}}
	}

	next, err := fn(current, now)
	if err != nil {
		return nil, err
	}
	if next == nil {
		return current, nil
	}
	next.Path = s.Path
	next.Created = created

	data, err := encode(next, createdAt)
	if err != nil {
		return nil, fmt.Errorf("unable to encode ledger: %w", err)
	}
	if err := writeFileAtomic(s.Path, data); err != nil {
		return nil, err
	}

	return next, nil
}

// Record writes one image's results into the ledger as part of batchID. It is the
// single write entry point; all state transitions, recurrences and rejections are
// resolved here, under the lock.
func (s *Store) Record(ctx context.Context, batchID string, image string, db DatabaseIdentity, observed []Observation) (Summary, error) {
	summary := Summary{
		LedgerPath: s.Path,
		Batch:      batchID,
		Image:      image,
	}

	result, err := s.withLock(ctx, func(current *Ledger, now time.Time) (*Ledger, error) {
		return applyBatch(current, batchID, s.recordedAt(now), image, db, observed, &summary, now), nil
	})
	if err != nil {
		return summary, err
	}
	summary.Created = result.Created
	summary.Counts = result.CountByState()
	return summary, nil
}

// LoadQuery loads the ledger for read-only display. It does not lock, because a
// reader only ever sees complete files: writes replace the file atomically.
func LoadQuery(path string) (*Ledger, error) {
	l, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	if l == nil {
		return nil, &NotFoundError{Path: path}
	}
	return l, nil
}

// NotFoundError reports a query against a ledger that does not exist yet.
type NotFoundError struct {
	Path string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("ledger file %s does not exist yet; run a scan with --ledger to create it", e.Path)
}

// ErrNoLockAvailable is returned when a lock could not be acquired before the
// deadline. It signals that the caller should retry or fail; it never means that a
// partial write happened.
var ErrNoLockAvailable = errors.New("no ledger lock available")

// lockTimeout bounds how long a writer waits for the ledger lock.
const lockTimeout = 2 * time.Minute
