package version

import (
	"sync"
	"sync/atomic"

	"github.com/anchore/grype/internal/log"
)

// DiagnosticKind classifies an observable event encountered while parsing or
// evaluating a version constraint expression.
type DiagnosticKind string

const (
	// ParseErrorDiagnostic is reported when an expression cannot be parsed.
	ParseErrorDiagnostic DiagnosticKind = "parse-error"
	// UnsupportedComparisonDiagnostic is reported when a single leaf term
	// cannot be compared against the installed version. The leaf is treated as
	// unsatisfied and the rest of the expression is still evaluated.
	UnsupportedComparisonDiagnostic DiagnosticKind = "unsupported-comparison"
)

// Diagnostic is an observable event emitted by the version constraint layer.
// It is intentionally limited to the raw expression, a record identifier and a
// human-readable message so internal parser structures never leak into logs.
type Diagnostic struct {
	Kind       DiagnosticKind
	Record     string
	Expression string
	Message    string
}

// DiagnosticCounts is an aggregated, monotonic snapshot of constraint
// diagnostics produced by the process.
type DiagnosticCounts struct {
	ParseErrors            int64
	UnsupportedComparisons int64
}

var (
	diagnosticMu      sync.Mutex
	diagnosticSink    func(Diagnostic)
	diagnosticHistory []Diagnostic

	parseErrorCount         atomic.Int64
	unsupportedCompareCount atomic.Int64
)

const maxDiagnosticHistory = 256

// SetDiagnosticSink installs (or clears, when nil) a callback that receives
// every diagnostic. It returns a function that restores the previous sink,
// which is convenient in tests.
func SetDiagnosticSink(sink func(Diagnostic)) (restore func()) {
	diagnosticMu.Lock()
	previous := diagnosticSink
	diagnosticSink = sink
	diagnosticMu.Unlock()

	return func() {
		diagnosticMu.Lock()
		diagnosticSink = previous
		diagnosticMu.Unlock()
	}
}

// ReportDiagnostic records an observable constraint diagnostic. Callers such
// as the database layer use it to report a record-scoped parse failure without
// exposing internal expression structures.
func ReportDiagnostic(d Diagnostic) {
	switch d.Kind {
	case ParseErrorDiagnostic:
		parseErrorCount.Add(1)
	case UnsupportedComparisonDiagnostic:
		unsupportedCompareCount.Add(1)
	}

	diagnosticMu.Lock()
	if len(diagnosticHistory) >= maxDiagnosticHistory {
		diagnosticHistory = diagnosticHistory[1:]
	}
	diagnosticHistory = append(diagnosticHistory, d)
	sink := diagnosticSink
	diagnosticMu.Unlock()

	fields := []any{"kind", string(d.Kind)}
	if d.Record != "" {
		fields = append(fields, "record", d.Record)
	}
	if d.Expression != "" {
		fields = append(fields, "expression", d.Expression)
	}
	if d.Message != "" {
		fields = append(fields, "message", d.Message)
	}

	switch d.Kind {
	case ParseErrorDiagnostic:
		// Parse failures are actionable; warnings that carry a record identifier
		// let an operator trace the failure back to its source record. Failures
		// without a record are still counted, but logged at debug to avoid
		// noisy warnings from internal call sites.
		if d.Record != "" {
			log.WithFields(fields...).Warn("version constraint could not be parsed")
		} else {
			log.WithFields(fields...).Debug("version constraint could not be parsed")
		}
	default:
		log.WithFields(fields...).Debug("version constraint could not be evaluated")
	}

	if sink != nil {
		sink(d)
	}
}

func reportDiagnostic(d Diagnostic) {
	ReportDiagnostic(d)
}

// DiagnosticCounts returns an aggregated snapshot of diagnostics emitted so
// far. The counters are monotonic for the lifetime of the process.
func DiagnosticCountsSnapshot() DiagnosticCounts {
	return DiagnosticCounts{
		ParseErrors:            parseErrorCount.Load(),
		UnsupportedComparisons: unsupportedCompareCount.Load(),
	}
}

// RecentDiagnostics returns a copy of the most recent diagnostics (bounded to a
// small ring buffer).
func RecentDiagnostics() []Diagnostic {
	diagnosticMu.Lock()
	defer diagnosticMu.Unlock()

	out := make([]Diagnostic, len(diagnosticHistory))
	copy(out, diagnosticHistory)
	return out
}

// ResetDiagnostics clears the aggregated counters and the recent-diagnostic
// buffer. It is intended for tests.
func ResetDiagnostics() {
	parseErrorCount.Store(0)
	unsupportedCompareCount.Store(0)

	diagnosticMu.Lock()
	diagnosticHistory = nil
	diagnosticMu.Unlock()
}
