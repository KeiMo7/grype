package version

import (
	"errors"
	"fmt"
)

// ErrUnsupportedVersion is returned when a version string cannot be parsed because the value is known
// to cause issues or is otherwise problematic (e.g. golang "devel" version).
var ErrUnsupportedVersion = fmt.Errorf("unsupported version value")

// ErrNoVersionProvided is returned when a version is attempted to be compared, but no other version is provided to compare against.
var ErrNoVersionProvided = errors.New("no version provided for comparison")

// SyntaxError describes a malformed version constraint expression. It records
// where in the input the problem occurred so callers can surface an actionable
// message without leaking internal parser details.
type SyntaxError struct {
	// Expression is the original constraint expression.
	Expression string
	// Position is the zero-based byte offset of the problem in Expression.
	Position int
	// Fragment is a bounded slice of Expression around Position.
	Fragment string
	// Reason is a human-readable description of the problem.
	Reason string
}

func newSyntaxError(expression string, position int, reason string) *SyntaxError {
	if position < 0 {
		position = 0
	}
	if position > len(expression) {
		position = len(expression)
	}
	return &SyntaxError{
		Expression: expression,
		Position:   position,
		Fragment:   expressionFragment(expression, position),
		Reason:     reason,
	}
}

// expressionFragment returns a bounded window of the expression centered on
// position, with ellipses when the window does not cover the whole expression.
func expressionFragment(expression string, position int) string {
	const window = 24

	start := position - window
	if start < 0 {
		start = 0
	}
	end := position + window
	if end > len(expression) {
		end = len(expression)
	}

	fragment := expression[start:end]
	if start > 0 {
		fragment = "..." + fragment
	}
	if end < len(expression) {
		fragment += "..."
	}
	return fragment
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("invalid version constraint expression at position %d near %q: %s", e.Position, e.Fragment, e.Reason)
}

// Is reports whether target describes the same syntax problem, so callers can
// compare syntax errors by value with errors.Is even when they are wrapped.
func (e *SyntaxError) Is(target error) bool {
	var t *SyntaxError
	if !errors.As(target, &t) {
		return false
	}
	return e.Position == t.Position && e.Expression == t.Expression && e.Reason == t.Reason
}

// UnsupportedComparisonError represents an error when a format doesn't match the expected format
type UnsupportedComparisonError struct {
	Left  Format
	Right *Version
}

// newUnsupportedFormatError creates a new UnsupportedComparisonError
func newUnsupportedFormatError(left Format, right *Version) *UnsupportedComparisonError {
	return &UnsupportedComparisonError{
		Left:  left,
		Right: right,
	}
}

func (e *UnsupportedComparisonError) Error() string {
	return fmt.Sprintf("(%s) unsupported version comparison: value=%q format=%q", e.Left, e.Right.Raw, e.Right.Format)
}

func (e *UnsupportedComparisonError) Is(target error) bool {
	var t *UnsupportedComparisonError
	ok := errors.As(target, &t)
	if !ok {
		return false
	}
	return (t.Left == UnknownFormat || t.Left == e.Left) &&
		(t.Right.Format == UnknownFormat || t.Right == e.Right)
}

func invalidFormatError(format Format, raw string, err error) error {
	return fmt.Errorf("invalid %s version from '%s': %w", format.String(), raw, err)
}

// NonFatalConstraintError should be used any time an unexpected but recoverable condition is encountered while
// checking version constraint satisfaction. The error should get returned by any implementer of the Constraint
// interface. If returned by the Satisfied method on the Constraint interface, this error will be caught and
// logged as a warning in the FindMatchesByPackageDistro function in grype/matcher/common/distro_matchers.go
type NonFatalConstraintError struct {
	constraint Constraint
	version    *Version
	message    string
}

func (e NonFatalConstraintError) Error() string {
	return fmt.Sprintf("matching raw constraint %s against version %s caused a non-fatal error: %s", e.constraint, e.version, e.message)
}
