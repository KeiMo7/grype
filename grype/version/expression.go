package version

import (
	"fmt"
	"strings"
)

// Expression is a parsed, reusable version constraint expression. It is
// immutable after construction and safe for concurrent evaluation.
//
// Expression exists for callers that need the parsed value itself (rather than
// the higher-level Constraint abstraction), for example when several affected
// ranges must be evaluated and displayed without re-parsing their text.
type Expression struct {
	raw    string
	format Format
	parsed simpleRangeExpression
}

// ParseExpression parses a version constraint expression using the given
// version format for leaf comparisons.
func ParseExpression(raw string, format Format) (*Expression, error) {
	parsed, err := parseRangeExpression(raw)
	if err != nil {
		return nil, err
	}
	return &Expression{raw: raw, format: format, parsed: parsed}, nil
}

// Satisfied evaluates the expression against an installed version, honoring any
// comparison configuration embedded in the version.
func (e *Expression) Satisfied(v *Version) (bool, error) {
	if e == nil {
		return false, fmt.Errorf("cannot evaluate a nil expression")
	}
	if v == nil {
		return false, ErrNoVersionProvided
	}
	if e.parsed.root == nil {
		// an empty expression is always satisfied, matching the historical
		// empty-constraint behavior
		return true, nil
	}
	cfg := v.Config
	return e.parsed.satisfiedWithConfig(e.format, v, cfg)
}

// Value returns the original expression text.
func (e *Expression) Value() string {
	if e == nil {
		return ""
	}
	return e.raw
}

// String returns the expression text with its version format, matching the
// historical Constraint string form.
func (e *Expression) String() string {
	if e == nil {
		return ""
	}
	if e.raw == "" {
		return "none (" + strings.ToLower(e.format.String()) + ")"
	}
	return fmt.Sprintf("%s (%s)", e.raw, strings.ToLower(e.format.String()))
}

// Format returns the version format used for leaf comparisons.
func (e *Expression) Format() Format {
	if e == nil {
		return UnknownFormat
	}
	return e.format
}

// Equal reports whether two expressions have the same text, format and parsed
// structure. It keeps the value comparable despite its internal tree.
func (e *Expression) Equal(other *Expression) bool {
	if e == nil || other == nil {
		return e == other
	}
	return e.raw == other.raw && e.format == other.format && e.parsed.Equal(other.parsed)
}

// IsEmpty reports whether the expression carries no constraint terms. An empty
// expression is always satisfied, matching the historical empty-constraint
// behavior.
func (e *Expression) IsEmpty() bool {
	return e == nil || e.parsed.root == nil
}
