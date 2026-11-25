package version

import (
	"errors"
	"fmt"
	"strings"

	"github.com/scylladb/go-set/strset"
)

func CombineConstraints(constraints ...Constraint) Constraint {
	constraints = uniqueConstraints(constraints...)

	if len(constraints) == 0 {
		return nil
	}
	if len(constraints) == 1 {
		return constraints[0]
	}

	return combinedConstraint{
		OrOperands: constraints,
	}
}

type combinedConstraint struct {
	OrOperands []Constraint
}

func (c combinedConstraint) String() string {
	return fmt.Sprintf("%s (%s)", c.Value(), strings.ToLower(c.Format().String()))
}

func (c combinedConstraint) Value() string {
	// TODO: there is room for improvement here to make this more readable (filter out redundant constraints... e.g. <1.0 || < 2.0 should just be < 2.0)
	var str string
	for i, op := range c.OrOperands {
		if i > 0 {
			str += " || "
		}
		str += op.Value()
	}
	return str
}

func (c combinedConstraint) Format() Format {
	format := UnknownFormat
	if len(c.OrOperands) > 0 {
		format = c.OrOperands[0].Format()
	}
	return format
}

func (c combinedConstraint) Satisfied(version *Version) (bool, error) {
	if version == nil {
		return false, fmt.Errorf("cannot evaluate combined constraint with nil version")
	}

	for _, op := range c.OrOperands {
		satisfied, err := op.Satisfied(version)
		if err != nil {
			var unsupported *UnsupportedComparisonError
			if errors.As(err, &unsupported) {
				// an unsupported comparison applies to one operand only; it
				// contributes "not satisfied" and is observable rather than
				// failing the whole OR expression.
				reportDiagnostic(Diagnostic{
					Kind:       UnsupportedComparisonDiagnostic,
					Expression: op.Value(),
					Message:    unsupported.Error(),
				})
				continue
			}
			return false, fmt.Errorf("error evaluating constraint %s: %w", op, err)
		}
		if satisfied {
			return true, nil
		}
	}

	return false, nil
}

func uniqueConstraints(constraints ...Constraint) []Constraint {
	var nonNil []Constraint
	seen := strset.New()
	for _, c := range constraints {
		if c == nil || seen.Has(c.Value()) {
			continue
		}
		seen.Add(c.Value())
		nonNil = append(nonNil, c)
	}
	return nonNil
}

// CombineConstraintRecords combines the constraints parsed from the individual
// affected ranges of a single vulnerability record into one OR expression.
//
// Unlike joining the raw constraint strings with "||", this keeps every
// operand's parsed group structure and version format intact down to the leaf
// terms. The textual form joins operands with "||" (no surrounding spaces) so
// that the displayed constraint text matches the historical representation for
// records whose ranges share a format.
func CombineConstraintRecords(constraints ...Constraint) Constraint {
	return CombineConstraintRecordsWithFormat(UnknownFormat, constraints...)
}

// CombineConstraintRecordsWithFormat is like CombineConstraintRecords but
// allows the caller to pin the format reported by the combined constraint.
// Individual operands still evaluate with their own format.
func CombineConstraintRecordsWithFormat(displayFormat Format, constraints ...Constraint) Constraint {
	var operands []Constraint
	for _, c := range constraints {
		if c == nil {
			continue
		}
		operands = append(operands, c)
	}

	switch len(operands) {
	case 0:
		return nil
	case 1:
		return operands[0]
	}

	if displayFormat == UnknownFormat {
		displayFormat = operands[0].Format()
	}

	return constraintRecordGroup{
		operands:      operands,
		displayFormat: displayFormat,
	}
}

// constraintRecordGroup ORs the constraints captured from the individual
// affected ranges of one vulnerability record.
type constraintRecordGroup struct {
	operands      []Constraint
	displayFormat Format
}

func (c constraintRecordGroup) String() string {
	return fmt.Sprintf("%s (%s)", c.Value(), strings.ToLower(c.displayFormat.String()))
}

func (c constraintRecordGroup) Value() string {
	values := make([]string, 0, len(c.operands))
	for _, op := range c.operands {
		values = append(values, op.Value())
	}
	return strings.Join(values, "||")
}

func (c constraintRecordGroup) Format() Format {
	return c.displayFormat
}

// Equal reports whether two record groups have the same operands in the same
// order. It keeps the value comparable (e.g. by go-cmp) despite the operand
// slice being unexported.
func (c constraintRecordGroup) Equal(other constraintRecordGroup) bool {
	if c.displayFormat != other.displayFormat || len(c.operands) != len(other.operands) {
		return false
	}
	for i := range c.operands {
		if c.operands[i].Value() != other.operands[i].Value() ||
			c.operands[i].Format() != other.operands[i].Format() {
			return false
		}
	}
	return true
}

func (c constraintRecordGroup) Satisfied(version *Version) (bool, error) {
	if version == nil {
		return false, fmt.Errorf("cannot evaluate combined constraint with nil version")
	}

	for _, op := range c.operands {
		satisfied, err := op.Satisfied(version)
		if err != nil {
			var unsupported *UnsupportedComparisonError
			if errors.As(err, &unsupported) {
				// one range's format not being comparable must not take down the
				// sibling ranges; it contributes "not satisfied".
				reportDiagnostic(Diagnostic{
					Kind:       UnsupportedComparisonDiagnostic,
					Expression: op.Value(),
					Message:    unsupported.Error(),
				})
				continue
			}
			return false, fmt.Errorf("error evaluating constraint %s: %w", op, err)
		}
		if satisfied {
			return true, nil
		}
	}

	return false, nil
}
