package version

import "fmt"

type Constraint interface {
	fmt.Stringer
	Value() string
	Format() Format
	Satisfied(*Version) (bool, error)
}

func GetConstraint(constStr string, format Format) (Constraint, error) {
	return getConstraint(constStr, format, "")
}

// GetConstraintWithRecord is GetConstraint with an associated record
// identifier (for example a vulnerability ID). Parse failures are reported as
// record-scoped diagnostics so they are countable and attributable instead of
// being silently dropped.
func GetConstraintWithRecord(constStr string, format Format, record string) (Constraint, error) {
	return getConstraint(constStr, format, record)
}

func getConstraint(constStr string, format Format, record string) (Constraint, error) {
	var c Constraint
	var err error

	switch format {
	case ApkFormat:
		c, err = newGenericConstraint(ApkFormat, constStr)
	case SemanticFormat:
		c, err = newGenericConstraint(SemanticFormat, constStr)
	case BitnamiFormat:
		c, err = newGenericConstraint(BitnamiFormat, constStr)
	case GemFormat:
		c, err = newGenericConstraint(GemFormat, constStr)
	case DebFormat:
		c, err = newGenericConstraint(DebFormat, constStr)
	case GolangFormat:
		c, err = newGenericConstraint(GolangFormat, constStr)
	case MavenFormat:
		c, err = newGenericConstraint(MavenFormat, constStr)
	case RpmFormat:
		c, err = newGenericConstraint(RpmFormat, constStr)
	case PythonFormat:
		c, err = newGenericConstraint(PythonFormat, constStr)
	case KBFormat:
		c, err = newKBConstraint(constStr)
	case PortageFormat:
		c, err = newGenericConstraint(PortageFormat, constStr)
	case PacmanFormat:
		c, err = newGenericConstraint(PacmanFormat, constStr)
	case JVMFormat:
		c, err = newGenericConstraint(JVMFormat, constStr)
	case UnknownFormat:
		c, err = newFuzzyConstraint(constStr, "unknown")
	default:
		return nil, fmt.Errorf("could not find constraint for given format: %s", format)
	}

	if err != nil && record != "" {
		// Only record-scoped call sites (the database layer) report parse
		// failures. Generic call sites may parse speculatively (for example the
		// fuzzy constraint fallback), where an error is expected and belongs to
		// normal control flow rather than a diagnostic.
		ReportDiagnostic(Diagnostic{
			Kind:       ParseErrorDiagnostic,
			Record:     record,
			Expression: constStr,
			Message:    err.Error(),
		})
	}

	return c, err
}

// MustGetConstraint is meant for testing only, do not use within the library
func MustGetConstraint(constStr string, format Format) Constraint {
	c, err := GetConstraint(constStr, format)
	if err != nil {
		panic(err)
	}
	return c
}
