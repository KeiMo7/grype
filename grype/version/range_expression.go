package version

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"text/scanner"
)

// simpleRangeExpression is a parsed version constraint expression.
//
// The historical flat "comma AND, double-pipe OR" syntax is still represented
// by Units. Expressions that use grouping or exclusion additionally carry an
// immutable expression tree in root, which is what evaluation always uses.
type simpleRangeExpression struct {
	// Units is the legacy OR-of-AND-groups representation. It is only
	// populated for expressions that use the historical flat syntax; it is nil
	// for expressions with grouping or exclusion.
	Units [][]rangeUnit

	root   *expressionNode
	simple bool
}

func parseRangeExpression(phrase string) (simpleRangeExpression, error) {
	root, simple, err := parseConstraintExpression(phrase)
	if err != nil {
		return simpleRangeExpression{}, fmt.Errorf("unable to create constraint expression from=%q : %w", phrase, err)
	}

	expr := simpleRangeExpression{
		root:   root,
		simple: simple,
	}
	if simple {
		expr.Units = legacyUnits(root)
	}
	return expr, nil
}

// legacyUnits converts a flat expression tree back into the historical
// OR-of-AND-groups representation.
func legacyUnits(root *expressionNode) [][]rangeUnit {
	if root == nil {
		return nil
	}

	var groups []expressionNode
	if root.kind == nodeOr {
		groups = root.children
	} else {
		groups = []expressionNode{*root}
	}

	units := make([][]rangeUnit, 0, len(groups))
	for i := range groups {
		group := &groups[i]
		var groupUnits []rangeUnit
		if group.kind == nodeAnd {
			for _, child := range group.children {
				if child.kind == nodeLeaf {
					groupUnits = append(groupUnits, child.unit)
				}
			}
		} else if group.kind == nodeLeaf {
			groupUnits = append(groupUnits, group.unit)
		}
		units = append(units, groupUnits)
	}
	return units
}

func (c *simpleRangeExpression) satisfied(format Format, version *Version) (bool, error) {
	// Use the version's embedded config if present, otherwise use empty config
	cfg := ComparisonConfig{}
	if version != nil {
		cfg = version.Config
	}
	return c.satisfiedWithConfig(format, version, cfg)
}

// Equal reports whether two parsed expressions are equivalent. It exists so
// the expression value stays comparable (e.g. via go-cmp) despite the parsed
// tree being an internal, unexported structure.
func (c simpleRangeExpression) Equal(other simpleRangeExpression) bool {
	left, right := c.leaves(), other.leaves()
	if (c.root == nil) != (other.root == nil) {
		return false
	}
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return structuralEqual(c.root, other.root)
}

func structuralEqual(a, b *expressionNode) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.kind != b.kind || a.unit != b.unit || len(a.children) != len(b.children) {
		return false
	}
	for i := range a.children {
		if !structuralEqual(&a.children[i], &b.children[i]) {
			return false
		}
	}
	return true
}

func (c *simpleRangeExpression) satisfiedWithConfig(format Format, version *Version, cfg ComparisonConfig) (bool, error) {
	if c.root == nil || version == nil {
		return false, nil
	}

	return c.root.satisfied(evaluationContext{
		format:  format,
		version: version,
		cfg:     cfg,
	})
}

// leaves returns every leaf term in the expression, in left-to-right order.
func (c *simpleRangeExpression) leaves() []rangeUnit {
	if c.root == nil {
		return nil
	}
	return c.root.leaves()
}

// evaluationContext carries everything a leaf needs to be evaluated. Each leaf
// uses the comparison configuration supplied by the caller, so a missing-epoch
// strategy applies at every depth of the expression rather than only at the
// outermost level.
type evaluationContext struct {
	format  Format
	version *Version
	cfg     ComparisonConfig
}

func (n *expressionNode) satisfied(ctx evaluationContext) (bool, error) {
	switch n.kind {
	case nodeLeaf:
		return n.satisfiedLeaf(ctx)
	case nodeAnd:
		allSatisfied := true
		for i := range n.children {
			ok, err := n.children[i].satisfied(ctx)
			if err != nil {
				return false, err
			}
			if !ok {
				allSatisfied = false
			}
		}
		return allSatisfied, nil
	case nodeOr:
		oneSatisfied := false
		for i := range n.children {
			ok, err := n.children[i].satisfied(ctx)
			if err != nil {
				return false, err
			}
			if ok {
				oneSatisfied = true
			}
		}
		return oneSatisfied, nil
	case nodeNot:
		ok, err := n.children[0].satisfied(ctx)
		if err != nil {
			return false, err
		}
		return !ok, nil
	default:
		return false, fmt.Errorf("unknown expression node")
	}
}

func (n *expressionNode) satisfiedLeaf(ctx evaluationContext) (bool, error) {
	constraintVersion := &Version{
		Format: ctx.format,
		Raw:    n.unit.Version,
	}

	var result int
	var err error

	// Use config-aware comparison for RPM and Deb formats when config is provided
	if ctx.cfg.MissingEpochStrategy != "" && (ctx.format == RpmFormat || ctx.format == DebFormat) {
		result, err = compareWithConfig(ctx.version, constraintVersion, ctx.cfg)
	} else {
		result, err = ctx.version.Compare(constraintVersion)
	}

	if err != nil {
		// A version format that cannot be compared is a property of this single
		// leaf, not of the whole expression: treat the leaf as unsatisfied and
		// leave an observable diagnostic instead of failing the evaluation.
		// Other comparison errors (for example an unparseable version value) keep
		// propagating so existing behavior is preserved.
		var unsupported *UnsupportedComparisonError
		if errors.As(err, &unsupported) {
			reportDiagnostic(Diagnostic{
				Kind:       UnsupportedComparisonDiagnostic,
				Expression: n.unit.Version,
				Message:    unsupported.Error(),
			})
			return false, nil
		}
		return false, fmt.Errorf("uncomparable %q vs %q: %w", n.unit.Version, ctx.version.String(), err)
	}

	return n.unit.Satisfied(result), nil
}

func (n *expressionNode) leaves() []rangeUnit {
	if n == nil {
		return nil
	}
	if n.kind == nodeLeaf {
		return []rangeUnit{n.unit}
	}
	var out []rangeUnit
	for i := range n.children {
		out = append(out, n.children[i].leaves()...)
	}
	return out
}

// compareWithConfig performs a version comparison using the provided configuration.
// This function extracts the comparator and calls CompareWithConfig if the comparator
// supports it (RPM and Deb versions).
func compareWithConfig(version *Version, constraintVersion *Version, cfg ComparisonConfig) (int, error) {
	comparator, err := version.getComparator(version.Format)
	if err != nil {
		return 0, err
	}

	// Check if the comparator supports config-aware comparison
	switch v := comparator.(type) {
	case rpmVersion:
		return v.CompareWithConfig(constraintVersion, cfg)
	case debVersion:
		return v.CompareWithConfig(constraintVersion, cfg)
	default:
		// Fall back to regular comparison for other formats
		return comparator.Compare(constraintVersion)
	}
}

// scanExpression is the legacy flat tokenizer retained for compatibility with
// callers (and tests) that inspect the pre-grouping representation. New code
// should use parseRangeExpression / parseConstraintExpression.
func scanExpression(phrase string) ([][]string, error) {
	var scnr scanner.Scanner
	var orGroups [][]string // all versions a group of and'd groups or'd together
	var andGroup []string   // most current group of and'd versions
	var buf bytes.Buffer    // most current single version value
	var lastToken string

	captureVersionOperatorPair := func() {
		if buf.Len() > 0 {
			ver := buf.String()
			andGroup = append(andGroup, ver)
			buf.Reset()
		}
	}

	captureAndGroup := func() {
		if len(andGroup) > 0 {
			orGroups = append(orGroups, andGroup)
			andGroup = nil
		}
	}

	scnr.Init(strings.NewReader(phrase))

	scnr.Error = func(*scanner.Scanner, string) {
		// scanner has the ability to invoke a callback upon tokenization errors. By default, if no handler is provided
		// then errors are printed to stdout. This handler is provided to suppress this output.

		// Suppressing these errors is not a problem in this case since the scanExpression function should see all tokens
		// and accumulate them as part of a version value if it is not a token of interest. The text/scanner splits on
		// a pre-configured set of "common" tokens (which we cannot provide). We are only interested in a sub-set of
		// these tokens, thus allow for input that would seemingly be invalid for this common set of tokens.
		// For example, the scanner finding `3.e` would interpret this as a float with no valid exponent. However,
		// this function accumulates all tokens into the version component (and versions are not guaranteed to have
		// valid tokens).
	}

	tokenRune := scnr.Scan()
	for tokenRune != scanner.EOF {
		currentToken := scnr.TokenText()
		switch {
		case currentToken == ",":
			captureVersionOperatorPair()
		case currentToken == "|" && lastToken == "|":
			captureVersionOperatorPair()
			captureAndGroup()
		case currentToken == "(" || currentToken == ")":
			return nil, fmt.Errorf("parenthetical expressions are not supported yet")
		case currentToken != "|":
			buf.Write([]byte(currentToken))
		}
		lastToken = currentToken
		tokenRune = scnr.Scan()
	}
	captureVersionOperatorPair()
	captureAndGroup()

	return orGroups, nil
}
