package version

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConstraintExpression_Grouping verifies parentheses group AND conditions
// and that groups joined by OR behave exactly like expanding each group into
// its own flat expression.
func TestConstraintExpression_Grouping(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		version    string
		satisfied  bool
	}{
		// the canonical shape: (AND) || (AND)
		{
			name:       "first parenthesized group matches",
			constraint: "(>= 1.0, < 2.0) || (>= 3.0, < 4.0)",
			version:    "1.5.0",
			satisfied:  true,
		},
		{
			name:       "second parenthesized group matches",
			constraint: "(>= 1.0, < 2.0) || (>= 3.0, < 4.0)",
			version:    "3.5.0",
			satisfied:  true,
		},
		{
			name:       "neither parenthesized group matches",
			constraint: "(>= 1.0, < 2.0) || (>= 3.0, < 4.0)",
			version:    "2.5.0",
			satisfied:  false,
		},
		// without parentheses the comma binds tighter than OR, so the flat
		// form is equivalent to the explicitly parenthesized form
		{
			name:       "flat form equals explicit grouping - first arm",
			constraint: ">= 1.0, < 2.0 || >= 3.0, < 4.0",
			version:    "1.5.0",
			satisfied:  true,
		},
		{
			name:       "flat form equals explicit grouping - outside arms",
			constraint: ">= 1.0, < 2.0 || >= 3.0, < 4.0",
			version:    "2.5.0",
			satisfied:  false,
		},
		// OR adjacent to comma, as official advisories often write it
		{
			name:       "or adjacent to comma",
			constraint: "(>= 1.0,< 2.0)||(>= 3.0,< 4.0)",
			version:    "3.1.0",
			satisfied:  true,
		},
		{
			name:       "commas directly surrounding the or",
			constraint: ">= 1.0,||,< 2.0",
			version:    "1.5.0",
			satisfied:  true,
		},
		{
			name:       "commas directly surrounding the or - outside both arms",
			constraint: ">= 3.0,||,< 2.0",
			version:    "2.5.0",
			satisfied:  false,
		},
		// a single parenthesized conjunctive group
		{
			name:       "single group matches",
			constraint: "(>= 1.0, < 2.0)",
			version:    "1.9.0",
			satisfied:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint, err := newGenericConstraint(SemanticFormat, tt.constraint)
			require.NoError(t, err)

			got, err := constraint.Satisfied(New(tt.version, SemanticFormat))
			require.NoError(t, err)
			assert.Equal(t, tt.satisfied, got)
		})
	}
}

// TestConstraintExpression_GroupingEquivalentToFlat proves grouping is
// semantically equivalent to evaluating each group independently.
func TestConstraintExpression_GroupingEquivalentToFlat(t *testing.T) {
	groups := []string{">= 1.0, < 2.0", ">= 3.0, < 4.0", "= 5.0", ">= 6.0, !(= 6.5)"}
	grouped := "(" + strings.Join(groups, ") || (") + ")"

	versions := []string{"0.9", "1.0", "1.5", "2.0", "3.5", "4.1", "5.0", "6.0", "6.5", "7.0"}
	for _, v := range versions {
		t.Run("version="+v, func(t *testing.T) {
			groupedConstraint, err := newGenericConstraint(SemanticFormat, grouped)
			require.NoError(t, err)
			groupedResult, err := groupedConstraint.Satisfied(New(v, SemanticFormat))
			require.NoError(t, err)

			var anyGroup bool
			for _, group := range groups {
				c, err := newGenericConstraint(SemanticFormat, group)
				require.NoError(t, err)
				ok, err := c.Satisfied(New(v, SemanticFormat))
				require.NoError(t, err)
				anyGroup = anyGroup || ok
			}

			assert.Equal(t, anyGroup, groupedResult, "grouped expression must equal OR of independently evaluated groups")
		})
	}
}

func TestConstraintExpression_NestedGroups(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		version    string
		satisfied  bool
	}{
		{
			name:       "three levels - inner or matches",
			constraint: "((>= 1.0, < 2.0) || (>= 5.0, > 5.5, < 6.0)), !(= 1.5)",
			version:    "1.2.0",
			satisfied:  true,
		},
		{
			name:       "three levels - excluded leaf inside inner group",
			constraint: "((>= 1.0, < 2.0) || (>= 5.0, > 5.5, < 6.0)), !(= 1.5)",
			version:    "1.5.0",
			satisfied:  false,
		},
		{
			name:       "three levels - second inner arm",
			constraint: "((>= 1.0, < 2.0) || (>= 5.0, > 5.5, < 6.0)), !(= 1.5)",
			version:    "5.7.0",
			satisfied:  true,
		},
		{
			name:       "three levels - outside all inner arms",
			constraint: "((>= 1.0, < 2.0) || (>= 5.0, > 5.5, < 6.0)), !(= 1.5)",
			version:    "7.0.0",
			satisfied:  false,
		},
		{
			name:       "deeply nested three independent levels",
			constraint: "((>= 1.0, < 10.0), ((< 3.0) || (> 7.0))), !(= 10.0)",
			version:    "8.0.0",
			satisfied:  true,
		},
		{
			name:       "deeply nested three independent levels - middle excluded",
			constraint: "((>= 1.0, < 10.0), ((< 3.0) || (> 7.0))), !(= 10.0)",
			version:    "5.0.0",
			satisfied:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint, err := newGenericConstraint(SemanticFormat, tt.constraint)
			require.NoError(t, err)

			got, err := constraint.Satisfied(New(tt.version, SemanticFormat))
			require.NoError(t, err)
			assert.Equal(t, tt.satisfied, got)
		})
	}
}

func TestConstraintExpression_Precedence(t *testing.T) {
	// The unabridged forms and their explicit parenthesization must agree.
	tests := []struct {
		name          string
		flat          string
		parenthesized string
		versions      []string
	}{
		{
			name:          "and binds tighter than or",
			flat:          ">= 1.0, < 2.0 || >= 3.0, < 4.0",
			parenthesized: "(>= 1.0, < 2.0) || (>= 3.0, < 4.0)",
			versions:      []string{"0.9", "1.5", "2.5", "3.5", "4.5"},
		},
		{
			name:          "or adjacent to comma",
			flat:          ">= 1.0,< 2.0||>= 3.0,< 4.0",
			parenthesized: "(>= 1.0,< 2.0)||(>= 3.0,< 4.0)",
			versions:      []string{"1.5", "2.5", "3.5"},
		},
		{
			name:          "division binds tighter than and",
			flat:          "= 1.0 || >= 2.0, < 3.0, !(= 2.5)",
			parenthesized: "(= 1.0) || ((>= 2.0, < 3.0), (!(= 2.5)))",
			versions:      []string{"1.0", "2.5", "2.6", "3.0"},
		},
		{
			name:          "mixed grouping and precedence",
			flat:          ">= 1.0, (< 2.0 || > 4.0), !(= 3.3) || = 9.0",
			parenthesized: "(>= 1.0, (< 2.0 || > 4.0), !(= 3.3)) || (= 9.0)",
			versions:      []string{"1.5", "3.3", "5.0", "9.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flatConstraint, err := newGenericConstraint(SemanticFormat, tt.flat)
			require.NoError(t, err)
			explicitConstraint, err := newGenericConstraint(SemanticFormat, tt.parenthesized)
			require.NoError(t, err)

			for _, v := range tt.versions {
				flatResult, err := flatConstraint.Satisfied(New(v, SemanticFormat))
				require.NoError(t, err)
				explicitResult, err := explicitConstraint.Satisfied(New(v, SemanticFormat))
				require.NoError(t, err)
				assert.Equal(t, explicitResult, flatResult, "version %s: flat form must match explicit grouping", v)
			}
		})
	}
}

func TestConstraintExpression_Exclusion(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		version    string
		satisfied  bool
	}{
		{
			name:       "version inside the carved-out sub-range is not affected",
			constraint: ">= 1.0, < 3.0, !(>= 1.5, < 2.0)",
			version:    "1.7.0",
			satisfied:  false,
		},
		{
			name:       "version before the hole is affected",
			constraint: ">= 1.0, < 3.0, !(>= 1.5, < 2.0)",
			version:    "1.2.0",
			satisfied:  true,
		},
		{
			name:       "version after the hole is affected",
			constraint: ">= 1.0, < 3.0, !(>= 1.5, < 2.0)",
			version:    "2.5.0",
			satisfied:  true,
		},
		{
			name:       "multiple holes carved out",
			constraint: ">= 1.0, < 5.0, !(>= 1.5, < 2.0), !(>= 3.0, <= 3.2)",
			version:    "3.1.0",
			satisfied:  false,
		},
		{
			name:       "outside every hole",
			constraint: ">= 1.0, < 5.0, !(>= 1.5, < 2.0), !(>= 3.0, <= 3.2)",
			version:    "4.0.0",
			satisfied:  true,
		},
		{
			name:       "negated single version",
			constraint: ">= 1.0, < 2.0, != 1.5.0",
			version:    "1.5.0",
			satisfied:  false,
		},
		{
			name:       "hole expressed with a nested grouped exclusion",
			constraint: ">= 1.0, < 4.0, !((>= 1.5, < 1.6) || (= 2.0))",
			version:    "2.0.0",
			satisfied:  false,
		},
		{
			name:       "hole expressed with a nested grouped exclusion - outside",
			constraint: ">= 1.0, < 4.0, !((>= 1.5, < 1.6) || (= 2.0))",
			version:    "3.0.0",
			satisfied:  true,
		},
		{
			name:       "exclusion combined with grouping on either side",
			constraint: "(>= 1.0, < 2.0) || (>= 3.0, < 5.0, !(>= 4.0, < 4.5))",
			version:    "4.2.0",
			satisfied:  false,
		},
		{
			name:       "exclusion inside a group that is or-ed",
			constraint: "(>= 1.0, < 2.0) || (>= 3.0, < 5.0, !(>= 4.0, < 4.5))",
			version:    "1.2.0",
			satisfied:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint, err := newGenericConstraint(SemanticFormat, tt.constraint)
			require.NoError(t, err)

			got, err := constraint.Satisfied(New(tt.version, SemanticFormat))
			require.NoError(t, err)
			assert.Equal(t, tt.satisfied, got)
		})
	}
}

// TestConstraintExpression_FormatDispatch asserts that the same expression and
// version string are judged by each format's own comparison rules. Every format
// has a case paired with a contrast format that judges the very same expression
// and version the other way, proving the dispatch is not flattened.
func TestConstraintExpression_FormatDispatch(t *testing.T) {
	tests := []struct {
		name       string
		format     Format
		constraint string
		version    string
		satisfied  bool
		contrast   Format
		contrastOK bool
	}{
		{
			name:       "semantic orders release candidates before the release",
			format:     SemanticFormat,
			constraint: "(>= 1.0.0)",
			version:    "1.0.0-rc1",
			satisfied:  false,
			contrast:   RpmFormat,
			contrastOK: true,
		},
		{
			name:       "rpm does not special-case rc prereleases",
			format:     RpmFormat,
			constraint: "(>= 1.0.0)",
			version:    "1.0.0-rc1",
			satisfied:  true,
			contrast:   SemanticFormat,
			contrastOK: false,
		},
		{
			name:       "apk treats an r revision as after the base version",
			format:     ApkFormat,
			constraint: "(>= 1.0.0)",
			version:    "1.0.0-r0",
			satisfied:  true,
			contrast:   SemanticFormat,
			contrastOK: false,
		},
		{
			name:       "deb gives the epoch precedence over the upstream version",
			format:     DebFormat,
			constraint: "(> 2.0)",
			version:    "1:0.9",
			satisfied:  true,
			contrast:   RpmFormat,
			contrastOK: false,
		},
		{
			name:       "maven treats SNAPSHOT as before the release",
			format:     MavenFormat,
			constraint: "(>= 1.0)",
			version:    "1.0-SNAPSHOT",
			satisfied:  false,
			contrast:   RpmFormat,
			contrastOK: true,
		},
		{
			name:       "go accepts a v-prefixed version and alpha ordering",
			format:     GolangFormat,
			constraint: "(> 1.0.0-alpha)",
			version:    "v1.0.0",
			satisfied:  true,
			contrast:   RpmFormat,
			contrastOK: false,
		},
		{
			name:       "python pep440 alpha is before the release",
			format:     PythonFormat,
			constraint: "(>= 1.0)",
			version:    "1.0a1",
			satisfied:  false,
			contrast:   RpmFormat,
			contrastOK: true,
		},
		{
			name:       "gem prerelease dot segment is before the release",
			format:     GemFormat,
			constraint: "(< 1.0.0)",
			version:    "1.0.0.pre",
			satisfied:  true,
			contrast:   RpmFormat,
			contrastOK: false,
		},
		{
			name:       "jvm normalizes pre-JEP223 underscore versions",
			format:     JVMFormat,
			constraint: "(= 8.0.456)",
			version:    "1.8.0_456",
			satisfied:  true,
			contrast:   RpmFormat,
			contrastOK: false,
		},
		{
			name:       "bitnami drops revisions",
			format:     BitnamiFormat,
			constraint: "(> 1.0.0)",
			version:    "1.0.0-2",
			satisfied:  false,
			contrast:   DebFormat,
			contrastOK: true,
		},
		{
			name:       "portage orders an alpha suffix before the release",
			format:     PortageFormat,
			constraint: "(>= 1.0)",
			version:    "1.0_alpha1",
			satisfied:  false,
			contrast:   RpmFormat,
			contrastOK: true,
		},
		{
			name:       "pacman orders rc before the release",
			format:     PacmanFormat,
			constraint: "(>= 1.0)",
			version:    "1.0rc1",
			satisfied:  true,
			contrast:   SemanticFormat,
			contrastOK: false,
		},
		{
			name:       "kb uses its equality-only comparator",
			format:     KBFormat,
			constraint: "(> 10)",
			version:    "9",
			satisfied:  true,
			contrast:   SemanticFormat,
			contrastOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateForConstraintTest(t, tt.format, tt.constraint, tt.version)
			assert.Equal(t, tt.satisfied, got)

			contrastGot := evaluateForConstraintTest(t, tt.contrast, tt.constraint, tt.version)
			assert.Equal(t, tt.contrastOK, contrastGot,
				"%s and %s must judge %q against %q differently", tt.format, tt.contrast, tt.constraint, tt.version)
			assert.NotEqual(t, got, contrastGot,
				"%s must not be flattened into the %s comparator", tt.format, tt.contrast)
		})
	}
}

func evaluateForConstraintTest(t *testing.T, format Format, constraint, installed string) bool {
	t.Helper()

	c, err := GetConstraint(constraint, format)
	require.NoError(t, err)
	require.NotNil(t, c)

	got, err := c.Satisfied(New(installed, format))
	require.NoError(t, err)
	return got
}

func TestConstraintExpression_MissingEpochStrategyPerLeaf(t *testing.T) {
	// The installed RPM version has no epoch. The strategy must apply at every
	// leaf, including leaves nested inside groups and under negation.
	tests := []struct {
		name       string
		format     Format
		constraint string
		version    string
		strategy   MissingEpochStrategy
		satisfied  bool
	}{
		{
			name:       "rpm leaf in nested group inherits zero strategy",
			format:     RpmFormat,
			constraint: "((>= 2:0) || (= 99))",
			version:    "3.0",
			strategy:   MissingEpochStrategyZero,
			satisfied:  false,
		},
		{
			name:       "rpm leaf in nested group inherits auto strategy",
			format:     RpmFormat,
			constraint: "((>= 2:0) || (= 99))",
			version:    "3.0",
			strategy:   MissingEpochStrategyAuto,
			satisfied:  true,
		},
		{
			name:       "rpm leaf under negation inherits zero strategy",
			format:     RpmFormat,
			constraint: "!(< 2:0)",
			version:    "3.0",
			strategy:   MissingEpochStrategyZero,
			satisfied:  false,
		},
		{
			name:       "rpm leaf under negation inherits auto strategy",
			format:     RpmFormat,
			constraint: "!(< 2:0)",
			version:    "3.0",
			strategy:   MissingEpochStrategyAuto,
			satisfied:  true,
		},
		{
			name:       "deb leaf in nested group inherits auto strategy",
			format:     DebFormat,
			constraint: "((>= 2:0) || (= 99))",
			version:    "3.0",
			strategy:   MissingEpochStrategyAuto,
			satisfied:  true,
		},
		{
			name:       "deb leaf in nested group without auto strategy",
			format:     DebFormat,
			constraint: "((>= 2:0) || (= 99))",
			version:    "3.0",
			strategy:   MissingEpochStrategyZero,
			satisfied:  false,
		},
		{
			name:       "rpm second leaf in an and group also inherits the strategy",
			format:     RpmFormat,
			constraint: "!(< 1:0), !(< 2:0)",
			version:    "5.0",
			strategy:   MissingEpochStrategyZero,
			satisfied:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint, err := newGenericConstraint(tt.format, tt.constraint)
			require.NoError(t, err)

			version := NewWithConfig(tt.version, tt.format, ComparisonConfig{MissingEpochStrategy: tt.strategy})
			got, err := constraint.Satisfied(version)
			require.NoError(t, err)
			assert.Equal(t, tt.satisfied, got)
		})
	}
}

func TestConstraintExpression_QuotedLiterals(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		version    string
		satisfied  bool
	}{
		{
			name:       "parentheses and pipes inside double quotes are content",
			constraint: `> 1.0, <= "  (2.0||),,, ", || = 3.0`,
			version:    "1.5.0",
			satisfied:  false,
		},
		{
			name:       "commas inside quotes are content",
			constraint: `= "1.0,2.0" || = 3.0`,
			version:    "1.0,2.0",
			satisfied:  true,
		},
		{
			name:       "single quoted literal is preserved verbatim",
			constraint: `'4.5.1' || '4.5.2'`,
			version:    "4.5.2",
			satisfied:  true,
		},
		{
			name:       "unbalanced quote is a syntax error, not a silent version",
			constraint: `= "unterminated`,
			satisfied:  false,
		},
		{
			name:       "quotes can appear inside a paren group",
			constraint: `(>= 1.0, = "1,5") || (= 2.0)`,
			version:    "1,5",
			satisfied:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			constraint, err := newGenericConstraint(UnknownFormat, tt.constraint)
			if tt.name == "unbalanced quote is a syntax error, not a silent version" {
				require.Error(t, err)
				var syntaxErr *SyntaxError
				require.True(t, errors.As(err, &syntaxErr), "expected a SyntaxError, got %T", err)
				return
			}
			require.NoError(t, err)

			got, err := constraint.Satisfied(New(tt.version, UnknownFormat))
			require.NoError(t, err)
			assert.Equal(t, tt.satisfied, got)
		})
	}
}

func TestConstraintExpression_EmptyAndMalformed(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		version    string
		satisfied  bool
		wantErr    require.ErrorAssertionFunc
	}{
		{
			name:       "empty string is always satisfied",
			constraint: "",
			version:    "1.0",
			satisfied:  true,
		},
		{
			name:       "empty string with nil version is satisfied",
			constraint: "",
			version:    "",
			satisfied:  true,
		},
		{
			name:       "only separators is a syntax error",
			constraint: ",,||,,",
			wantErr:    require.Error,
		},
		{
			name:       "only an or operator is a syntax error",
			constraint: "||",
			wantErr:    require.Error,
		},
		{
			name:       "empty group is a syntax error",
			constraint: "()",
			wantErr:    require.Error,
		},
		{
			name:       "empty nested group is a syntax error",
			constraint: "((()))",
			wantErr:    require.Error,
		},
		{
			name:       "unbalanced opening parenthesis is a syntax error",
			constraint: "(>= 1.0",
			wantErr:    require.Error,
		},
		{
			name:       "unbalanced closing parenthesis is a syntax error",
			constraint: ">= 1.0)",
			wantErr:    require.Error,
		},
		{
			name:       "stray closing parenthesis is a syntax error",
			constraint: ")",
			wantErr:    require.Error,
		},
		{
			name:       "empty negation is a syntax error",
			constraint: "!",
			wantErr:    require.Error,
		},
		{
			name:       "negated empty group is a syntax error",
			constraint: "!()",
			wantErr:    require.Error,
		},
		{
			name:       "trailing comma is tolerated (historic behavior)",
			constraint: ">= 1.0,",
			version:    "2.0",
			satisfied:  true,
		},
		{
			name:       "repeated commas are tolerated (historic behavior)",
			constraint: ">= 1.0,,,< 2.0",
			version:    "1.5",
			satisfied:  true,
		},
		{
			name:       "whitespace only is treated as empty",
			constraint: "   ",
			version:    "1.0",
			satisfied:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			constraint, err := newGenericConstraint(SemanticFormat, tt.constraint)
			tt.wantErr(t, err)
			if err != nil {
				return
			}

			if tt.version == "" {
				return
			}
			got, err := constraint.Satisfied(New(tt.version, SemanticFormat))
			require.NoError(t, err)
			assert.Equal(t, tt.satisfied, got)
		})
	}
}

// TestConstraintExpression_BackwardsCompatibility locks in the semantics of
// the pre-existing notation.
func TestConstraintExpression_BackwardsCompatibility(t *testing.T) {
	tests := []testCase{
		{version: "2.3.1", constraint: "", satisfied: true},
		{version: "1.3.1", constraint: "> 1.0.0, < 2.0.0", satisfied: true},
		{version: "2.5.0", constraint: "> 1.0.0, < 2.0.0", satisfied: false},
		{version: "0.2.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "1.5.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: true},
		{version: "2.5.0", constraint: "> 0.1.0, < 0.5.0 || > 1.0.0, < 2.0.0", satisfied: false},
		{version: "1.0.0", constraint: "1.0.0", satisfied: true},
		{version: "1.0.0", constraint: "=1.0.0", satisfied: true},
		{version: "1.0.0", constraint: ">=1.0.0", satisfied: true},
		{version: "1.0.0", constraint: "<=1.0.0", satisfied: true},
		{version: "1.0.0", constraint: ">1.0.0", satisfied: false},
		{version: "1.0.0", constraint: "<1.0.0", satisfied: false},
		{version: "4.5.2", constraint: "'4.5.1' || '4.5.2'", satisfied: true},
		{version: "4.5.2", constraint: `"4.5.1" || "4.5.2"`, satisfied: true},
	}

	for _, tt := range tests {
		t.Run(tt.tName(), func(t *testing.T) {
			constraint, err := newGenericConstraint(SemanticFormat, tt.constraint)
			require.NoError(t, err)
			tt.assertVersionConstraint(t, SemanticFormat, constraint)
		})
	}
}

func TestConstraintExpression_SyntaxErrorLocation(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		wantPos    int
		wantNear   string
	}{
		{
			name:       "unclosed group points at the opening parenthesis",
			constraint: "(>= 1.0, < 2.0",
			wantPos:    0,
			wantNear:   "(>= 1.0",
		},
		{
			name:       "unexpected closing parenthesis",
			constraint: ">= 1.0, < 2.0)",
			wantPos:    13,
			wantNear:   "< 2.0)",
		},
		{
			name:       "empty group points at the closing parenthesis",
			constraint: "()",
			wantPos:    1,
			wantNear:   "()",
		},
		{
			name:       "dangling negation points at the exclamation mark",
			constraint: ">= 1.0 || !",
			wantPos:    10,
			wantNear:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseRangeExpression(tt.constraint)
			require.Error(t, err)

			var syntaxErr *SyntaxError
			require.True(t, errors.As(err, &syntaxErr), "expected a SyntaxError, got %T", err)
			assert.Equal(t, tt.wantPos, syntaxErr.Position)
			assert.Contains(t, syntaxErr.Fragment, tt.wantNear)
			assert.Contains(t, syntaxErr.Error(), "position")
			assert.NotEmpty(t, syntaxErr.Fragment)
		})
	}
}

// TestConstraintExpression_SyntaxErrorsDoNotLeakInternals verifies the public
// error only exposes a stable reason plus location, never internal structures.
func TestConstraintExpression_SyntaxErrorsDoNotLeakInternals(t *testing.T) {
	inputs := []string{
		"(>= 1.0",
		"()",
		"||",
		"~1.0",
		">= 1.0 < 2.0",
		`"unterminated`,
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			_, err := parseRangeExpression(input)
			require.Error(t, err)

			message := err.Error()
			for _, banned := range []string{"expressionNode", "rangeUnit", "nodeAnd", "nodeOr", "simpleRangeExpression"} {
				assert.NotContains(t, message, banned)
			}
			assert.Contains(t, message, "position")
		})
	}
}

// TestConstraintExpression_Limits covers the depth and term-count guards.
func TestConstraintExpression_Limits(t *testing.T) {
	t.Run("deep but within-limit nesting parses", func(t *testing.T) {
		depth := MaxExpressionDepth
		expr := strings.Repeat("(", depth) + ">= 1.0" + strings.Repeat(")", depth)

		constraint, err := newGenericConstraint(SemanticFormat, expr)
		require.NoError(t, err)
		ok, err := constraint.Satisfied(New("2.0.0", SemanticFormat))
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("deep over-limit nesting fails fast without panicking", func(t *testing.T) {
		expr := strings.Repeat("(", 10_000) + "1.0" + strings.Repeat(")", 10_000)

		start := time.Now()
		_, err := parseRangeExpression(expr)
		elapsed := time.Since(start)

		require.Error(t, err)
		var syntaxErr *SyntaxError
		require.True(t, errors.As(err, &syntaxErr))
		assert.Contains(t, syntaxErr.Reason, "nesting depth")
		assert.Less(t, elapsed, 2*time.Second, "over-limit input must fail fast")
	})

	t.Run("many chained negations fail at the depth limit", func(t *testing.T) {
		expr := ">= 1.0, " + strings.Repeat("!", 10_000) + ">= 2.0"
		_, err := parseRangeExpression(expr)
		require.Error(t, err)
	})

	t.Run("long flat expression within the term limit parses", func(t *testing.T) {
		terms := make([]string, 0, MaxExpressionTerms/2)
		for i := 1; i <= MaxExpressionTerms/2; i++ {
			terms = append(terms, ">= "+strings.Repeat("0", 3)+string(rune('0'+i%10)))
		}
		expr := strings.Join(terms, ",")

		start := time.Now()
		_, err := parseRangeExpression(expr)
		require.NoError(t, err)
		assert.Less(t, time.Since(start), 2*time.Second)
	})

	t.Run("over-limit term count fails fast", func(t *testing.T) {
		terms := make([]string, 0, MaxExpressionTerms+100)
		for i := 0; i < MaxExpressionTerms+100; i++ {
			terms = append(terms, ">= 1.0")
		}
		expr := strings.Join(terms, ",")

		start := time.Now()
		_, err := parseRangeExpression(expr)
		elapsed := time.Since(start)

		require.Error(t, err)
		var syntaxErr *SyntaxError
		require.True(t, errors.As(err, &syntaxErr))
		assert.Contains(t, syntaxErr.Reason, "maximum")
		assert.Less(t, elapsed, 2*time.Second)
	})

	t.Run("unbalanced parentheses in a huge input fail fast", func(t *testing.T) {
		// a single unterminated group must not recurse down the entire input
		expr := strings.Repeat("(", 1_000_000)

		start := time.Now()
		_, err := parseRangeExpression(expr)
		require.Error(t, err)
		assert.Less(t, time.Since(start), 2*time.Second)
	})
}

func TestConstraintExpression_DeterministicRepeatedEvaluation(t *testing.T) {
	const expr = "((>= 1.0, < 2.0) || (>= 3.0, < 4.0)), !(>= 1.5, < 1.6)"

	first, err := newGenericConstraint(SemanticFormat, expr)
	require.NoError(t, err)

	var firstResult bool
	var firstErr error
	for i := 0; i < 5; i++ {
		got, err := first.Satisfied(New("1.55", SemanticFormat))
		require.NoError(t, err)
		if i == 0 {
			firstResult, firstErr = got, err
			continue
		}
		assert.Equal(t, firstResult, got)
		assert.Equal(t, firstErr, err)
	}

	// A fresh parse of the same expression must behave identically, and a
	// failed parse must leave no partial expression behind.
	second, err := newGenericConstraint(SemanticFormat, expr)
	require.NoError(t, err)
	assert.True(t, first.Expression.Equal(second.Expression))

	bad, err := newGenericConstraint(SemanticFormat, "(>= 1.0")
	require.Error(t, err)
	assert.Nil(t, bad.Expression.root, "a failed parse must not leave a partial expression")

	badAgain, errAgain := newGenericConstraint(SemanticFormat, "(>= 1.0")
	require.Error(t, errAgain)
	assert.Equal(t, err.Error(), errAgain.Error())
	assert.Nil(t, badAgain.Expression.root)
}

func TestConstraintExpression_Diagnostics(t *testing.T) {
	ResetDiagnostics()
	t.Cleanup(ResetDiagnostics)

	var seen []Diagnostic
	restore := SetDiagnosticSink(func(d Diagnostic) {
		seen = append(seen, d)
	})
	t.Cleanup(restore)

	// unparseable input produces an observable, record-scoped diagnostic
	_, err := GetConstraintWithRecord("(>= 1.0", SemanticFormat, "CVE-2024-0001")
	require.Error(t, err)

	counts := DiagnosticCountsSnapshot()
	assert.EqualValues(t, 1, counts.ParseErrors)
	require.Len(t, seen, 1)
	assert.Equal(t, ParseErrorDiagnostic, seen[0].Kind)
	assert.Equal(t, "CVE-2024-0001", seen[0].Record)
	assert.Equal(t, "(>= 1.0", seen[0].Expression)
	assert.Contains(t, seen[0].Message, "position")

	// a leaf whose format cannot be compared degrades to unsatisfied and emits
	// an observable event, without turning the whole expression into an error
	ok, evalErr := kBOperandInUnknownExpression(t)
	require.NoError(t, evalErr)
	assert.False(t, ok)

	counts = DiagnosticCountsSnapshot()
	assert.EqualValues(t, 1, counts.ParseErrors, "the supported expression must not add parse errors")
	assert.EqualValues(t, 1, counts.UnsupportedComparisons)

	// repeated evaluation is deterministic and does not accumulate partial state
	before := DiagnosticCountsSnapshot()
	for i := 0; i < 3; i++ {
		ok, evalErr := kBOperandInUnknownExpression(t)
		require.NoError(t, evalErr)
		assert.False(t, ok)
	}
	after := DiagnosticCountsSnapshot()
	assert.Equal(t, after.UnsupportedComparisons-before.UnsupportedComparisons, int64(3))

	// diagnostics carry no internal parser structures
	for _, d := range RecentDiagnostics() {
		assert.NotContains(t, d.Message, "expressionNode")
		assert.NotContains(t, d.Message, "rangeUnit")
	}
}

func kBOperandInUnknownExpression(t *testing.T) (bool, error) {
	t.Helper()
	// Build a record-style OR between a KB constraint and a semantic one, then
	// evaluate it against a semantic version. The KB operand cannot compare a
	// semantic value and must not fail the whole expression.
	kb, err := newKBConstraint("= 10")
	require.NoError(t, err)
	semantic, err := newGenericConstraint(SemanticFormat, ">= 9.0.0")
	require.NoError(t, err)

	combined := CombineConstraints(kb, semantic)
	require.NotNil(t, combined)
	return combined.Satisfied(New("5.0.0", SemanticFormat))
}

func TestConstraintExpression_RecordCombinationPreservesFormats(t *testing.T) {
	kbc, err := newKBConstraint("= 10")
	require.NoError(t, err)
	rpmc, err := newGenericConstraint(RpmFormat, "< 2.0")
	require.NoError(t, err)

	combined := CombineConstraintRecordsWithFormat(RpmFormat, rpmc, kbc)
	require.NotNil(t, combined)

	// display text joins with "||", matching the historical joined string
	assert.Equal(t, "< 2.0||= 10", combined.Value())
	assert.Equal(t, "< 2.0||= 10 (rpm)", combined.String())
	assert.Equal(t, RpmFormat, combined.Format())

	// each operand still uses its own format: the KB term only matches a KB
	// version, and the RPM term only matches an RPM version
	ok, err := combined.Satisfied(New("10", KBFormat))
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = combined.Satisfied(New("1.5.0", RpmFormat))
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = combined.Satisfied(New("10", KBFormat))
	require.NoError(t, err)
	assert.True(t, ok)

	// the KB operand is unsatisfied for a different KB value; the RPM operand
	// is compared with RPM rules because it retains its own format
	ok, err = combined.Satisfied(New("11", KBFormat))
	require.NoError(t, err)
	assert.False(t, ok)

	// combined constraint must be printable
	assert.NotEmpty(t, combined.String())
}

func TestExpression_ValueAndStringContract(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		format     Format
		wantValue  string
		wantString string
	}{
		{
			name:       "grouped expression keeps its raw text",
			constraint: "(>= 1.0, < 2.0) || (>= 3.0, < 4.0)",
			format:     SemanticFormat,
			wantValue:  "(>= 1.0, < 2.0) || (>= 3.0, < 4.0)",
			wantString: "(>= 1.0, < 2.0) || (>= 3.0, < 4.0) (semantic)",
		},
		{
			name:       "exclusion keeps its raw text",
			constraint: ">= 1.0, < 3.0, !(>= 1.5, < 2.0)",
			format:     RpmFormat,
			wantValue:  ">= 1.0, < 3.0, !(>= 1.5, < 2.0)",
			wantString: ">= 1.0, < 3.0, !(>= 1.5, < 2.0) (rpm)",
		},
		{
			name:       "empty expression preserves the none form",
			constraint: "",
			format:     DebFormat,
			wantValue:  "",
			wantString: "none (deb)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expr, err := ParseExpression(tt.constraint, tt.format)
			require.NoError(t, err)
			assert.Equal(t, tt.wantValue, expr.Value())
			assert.Equal(t, tt.wantString, expr.String())
			assert.Equal(t, tt.format, expr.Format())

			// value semantics: independently parsed expressions compare equal,
			// and a differently formatted one does not
			same, err := ParseExpression(tt.constraint, tt.format)
			require.NoError(t, err)
			assert.True(t, expr.Equal(same))

			different, err := ParseExpression(tt.constraint, UnknownFormat)
			require.NoError(t, err)
			assert.False(t, expr.Equal(different))
		})
	}
}

func TestExpression_Satisfied(t *testing.T) {
	expr, err := ParseExpression("((>= 1.0, < 2.0) || (>= 3.0, < 4.0)), !(= 1.5)", SemanticFormat)
	require.NoError(t, err)
	assert.False(t, expr.IsEmpty())

	tests := []struct {
		version   string
		satisfied bool
	}{
		{"1.2.0", true},
		{"1.5.0", false},
		{"3.5.0", true},
		{"5.0.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got, err := expr.Satisfied(New(tt.version, SemanticFormat))
			require.NoError(t, err)
			assert.Equal(t, tt.satisfied, got)
		})
	}

	t.Run("nil version is rejected", func(t *testing.T) {
		_, err := expr.Satisfied(nil)
		require.ErrorIs(t, err, ErrNoVersionProvided)
	})

	t.Run("empty expression is always satisfied", func(t *testing.T) {
		empty, err := ParseExpression("", SemanticFormat)
		require.NoError(t, err)
		assert.True(t, empty.IsEmpty())
		got, err := empty.Satisfied(New("0.0.1", SemanticFormat))
		require.NoError(t, err)
		assert.True(t, got)
	})
}

func TestExpression_SyntaxErrorIsComparableAndPrintable(t *testing.T) {
	_, first := ParseExpression("(>= 1.0", SemanticFormat)
	_, second := ParseExpression("(>= 1.0", SemanticFormat)
	require.Error(t, first)
	require.Error(t, second)

	assert.True(t, errors.Is(first, second), "identical malformed inputs must produce comparable errors")
	assert.Equal(t, first.Error(), second.Error())

	_, different := ParseExpression(">= 1.0)", SemanticFormat)
	require.Error(t, different)
	assert.False(t, errors.Is(first, different))
}
