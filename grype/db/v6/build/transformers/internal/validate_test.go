package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	db "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/version"
)

func TestValidateAffectedVersion(t *testing.T) {
	tests := []struct {
		name      string
		version   db.Version
		wantErr   require.ErrorAssertionFunc
		wantErrAs bool
	}{
		// existing, previously-valid notation must keep passing
		{
			name:    "empty constraint",
			version: db.Version{Type: "rpm", Constraint: ""},
		},
		{
			name:    "single comparator",
			version: db.Version{Type: "rpm", Constraint: ">= 1.2.3"},
		},
		{
			name:    "comma and",
			version: db.Version{Type: "rpm", Constraint: ">= 1.0, < 2.0"},
		},
		{
			name:    "double pipe or",
			version: db.Version{Type: "rpm", Constraint: "< 1.0 || >= 2.0"},
		},
		{
			name:    "quoted version",
			version: db.Version{Type: "semantic", Constraint: `"1.2.3"`},
		},
		{
			name:    "unknown format legacy notation",
			version: db.Version{Type: "", Constraint: "> 1.0, < 2.0 || = 3.0"},
		},
		// newly supported notation must be recognized, not flagged as dirty data
		{
			name:    "parenthesized groups",
			version: db.Version{Type: "rpm", Constraint: "(>= 1.0, < 2.0) || (>= 3.0, < 4.0)"},
		},
		{
			name:    "nested parenthesized groups",
			version: db.Version{Type: "rpm", Constraint: "((>= 1.0, < 2.0) || (>= 5.0, < 6.0)), !(= 1.5)"},
		},
		{
			name:    "exclusion range",
			version: db.Version{Type: "deb", Constraint: ">= 1.0, < 3.0, !(>= 1.5, < 2.0)"},
		},
		{
			name:    "quoted literal containing grouping characters",
			version: db.Version{Type: "", Constraint: `"1.0, (2.0||)"`},
		},
		// malformed notation must still be rejected
		{
			name:      "unbalanced parentheses",
			version:   db.Version{Type: "rpm", Constraint: "(>= 1.0, < 2.0"},
			wantErr:   require.Error,
			wantErrAs: true,
		},
		{
			name:      "empty group",
			version:   db.Version{Type: "rpm", Constraint: "()"},
			wantErr:   require.Error,
			wantErrAs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			err := ValidateAffectedVersion(tt.version)
			tt.wantErr(t, err)
			if err != nil && tt.wantErrAs {
				var syntaxErr *version.SyntaxError
				assert.ErrorAs(t, err, &syntaxErr)
			}
		})
	}
}
