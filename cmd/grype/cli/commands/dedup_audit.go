package commands

import (
	"encoding/json"
	"os"

	"github.com/anchore/grype/grype/match/dedup"
)

// writeDedupAuditReport writes the second-stage dedup audit trail to path as indented JSON.
// It is only invoked when the user configured dedup.audit-report; ordinary scans produce no
// extra file.
func writeDedupAuditReport(path string, report dedup.Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
