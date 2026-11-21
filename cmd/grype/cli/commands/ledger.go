package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/ledger"
)

type ledgerQueryOptions struct {
	File string `yaml:"file" json:"file" mapstructure:"file"`
	// By selects the query dimension: vulnerability, package or image.
	By    string   `yaml:"by" json:"by" mapstructure:"by"`
	ID    string   `yaml:"id" json:"id" mapstructure:"id"`
	State []string `yaml:"state" json:"state" mapstructure:"state"`
	// Output is "text" or "json".
	Output string `yaml:"output" json:"output" mapstructure:"output"`
	// Summary prints per-state counts for the whole ledger instead of entries.
	Summary bool `yaml:"summary" json:"summary" mapstructure:"summary"`
}

var _ clio.FlagAdder = (*ledgerQueryOptions)(nil)

func (o *ledgerQueryOptions) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.File, "file", "f", "path to the ledger file")
	flags.StringVarP(&o.By, "by", "", "query dimension: vulnerability, package, or image")
	flags.StringVarP(&o.ID, "id", "", "vulnerability ID, package name, or image reference to query")
	flags.StringArrayVarP(&o.State, "state", "", "only show entries in the given state (repeatable): unfixed, fixed, not-affected, ignored")
	flags.StringVarP(&o.Output, "output", "o", "output format: text or json")
	flags.BoolVarP(&o.Summary, "summary", "", "show per-state counts for the whole ledger instead of entries")
}

// Ledger returns the `grype ledger` command, which queries an existing ledger. It
// never writes.
func Ledger(app clio.Application) *cobra.Command {
	opts := &ledgerQueryOptions{Output: textOutputFormat}

	cmd := &cobra.Command{
		Use:   "ledger --file PATH (--by vulnerability --id CVE-YYYY-NNNN | --by package --id NAME | --by image --id IMAGE | --summary)",
		Short: "Query a vulnerability ledger recorded with --ledger",
		Long: `Query the persistent vulnerability ledger produced by scans run with --ledger.

Three views are available:
  --by vulnerability --id CVE-...   every package and image this vulnerability was recorded against
  --by package --id NAME            every vulnerability this package has carried
  --by image --id IMAGE             the entries currently open (unfixed) on that image

States are distinct: a finding that is not in the report is classified as fixed,
not-affected or ignored rather than lumped together as "absent".`,
		Args:    cobra.NoArgs,
		PreRunE: disableUI(app),
		RunE: func(_ *cobra.Command, _ []string) error {
			return runLedgerQuery(*opts)
		},
	}

	type configWrapper struct {
		Hidden *ledgerQueryOptions `json:"-" yaml:"-" mapstructure:"-"`
	}

	return app.SetupCommand(cmd, &configWrapper{Hidden: opts})
}

func runLedgerQuery(opts ledgerQueryOptions) error {
	if opts.File == "" {
		return fmt.Errorf("--file is required")
	}

	l, err := ledger.LoadQuery(opts.File)
	if err != nil {
		return err
	}

	if opts.Summary {
		return writeLedgerSummary(opts, l)
	}

	kind, ok := ledger.ParseQueryKind(opts.By)
	if !ok {
		return fmt.Errorf("--by must be one of: vulnerability, package, image")
	}
	if strings.TrimSpace(opts.ID) == "" {
		return fmt.Errorf("--id is required with --by %s", kind)
	}

	states, err := parseStates(opts.State)
	if err != nil {
		return err
	}
	// The by-image view asks "what is currently open on this image", so it defaults
	// to unfixed when no explicit state was requested.
	if len(states) == 0 && kind == ledger.QueryByImage {
		states = []ledger.State{ledger.StateUnfixed}
	}

	result := ledger.RunQuery(l, ledger.Query{Kind: kind, Value: opts.ID, States: states})

	if opts.Output == jsonOutputFormat {
		return writeLedgerJSON(os.Stdout, result)
	}
	_, err = fmt.Fprint(os.Stdout, result.String())
	return err
}

func parseStates(values []string) ([]ledger.State, error) {
	var states []ledger.State
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			state, ok := ledger.ParseState(part)
			if !ok {
				return nil, fmt.Errorf("unknown state %q (options: unfixed, fixed, not-affected, ignored)", part)
			}
			states = append(states, state)
		}
	}
	return states, nil
}

func writeLedgerSummary(opts ledgerQueryOptions, l *ledger.Ledger) error {
	counts := l.CountByState()

	if opts.Output == jsonOutputFormat {
		payload := struct {
			Entries    int            `json:"entries"`
			Batches    int            `json:"batches"`
			States     map[string]int `json:"states"`
			Rejections int            `json:"rejections"`
			Issues     int            `json:"issues"`
		}{
			Entries:    len(l.Entries),
			Batches:    len(l.Batches),
			States:     map[string]int{},
			Rejections: len(l.Rejections),
			Issues:     len(l.Issues),
		}
		for _, state := range ledger.AllStates() {
			payload.States[string(state)] = counts[state]
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(payload)
	}

	fmt.Fprintf(os.Stdout, "ledger %s\n", opts.File)
	// batches, oldest first, with database-change annotations
	batches := append([]ledger.Batch{}, l.Batches...)
	sort.Slice(batches, func(i, j int) bool { return batches[i].Sequence < batches[j].Sequence })
	for _, batch := range batches {
		annotation := ""
		if batch.DatabaseChanged {
			annotation = " (database changed)"
		}
		fmt.Fprintf(os.Stdout, "  batch %q seq=%d images=%s%s\n", batch.ID, batch.Sequence, strings.Join(batch.Images, ","), annotation)
	}
	fmt.Fprintf(os.Stdout, "entries: %d (unfixed %d, fixed %d, not-affected %d, ignored %d)\n",
		len(l.Entries), counts[ledger.StateUnfixed], counts[ledger.StateFixed],
		counts[ledger.StateNotAffected], counts[ledger.StateIgnored])
	if len(l.Rejections) > 0 {
		fmt.Fprintf(os.Stdout, "rejected transitions: %d\n", len(l.Rejections))
	}
	if len(l.Issues) > 0 {
		fmt.Fprintf(os.Stdout, "issues: %d\n", len(l.Issues))
	}
	return nil
}

func writeLedgerJSON(w *os.File, result ledger.QueryResult) error {
	payload := struct {
		Kind        string         `json:"kind"`
		Value       string         `json:"value"`
		StateCounts map[string]int `json:"stateCounts"`
		Entries     []ledger.Entry `json:"entries"`
	}{
		Kind:        string(result.Kind),
		Value:       result.Value,
		StateCounts: map[string]int{},
		Entries:     result.Entries,
	}
	for _, state := range ledger.AllStates() {
		payload.StateCounts[string(state)] = result.StateCounts[state]
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}
