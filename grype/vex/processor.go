package vex

import (
	"fmt"
	"os"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vex/csaf"
	"github.com/anchore/grype/grype/vex/openvex"
)

type Processor struct {
	Options ProcessorOptions
	impl    vexProcessorImplementation

	// Clock supplies the current time when deciding whether a time-bound VEX
	// exemption is active. When nil the system clock is used.
	Clock match.Clock
}

type vexProcessorImplementation interface {
	// ReadVexDocuments takes a list of vex filenames and returns a single
	// value representing the VEX information in the underlying implementation's
	// format. Returns an error if the files cannot be processed.
	ReadVexDocuments(docs []string) (any, error)

	// FilterMatches matches receives the underlying VEX implementation VEX data and
	// the scanning context and matching results and filters the fixed and
	// not_affected results,moving them to the list of ignored matches.
	FilterMatches(any, []match.IgnoreRule, *pkg.Context, *match.Matches, []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch, error)

	// AugmentMatches reads known affected VEX products from loaded documents and
	// adds new results to the scanner results when the product is marked as
	// affected in the VEX data.
	AugmentMatches(any, []match.IgnoreRule, *pkg.Context, *match.Matches, []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch, error)
}

// getVexImplementation this function returns the vex processor implementation
// at some point it can read the options and choose a user configured implementation.
func getVexImplementation(documents []string) (vexProcessorImplementation, error) {
	// No documents, no implementation
	if len(documents) == 0 {
		return nil, nil
	}

	firstDoc := documents[0]

	if _, err := os.Stat(firstDoc); err != nil {
		return nil, fmt.Errorf("VEX document %q not found", firstDoc)
	}

	if csaf.IsCSAF(firstDoc) {
		return csaf.New(), nil
	}
	if openvex.IsOpenVex(firstDoc) {
		return openvex.New(), nil
	}

	return nil, fmt.Errorf("unsupported VEX document format for %q", firstDoc)
}

// NewProcessor returns a new VEX processor
func NewProcessor(opts ProcessorOptions) (*Processor, error) {
	implementation, err := getVexImplementation(opts.Documents)
	if err != nil {
		return nil, fmt.Errorf("unable to create VEX processor: %w", err)
	}

	return &Processor{
		Options: opts,
		impl:    implementation,
	}, nil
}

// ProcessorOptions captures the options of the VEX processor.
type ProcessorOptions struct {
	Documents   []string
	IgnoreRules []match.IgnoreRule
}

// inactiveExemptionStatus marks a placeholder rule that stands in for configured
// VEX exemptions that are not active at the moment of evaluation. It can never
// equal a VEX statement's status, so it never suppresses, but its presence keeps
// the VEX processors from falling back to their "no rules configured" default,
// which would otherwise suppress every not_affected/fixed statement and let an
// expired exemption keep working.
const inactiveExemptionStatus = "__grype_inactive_exemption__"

// vexRulesEvaluatedAt extracts the VEX ignore rules that are active at now.
// When VEX rules are configured but none is active, it returns a single inert
// placeholder so the processors do not apply their default suppression.
func (vm *Processor) vexRulesEvaluatedAt(now time.Time) []match.IgnoreRule {
	configured := extractVexRules(vm.Options.IgnoreRules)
	active := match.ActiveIgnoreRules(configured, now)
	if len(configured) > 0 && len(active) == 0 {
		return []match.IgnoreRule{{Namespace: "vex", VexStatus: inactiveExemptionStatus}}
	}
	return active
}

// ApplyVEX receives the results from a scan run and applies any VEX information
// in the files specified in the grype invocation. Any filtered results will
// be moved to the ignored matches slice. Exemptions are evaluated against the
// processor's clock; use ApplyVEXAt to evaluate them at an explicit moment.
func (vm *Processor) ApplyVEX(pkgContext *pkg.Context, remainingMatches *match.Matches, ignoredMatches []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch, error) {
	return vm.ApplyVEXAt(match.Now(vm.Clock), pkgContext, remainingMatches, ignoredMatches)
}

// ApplyVEXAt is ApplyVEX evaluated at an explicit moment, so a run uses one
// clock for both DB and VEX exemption decisions.
func (vm *Processor) ApplyVEXAt(now time.Time, pkgContext *pkg.Context, remainingMatches *match.Matches, ignoredMatches []match.IgnoredMatch) (*match.Matches, []match.IgnoredMatch, error) {
	var err error

	// If no VEX documents are loaded, just pass through the matches, effectively NOOP
	if len(vm.Options.Documents) == 0 {
		return remainingMatches, ignoredMatches, nil
	}

	// Read VEX data from all passed documents
	rawVexData, err := vm.impl.ReadVexDocuments(vm.Options.Documents)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing vex document: %w", err)
	}

	vexRules := vm.vexRulesEvaluatedAt(now)

	remainingMatches, ignoredMatches, err = vm.impl.FilterMatches(
		rawVexData, vexRules, pkgContext, remainingMatches, ignoredMatches,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("checking matches against VEX data: %w", err)
	}

	remainingMatches, ignoredMatches, err = vm.impl.AugmentMatches(
		rawVexData, vexRules, pkgContext, remainingMatches, ignoredMatches,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("checking matches to augment from VEX data: %w", err)
	}

	return remainingMatches, ignoredMatches, nil
}

// extractVexRules is a utility function that takes a set of ignore rules and
// extracts those that act on VEX statuses.
func extractVexRules(rules []match.IgnoreRule) []match.IgnoreRule {
	newRules := []match.IgnoreRule{}
	for _, r := range rules {
		if r.VexStatus != "" {
			newRules = append(newRules, r)
			newRules[len(newRules)-1].Namespace = "vex"
		}
	}

	return newRules
}
