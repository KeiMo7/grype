package options

import (
	"fmt"
	"strings"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/format"
	"github.com/anchore/syft/syft/source"
)

type Grype struct {
	Outputs                    []string           `yaml:"output" json:"output" mapstructure:"output"` // -o, <presenter>=<file> the Presenter hint string to use for report formatting and the output file
	File                       string             `yaml:"file" json:"file" mapstructure:"file"`       // --file, the file to write report output to
	Pretty                     bool               `yaml:"pretty" json:"pretty" mapstructure:"pretty"`
	Distro                     string             `yaml:"distro" json:"distro" mapstructure:"distro"`                                           // --distro, specify a distro to explicitly use
	GenerateMissingCPEs        bool               `yaml:"add-cpes-if-none" json:"add-cpes-if-none" mapstructure:"add-cpes-if-none"`             // --add-cpes-if-none, automatically generate CPEs if they are not present in import (e.g. from a 3rd party SPDX document)
	OutputTemplateFile         string             `yaml:"output-template-file" json:"output-template-file" mapstructure:"output-template-file"` // -t, the template file to use for formatting the final report
	CheckForAppUpdate          bool               `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
	OnlyFixed                  bool               `yaml:"only-fixed" json:"only-fixed" mapstructure:"only-fixed"`                               // only fail if detected vulns have a fix
	OnlyNotFixed               bool               `yaml:"only-notfixed" json:"only-notfixed" mapstructure:"only-notfixed"`                      // only fail if detected vulns don't have a fix
	IgnoreStates               string             `yaml:"ignore-states" json:"ignore-wontfix" mapstructure:"ignore-wontfix"`                    // ignore detections for vulnerabilities matching these comma-separated fix states
	Platform                   string             `yaml:"platform" json:"platform" mapstructure:"platform"`                                     // --platform, override the target platform for a container image
	Search                     search             `yaml:"search" json:"search" mapstructure:"search"`
	Ignore                     []match.IgnoreRule `yaml:"ignore" json:"ignore" mapstructure:"ignore"`
	Exclusions                 []string           `yaml:"exclude" json:"exclude" mapstructure:"exclude"`
	ExternalSources            externalSources    `yaml:"external-sources" json:"externalSources" mapstructure:"external-sources"`
	Match                      matchConfig        `yaml:"match" json:"match" mapstructure:"match"`
	FailOn                     string             `yaml:"fail-on-severity" json:"fail-on-severity" mapstructure:"fail-on-severity"`
	Registry                   registry           `yaml:"registry" json:"registry" mapstructure:"registry"`
	ShowSuppressed             bool               `yaml:"show-suppressed" json:"show-suppressed" mapstructure:"show-suppressed"`
	IncludeMatcherSuppressions bool               `yaml:"include-matcher-suppressions" json:"include-matcher-suppressions" mapstructure:"include-matcher-suppressions"` // include matches suppressed internally by matchers (distro fixed/NAK records, built-in false-positive list) in the ignored matches output, default=false
	ByCVE                      bool               `yaml:"by-cve" json:"by-cve" mapstructure:"by-cve"`                                                                   // --by-cve, indicates if the original match vulnerability IDs should be preserved or the CVE should be used instead
	SortBy                     SortBy             `yaml:",inline" json:",inline" mapstructure:",squash"`
	Name                       string             `yaml:"name" json:"name" mapstructure:"name"`
	DefaultImagePullSource     string             `yaml:"default-image-pull-source" json:"default-image-pull-source" mapstructure:"default-image-pull-source"`
	From                       []string           `yaml:"from" json:"from" mapstructure:"from"`
	VexDocuments               []string           `yaml:"vex-documents" json:"vex-documents" mapstructure:"vex-documents"`
	VexAdd                     []string           `yaml:"vex-add" json:"vex-add" mapstructure:"vex-add"`                                                                   // GRYPE_VEX_ADD
	MatchUpstreamKernelHeaders bool               `yaml:"match-upstream-kernel-headers" json:"match-upstream-kernel-headers" mapstructure:"match-upstream-kernel-headers"` // Show matches on kernel-headers packages where the match is on kernel upstream instead of marking them as ignored, default=false
	FixChannel                 FixChannels        `yaml:"fix-channel" json:"fix-channel" mapstructure:"fix-channel"`                                                       // the fix channels to apply to the distro when matching
	Timestamp                  bool               `yaml:"timestamp" json:"timestamp" mapstructure:"timestamp"`
	Alerts                     Alerts             `yaml:"alerts" json:"alerts" mapstructure:"alerts"`
	// Ledger, when non-empty, is the path to a vulnerability ledger file to record
	// this scan into. An empty value disables ledger recording entirely (the default).
	Ledger string `yaml:"ledger" json:"ledger,omitempty" mapstructure:"ledger"` // --ledger, record results into a persistent vulnerability ledger at this path
	// LedgerImage optionally overrides the image identity recorded in the ledger.
	LedgerImage string `yaml:"ledger-image" json:"ledger-image,omitempty" mapstructure:"ledger-image"` // --ledger-image
	// LedgerBatch optionally groups several scans into one batch. Scans sharing a
	// batch name are recorded as one batch; writes are serialized by a file lock.
	LedgerBatch string `yaml:"ledger-batch" json:"ledger-batch,omitempty" mapstructure:"ledger-batch"` // --ledger-batch
	// LedgerTimestamps controls whether wall-clock timestamps are written into the
	// ledger; disabled by default so re-running a scan is byte-identical.
	LedgerTimestamps bool `yaml:"ledger-timestamps" json:"ledger-timestamps,omitempty" mapstructure:"ledger-timestamps"` // --ledger-timestamps
	DatabaseCommand  `yaml:",inline" json:",inline" mapstructure:",squash"`
}

type developer struct {
	DB databaseDeveloper `yaml:"db" json:"db" mapstructure:"db"`
}

type databaseDeveloper struct {
	Debug bool `yaml:"debug" json:"debug" mapstructure:"debug"`
}

var _ interface {
	clio.FlagAdder
	clio.PostLoader
	clio.FieldDescriber
} = (*Grype)(nil)

func DefaultGrype(id clio.Identification) *Grype {
	return &Grype{
		Search:     defaultSearch(source.SquashedScope),
		FixChannel: DefaultFixChannels(),
		DatabaseCommand: DatabaseCommand{
			DB: DefaultDatabase(id),
		},
		Match:                      defaultMatchConfig(),
		ExternalSources:            defaultExternalSources(),
		CheckForAppUpdate:          true,
		VexAdd:                     []string{},
		MatchUpstreamKernelHeaders: false,
		IncludeMatcherSuppressions: false,
		SortBy:                     defaultSortBy(),
		Timestamp:                  true,
		Alerts:                     defaultAlerts(),
	}
}

// nolint:funlen
func (o *Grype) AddFlags(flags clio.FlagSet) {
	flags.StringVarP(&o.Search.Scope,
		"scope", "s",
		fmt.Sprintf("selection of layers to analyze, options=%v", source.AllScopes),
	)

	flags.StringArrayVarP(&o.Outputs,
		"output", "o",
		fmt.Sprintf("report output formatter, formats=%v, deprecated formats=%v", format.AvailableFormats, format.DeprecatedFormats),
	)

	flags.StringVarP(&o.File,
		"file", "",
		"file to write the default report output to (default is STDOUT)",
	)

	flags.StringVarP(&o.Name,
		"name", "",
		"set the name of the target being analyzed",
	)

	flags.StringVarP(&o.Distro,
		"distro", "",
		"distro to match against in the format: <distro>[-:@]<version>",
	)

	flags.BoolVarP(&o.GenerateMissingCPEs,
		"add-cpes-if-none", "",
		"generate CPEs for packages with no CPE data",
	)

	flags.StringVarP(&o.OutputTemplateFile,
		"template", "t",
		"specify the path to a Go template file (requires 'template' output to be selected)")

	flags.StringVarP(&o.FailOn,
		"fail-on", "f",
		fmt.Sprintf("set the return code to 2 if a vulnerability is found with a severity >= the given severity, options=%v", vulnerability.AllSeverities()),
	)

	flags.BoolVarP(&o.OnlyFixed,
		"only-fixed", "",
		"ignore matches for vulnerabilities that are not fixed",
	)

	flags.BoolVarP(&o.OnlyNotFixed,
		"only-notfixed", "",
		"ignore matches for vulnerabilities that are fixed",
	)

	flags.StringVarP(&o.IgnoreStates,
		"ignore-states", "",
		fmt.Sprintf("ignore matches for vulnerabilities with specified comma separated fix states, options=%v", vulnerability.AllFixStates()),
	)

	flags.BoolVarP(&o.ByCVE,
		"by-cve", "",
		"orient results by CVE instead of the original vulnerability ID when possible",
	)

	flags.BoolVarP(&o.ShowSuppressed,
		"show-suppressed", "",
		"show suppressed/ignored vulnerabilities in the output (only supported with table output format)",
	)

	flags.StringArrayVarP(&o.Exclusions,
		"exclude", "",
		"exclude paths from being scanned using a glob expression",
	)

	flags.StringVarP(&o.Platform,
		"platform", "",
		"an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux')",
	)

	flags.StringArrayVarP(&o.From,
		"from", "",
		"specify the source behavior to use (e.g. docker, registry, podman, containers-storage, oci-dir, ...)",
	)

	flags.StringArrayVarP(&o.VexDocuments,
		"vex", "",
		"a list of VEX documents to consider when producing scanning results",
	)

	flags.StringVarP(&o.Ledger,
		"ledger", "",
		"record results into a persistent vulnerability ledger at this path (disabled by default)",
	)

	flags.StringVarP(&o.LedgerImage,
		"ledger-image", "",
		"image identity to record in the ledger (defaults to the scan source)",
	)

	flags.StringVarP(&o.LedgerBatch,
		"ledger-batch", "",
		"batch name grouping several scans recorded into the same ledger (defaults to the image identity)",
	)

	flags.BoolVarP(&o.LedgerTimestamps,
		"ledger-timestamps", "",
		"write wall-clock timestamps into the ledger (disabled by default so re-running a scan is byte-identical)",
	)
}

func (o *Grype) PostLoad() error {
	o.From = flatten(o.From)

	if o.FailOn != "" {
		failOnSeverity := *o.FailOnSeverity()
		if failOnSeverity == vulnerability.UnknownSeverity {
			return fmt.Errorf("bad --fail-on severity value '%s'", o.FailOn)
		}
	}
	return nil
}

func (o *Grype) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.CheckForAppUpdate, `enable/disable checking for application updates on startup`)
	descriptions.Add(&o.DefaultImagePullSource, `allows users to specify which image source should be used to generate the sbom
valid values are: registry, docker, podman, containers-storage`)
	descriptions.Add(&o.Name, `same as --name; set the name of the target being analyzed`)
	descriptions.Add(&o.Exclusions, `a list of globs to exclude from scanning, for example:
  - '/etc/**'
  - './out/**/*.json'
same as --exclude`)
	descriptions.Add(&o.File, `if using template output, you must provide a path to a Go template file
see https://github.com/anchore/grype#using-templates for more information on template output
the default path to the template file is the current working directory
output-template-file: .grype/html.tmpl

write output report to a file (default is to write to stdout)`)
	descriptions.Add(&o.Outputs, `the output format of the vulnerability report (options: table, template, json, cyclonedx)
when using template as the output type, you must also provide a value for 'output-template-file'`)
	descriptions.Add(&o.Pretty, `pretty-print output`)
	descriptions.Add(&o.FailOn, `upon scanning, if a severity is found at or above the given severity then the return code will be 1
default is unset which will skip this validation (options: negligible, low, medium, high, critical)`)
	descriptions.Add(&o.Ignore, `a list of vulnerability ignore rules; a match must meet ALL criteria specified in a rule to be ignored.
This is the full set of supported rule fields:
  - vulnerability: CVE-2008-4318        # match by vulnerability ID (required if no other criteria are given)
    namespace: nvd:cpe                   # match by vulnerability namespace (e.g. nvd:cpe, github:language:go)
    fix-state: unknown                   # match by fix state; options: fixed, not-fixed, wont-fix, unknown
    match-type: exact-direct-match       # match by how the vulnerability was found; options: exact-direct-match, exact-indirect-match, cpe-match
    reason: "tolerated by policy"        # optional human-readable note recorded on the ignored match (does not affect matching)
    expires: "2026-06-30"                # optional expiry for a temporary ignore (RFC3339 or YYYY-MM-DD); the vulnerability is still ignored for this scan, but the ledger returns it to unfixed afterwards
    include-aliases: true                # also apply the vulnerability ID match to aliases/related CVEs (default: false)
    package:
      name: libcurl                      # match by package name (supports regular expressions)
      version: 1.5.1                     # match by package version
      language: python                   # match by package language (e.g. python, javascript, java, go, …)
      type: npm                          # match by package type (e.g. rpm, deb, apk, gem, npm, go-module, …)
      location: "/usr/local/lib/node_modules/**"  # match by package location (supports glob patterns)
      upstream-name: curl                # match by upstream package name (supports regular expressions)

VEX fields apply when Grype reads VEX data:
  - vex-status: not_affected
    vex-justification: vulnerable_code_not_present
`)
	descriptions.Add(&o.VexAdd, `VEX statuses to consider as ignored rules`)
	descriptions.Add(&o.MatchUpstreamKernelHeaders, `match kernel-header packages with upstream kernel as kernel vulnerabilities`)
	descriptions.Add(&o.IncludeMatcherSuppressions, `include matches suppressed internally by matchers (e.g. distro fixed/NAK records, the built-in false-positive list) in the ignored matches output`)
	descriptions.Add(&o.Ledger, `record this scan's findings into a persistent vulnerability ledger at the given file path.
The ledger tracks each finding across batches: when it was first seen, the most
recent batch it was still seen in, whether it is unfixed, fixed, not-affected or
ignored, and recurrences after a fix. Recording never changes the report, the
ignore/VEX decisions, or the exit code. Query a ledger with 'grype ledger'.`)
	descriptions.Add(&o.LedgerImage, `image identity to record in the ledger; defaults to the scan source. Use this to keep
the identity stable when the same image is scanned from different references.`)
	descriptions.Add(&o.LedgerBatch, `batch name grouping several scans into one ledger batch; defaults to the image identity.
Scans recorded under the same batch share a batch identity, and concurrent writes to
one ledger file are serialized by a file lock, so a multi-image scan can record each
image as it finishes.`)
	descriptions.Add(&o.LedgerTimestamps, `write wall-clock timestamps into the ledger. Disabled by default so that recording
the same scan twice produces byte-identical ledger contents.`)
}

func (o Grype) FailOnSeverity() *vulnerability.Severity {
	severity := vulnerability.ParseSeverity(o.FailOn)
	return &severity
}

// flatten takes a list of comma-separated entries and returns a flattened list of trimmed values (preserving order)
func flatten(commaSeparatedEntries []string) []string {
	var out []string
	for _, v := range commaSeparatedEntries {
		for _, s := range strings.Split(v, ",") {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}
