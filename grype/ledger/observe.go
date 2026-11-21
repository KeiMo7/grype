package ledger

import (
	"sort"
	"strings"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/vulnerability"
)

// Observation is one finding as observed in a single scan, before it is reconciled
// with the ledger. Every finding that either appears in the report or was suppressed
// by an ignore/VEX rule is an observation; findings that were never detected are not.
type Observation struct {
	Identity       Identity
	PackageVersion string
	Namespaces     []string
	Aliases        []string
	State          State
	Ignore         *IgnoreInfo
	Database       DatabaseIdentity
	// FromSuppression is true when the observation came from a match the matchers
	// suppressed internally, rather than from a report match or a user ignore rule.
	// Suppressions are assessments (a distro record, an unaffected-package entry)
	// and are not audited for a missing user-supplied reason.
	FromSuppression bool
}

// Observer translates the outcomes of the existing matcher pipeline into
// observations. It only reads those outcomes; it never alters them.
type Observer struct {
	Image string
}

// NewObserver returns an Observer for one image.
func NewObserver(image string) *Observer {
	return &Observer{Image: image}
}

// Observe converts the results produced by the existing pipeline into observations:
//
//   - surviving report matches are unfixed;
//   - ignored matches that carry a VEX status are fixed or not-affected per that status;
//   - every other ignored match is ignored (an explicit user rule);
//   - matches the matchers suppressed internally are assessed from the suppression
//     reason: a distro "fixed"/NAK record or an unaffected-package entry is fixed or
//     not-affected, not merely "not in the report".
//
// suppressed are passed separately so the ledger can see those assessments even when
// the report does not (the report only includes them with
// --include-matcher-suppressions).
func (o *Observer) Observe(matches []match.Match, ignoredMatches []match.IgnoredMatch, suppressed []match.IgnoredMatch, db DatabaseIdentity) []Observation {
	byID := make(map[string]*Observation)

	for _, m := range matches {
		o.add(byID, m, StateUnfixed, nil, db, false)
	}
	for _, ignored := range ignoredMatches {
		state, info := classifyIgnored(ignored)
		o.add(byID, ignored.Match, state, info, db, false)
	}
	for _, suppressedMatch := range suppressed {
		state, info := classifySuppression(suppressedMatch)
		o.add(byID, suppressedMatch.Match, state, info, db, true)
	}

	out := make([]Observation, 0, len(byID))
	for _, obs := range byID {
		out = append(out, *obs)
	}
	// Deterministic order: encoding and byte comparisons must never depend on map
	// iteration order.
	sort.Slice(out, func(i, j int) bool { return out[i].Identity.ID() < out[j].Identity.ID() })
	return out
}

func (o *Observer) add(byID map[string]*Observation, m match.Match, state State, info *IgnoreInfo, db DatabaseIdentity, fromSuppression bool) {
	identity := Identity{
		VulnerabilityID: m.Vulnerability.ID,
		PackageName:     m.Package.Name,
		PackageType:     string(m.Package.Type),
		Image:           o.Image,
	}
	id := identity.ID()

	aliases := collectAliases(m.Vulnerability)
	namespaces := collectNamespaces(m.Vulnerability)

	if existing, ok := byID[id]; ok {
		// Several records can describe the same finding. The strongest state wins,
		// and ignore rules are unioned so every reason it was suppressed for stays
		// on the account.
		if statePriority(state) > statePriority(existing.State) {
			existing.State = state
			existing.Ignore = info
			existing.FromSuppression = fromSuppression
		} else if info != nil {
			if existing.Ignore == nil {
				existing.Ignore = &IgnoreInfo{Rules: []IgnoreRuleInfo{}}
			}
			existing.Ignore.Rules = mergeIgnoreRules(existing.Ignore.Rules, info.Rules)
		}
		existing.Aliases = dedupeSorted(append(existing.Aliases, aliases...))
		existing.Namespaces = dedupeSorted(append(existing.Namespaces, namespaces...))
		return
	}

	byID[id] = &Observation{
		Identity:        identity,
		PackageVersion:  m.Package.Version,
		Namespaces:      namespaces,
		Aliases:         aliases,
		State:           state,
		Ignore:          info,
		Database:        db,
		FromSuppression: fromSuppression,
	}
}

// classifyIgnored maps an ignored match produced by a user ignore rule or VEX onto a
// ledger state.
func classifyIgnored(ignored match.IgnoredMatch) (State, *IgnoreInfo) {
	info := newIgnoreInfo(ignored.AppliedIgnoreRules)
	state := StateIgnored
	for _, rule := range ignored.AppliedIgnoreRules {
		if rule.VexStatus != "" {
			state = stateForVexStatus(rule.VexStatus)
		}
	}
	return state, info
}

// classifySuppression maps a match dropped by a matcher onto a ledger state. These
// are assessments, not an absence: a distro that marked the package fixed gets the
// fixed state, a distro that marked it not vulnerable gets not-affected.
func classifySuppression(ignored match.IgnoredMatch) (State, *IgnoreInfo) {
	info := newIgnoreInfo(ignored.AppliedIgnoreRules)
	state := StateIgnored
	for _, rule := range ignored.AppliedIgnoreRules {
		if rule.VexStatus != "" {
			state = stateForVexStatus(rule.VexStatus)
			continue
		}
		switch assessReason(rule.Reason) {
		case StateFixed:
			state = StateFixed
		case StateNotAffected:
			// only upgrade to not-affected if nothing has already said fixed
			if state != StateFixed {
				state = StateNotAffected
			}
		}
	}
	return state, info
}

// assessReason classifies the reasons Grype's matchers attach when they suppress a
// match. User-supplied rules use the same Reason field for free-form notes, which is
// why this classification is applied only to matcher-supplied suppressions.
func assessReason(reason string) State {
	normalized := strings.ToLower(strings.TrimSpace(reason))
	switch {
	case normalized == "distro-fixed", normalized == "distro fixed":
		return StateFixed
	case strings.Contains(normalized, "not vulnerable"),
		strings.Contains(normalized, "not-affected"),
		strings.Contains(normalized, "not affected"),
		normalized == "distro-nak",
		normalized == "unaffectedpackageentry",
		strings.Contains(normalized, "unaffected"):
		return StateNotAffected
	default:
		return ""
	}
}

func newIgnoreInfo(rules []match.IgnoreRule) *IgnoreInfo {
	info := &IgnoreInfo{Rules: make([]IgnoreRuleInfo, 0, len(rules))}
	for _, rule := range rules {
		info.Rules = append(info.Rules, ignoreRuleInfo(rule))
	}
	return info
}

func stateForVexStatus(status string) State {
	switch status {
	case "fixed":
		return StateFixed
	case "not_affected":
		return StateNotAffected
	default:
		return StateIgnored
	}
}

func ignoreRuleInfo(rule match.IgnoreRule) IgnoreRuleInfo {
	return IgnoreRuleInfo{
		Vulnerability:    rule.Vulnerability,
		Namespace:        rule.Namespace,
		Reason:           rule.Reason,
		FixState:         rule.FixState,
		PackageName:      rule.Package.Name,
		PackageVersion:   rule.Package.Version,
		PackageType:      rule.Package.Type,
		VexStatus:        rule.VexStatus,
		VexJustification: rule.VexJustification,
		Expires:          rule.Expires,
	}
}

func mergeIgnoreRules(a, b []IgnoreRuleInfo) []IgnoreRuleInfo {
	seen := make(map[IgnoreRuleInfo]struct{}, len(a)+len(b))
	out := make([]IgnoreRuleInfo, 0, len(a)+len(b))
	for _, rule := range append(append([]IgnoreRuleInfo{}, a...), b...) {
		if _, exists := seen[rule]; exists {
			continue
		}
		seen[rule] = struct{}{}
		out = append(out, rule)
	}
	return out
}

func collectAliases(v vulnerability.Vulnerability) []string {
	values := make([]string, 0, 1+len(v.RelatedVulnerabilities))
	values = append(values, v.ID)
	for _, related := range v.RelatedVulnerabilities {
		values = append(values, related.ID)
	}
	return dedupeSorted(values)
}

func collectNamespaces(v vulnerability.Vulnerability) []string {
	values := make([]string, 0, 1+len(v.RelatedVulnerabilities))
	values = append(values, v.Namespace)
	for _, related := range v.RelatedVulnerabilities {
		values = append(values, related.Namespace)
	}
	return dedupeSorted(values)
}

// DatabaseFromStatus builds a DatabaseIdentity from the loaded database's status.
func DatabaseFromStatus(status *vulnerability.ProviderStatus) DatabaseIdentity {
	if status == nil {
		return DatabaseIdentity{}
	}
	db := DatabaseIdentity{SchemaVersion: status.SchemaVersion}
	if !status.Built.IsZero() {
		db.Built = status.Built.UTC().Format(time.RFC3339)
	}
	return db
}

// applyBatch reconciles one image's observations with the current ledger and returns
// the updated ledger. It is the only place entry states change.
//
// recordedAt may be empty, in which case no wall-clock timestamps are written (that
// is what keeps a re-run of the same scan byte-identical). Expiry checks still use
// the current time via the clock parameter; the time is never stored unless
// recordedAt is non-empty.
func applyBatch(current *Ledger, batchID, recordedAt, image string, db DatabaseIdentity, observed []Observation, summary *Summary, clock time.Time) *Ledger {
	next := cloneLedger(current)
	batch := upsertBatch(next, batchID, recordedAt, image, db)
	summary.DatabaseChanged = batch.DatabaseChanged

	entryIndex := make(map[string]int, len(next.Entries))
	for i := range next.Entries {
		entryIndex[next.Entries[i].ID] = i
	}

	// aliasIndex maps an alias ID (for a given package+image) to an existing entry,
	// so one account stays lined up across rounds when the same vulnerability is
	// written with a different ID in different rounds (an advisory ID in one report,
	// its CVE alias in another).
	aliasIndex := make(map[string]int)
	for i := range next.Entries {
		indexEntryAliases(aliasIndex, i, &next.Entries[i])
	}

	seenThisImage := make(map[string]struct{}, len(observed))

	for _, obs := range observed {
		state, info, issues := resolveObservation(obs, recordedAt, clock)
		for i := range issues {
			issues[i].Batch = batchID
			next.addIssue(issues[i])
			summary.Issues++
		}

		id := obs.Identity.ID()
		seenThisImage[id] = struct{}{}

		idx, exists := entryIndex[id]
		if !exists {
			// The exact identity is new, but an existing account may be the same
			// finding under a different ID spelling. Link to it rather than opening a
			// duplicate account.
			if linkedIdx, seenUnderAlias := findAliasEntry(aliasIndex, obs); seenUnderAlias {
				// the entry keeps its original ID; the new spelling is recorded as
				// an alias below
				entryIndex[id] = linkedIdx
				idx, exists = linkedIdx, true
			}
		}

		if !exists {
			entry := Entry{
				ID:              id,
				VulnerabilityID: obs.Identity.VulnerabilityID,
				Aliases:         obs.Aliases,
				Namespaces:      obs.Namespaces,
				Package: PackageIdentity{
					Name:    obs.Identity.PackageName,
					Type:    obs.Identity.PackageType,
					Version: obs.PackageVersion,
				},
				Image:          image,
				State:          state,
				FirstSeenBatch: batchID,
				LastSeenBatch:  batchID,
				FirstSeenCause: FirstSeenCauseInitial,
				Database:       obs.Database,
			}
			if batch.DatabaseChanged {
				entry.FirstSeenCause = FirstSeenCauseDatabaseChange
				summary.NewFromDatabaseChange++
			} else {
				summary.NewEntries++
			}
			if state == StateIgnored || state == StateNotAffected {
				entry.Ignore = info
			}
			if state == StateUnfixed && info != nil && info.Expired {
				// keep the expired rule for audit even though the finding is open
				entry.Ignore = info
			}
			if state == StateFixed {
				entry.FixedAtBatch = batchID
			}
			next.Entries = append(next.Entries, entry)
			entryIndex[id] = len(next.Entries) - 1
			indexEntryAliases(aliasIndex, len(next.Entries)-1, &next.Entries[len(next.Entries)-1])
			continue
		}

		entry := &next.Entries[idx]
		// mark the entry's canonical ID as observed too: when this observation linked
		// to an existing account through an alias, the canonical ID differs from the
		// observed one and must not be mistaken for "stopped being reported".
		seenThisImage[entry.ID] = struct{}{}
		entry.LastSeenBatch = batchID
		entry.Database = obs.Database
		entry.Aliases = dedupeSorted(append(entry.Aliases, obs.Aliases...))
		entry.Namespaces = dedupeSorted(append(entry.Namespaces, obs.Namespaces...))
		if obs.PackageVersion != "" {
			entry.Package.Version = obs.PackageVersion
		}
		// the ledger's canonical ID/aliases are authoritative; the observed spelling
		// is already in obs.Aliases
		if !strings.EqualFold(entry.VulnerabilityID, obs.Identity.VulnerabilityID) {
			entry.Aliases = dedupeSorted(append(entry.Aliases, obs.Identity.VulnerabilityID))
		}
		indexEntryAliases(aliasIndex, idx, entry)

		from := entry.State

		// An ignore or not-affected assessment that has been in force since an
		// earlier batch falls back to unfixed once its expiry passes, even though the
		// reported result itself is unchanged.
		if state == StateUnfixed && (from == StateIgnored || from == StateNotAffected) && info != nil && info.Expired {
			entry.State = StateUnfixed
			entry.Ignore = info
			continue
		}

		// A fixed finding being observed again is a recurrence, but only when the
		// new observation is an open one. A later assessment (not-affected) does not
		// reopen a closed account: fixed -> not-affected is rejected below.
		if from == StateFixed && state == StateUnfixed {
			cause := RecurrenceCauseReappeared
			if batch.DatabaseChanged {
				cause = RecurrenceCauseDatabaseChange
			}
			entry.Recurrences = append(entry.Recurrences, Recurrence{Batch: batchID, At: recordedAt, Cause: cause})
			summary.Recurrences++
			entry.State = StateUnfixed
			entry.Ignore = nil
			continue
		}

		if !TransitionAllowed(from, state) {
			entry.State = from
			next.Rejections = append(next.Rejections, Rejection{
				EntryID:         entry.ID,
				Batch:           batchID,
				VulnerabilityID: entry.VulnerabilityID,
				Package:         entry.Package,
				Image:           entry.Image,
				From:            from,
				To:              state,
				Reason:          RejectionReasonDisallowedState,
			})
			summary.RejectedTransitions++
			continue
		}

		entry.State = state
		switch state {
		case StateFixed:
			entry.FixedAtBatch = batchID
		case StateIgnored, StateNotAffected:
			entry.Ignore = info
		case StateUnfixed:
			if info != nil && info.Expired {
				entry.Ignore = info
			}
		}
	}

	// Anything previously on this image's ledger and not observed in this batch has
	// stopped being reported: it is fixed. The state change goes through the same
	// transition check as everything else.
	for i := range next.Entries {
		entry := &next.Entries[i]
		if entry.Image != image {
			continue
		}
		if _, seen := seenThisImage[entry.ID]; seen {
			continue
		}
		if entry.State == StateFixed {
			continue
		}
		if !TransitionAllowed(entry.State, StateFixed) {
			next.Rejections = append(next.Rejections, Rejection{
				EntryID:         entry.ID,
				Batch:           batchID,
				VulnerabilityID: entry.VulnerabilityID,
				Package:         entry.Package,
				Image:           entry.Image,
				From:            entry.State,
				To:              StateFixed,
				Reason:          RejectionReasonDisallowedState,
			})
			summary.RejectedTransitions++
			continue
		}
		entry.State = StateFixed
		entry.FixedAtBatch = batchID
		summary.Fixed++
	}

	return next
}

func (l *Ledger) addIssue(issue Issue) {
	// Never record the same issue twice for the same batch and entry.
	for _, existing := range l.Issues {
		if existing.Batch == issue.Batch && existing.EntryID == issue.EntryID && existing.Kind == issue.Kind && existing.Detail == issue.Detail {
			return
		}
	}
	l.Issues = append(l.Issues, issue)
}

// resolveObservation applies ignore-expiry to an observation. It returns the
// effective state, the ignore information to record, and any issues to record.
//
// An ignore whose rules all carry an expiry that has passed no longer holds: the
// finding returns to the unfixed state on the ledger (the report itself is unchanged).
// A permanent ignore (no expiry) is accepted, but it must have a reason or VEX
// justification available for audit; otherwise an issue is recorded.
func resolveObservation(obs Observation, recordedAt string, clock time.Time) (State, *IgnoreInfo, []Issue) {
	// Expiry applies to explicit ignores only. A not-affected assessment (VEX or a
	// distro record) is a classification, not a time-boxed exception.
	if obs.State != StateIgnored {
		return obs.State, nil, nil
	}
	if obs.Ignore == nil || len(obs.Ignore.Rules) == 0 {
		return obs.State, obs.Ignore, nil
	}

	at := clock
	if recordedAt != "" {
		if parsed, err := time.Parse(time.RFC3339, recordedAt); err == nil {
			at = parsed
		}
	}

	allExpired := true
	var issues []Issue

	for _, rule := range obs.Ignore.Rules {
		if rule.Expires == "" {
			allExpired = false
			// A permanent ignore is only auditable if a reason or a VEX
			// justification explains it. Matcher suppressions are assessments (the
			// distro or database supplied the classification), so they are exempt.
			if !obs.FromSuppression && rule.Reason == "" && rule.VexJustification == "" && rule.VexStatus == "" {
				issues = append(issues, Issue{
					EntryID: obs.Identity.ID(),
					Kind:    IssuePermanentIgnoreNoReason,
					Detail:  describeRule(rule),
				})
			}
			continue
		}

		expiry, err := parseExpiry(rule.Expires)
		if err != nil {
			allExpired = false
			issues = append(issues, Issue{
				EntryID: obs.Identity.ID(),
				Kind:    IssueInvalidIgnoreExpiry,
				Detail:  rule.Expires,
			})
			continue
		}
		if !expiry.Before(at) {
			allExpired = false
		}
	}

	info := *obs.Ignore
	if allExpired {
		info.Expired = true
		issues = append(issues, Issue{
			EntryID: obs.Identity.ID(),
			Kind:    IssueIgnoreExpired,
			Detail:  describeRule(info.Rules[0]),
		})
		return StateUnfixed, &info, issues
	}

	return obs.State, &info, issues
}

func describeRule(rule IgnoreRuleInfo) string {
	switch {
	case rule.Vulnerability != "" && rule.Reason != "":
		return rule.Vulnerability + ": " + rule.Reason
	case rule.Vulnerability != "":
		return rule.Vulnerability
	case rule.Reason != "":
		return rule.Reason
	default:
		return "ignore rule without vulnerability or reason"
	}
}

// parseExpiry accepts an RFC3339 timestamp or a YYYY-MM-DD date; a bare date is
// interpreted as the end of that day in UTC.
func parseExpiry(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	t, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}, err
	}
	return t.Add(24*time.Hour - time.Nanosecond), nil
}

func cloneLedger(l *Ledger) *Ledger {
	next := &Ledger{
		Path:       l.Path,
		Created:    l.Created,
		Batches:    append([]Batch{}, l.Batches...),
		Entries:    make([]Entry, len(l.Entries)),
		Rejections: append([]Rejection{}, l.Rejections...),
		Issues:     append([]Issue{}, l.Issues...),
	}
	copy(next.Entries, l.Entries)
	return next
}

// indexEntryAliases records every spelling of an entry's vulnerability ID under the
// entry's identity coordinates.
func indexEntryAliases(index map[string]int, entryIdx int, entry *Entry) {
	for _, alias := range append([]string{entry.VulnerabilityID}, entry.Aliases...) {
		index[aliasKey(alias, entry.Package.Name, entry.Package.Type, entry.Image)] = entryIdx
	}
}

func aliasKey(alias, packageName, packageType, image string) string {
	return strings.ToLower(strings.TrimSpace(alias)) + "\x00" +
		strings.TrimSpace(packageName) + "\x00" +
		strings.TrimSpace(packageType) + "\x00" +
		strings.TrimSpace(image)
}

// findAliasEntry looks for an existing entry sharing any spelling of the observed
// vulnerability ID on the same package and image.
func findAliasEntry(index map[string]int, obs Observation) (int, bool) {
	for _, alias := range append([]string{obs.Identity.VulnerabilityID}, obs.Aliases...) {
		key := aliasKey(alias, obs.Identity.PackageName, obs.Identity.PackageType, obs.Identity.Image)
		if idx, ok := index[key]; ok {
			return idx, true
		}
	}
	return 0, false
}

func upsertBatch(l *Ledger, batchID, recordedAt, image string, db DatabaseIdentity) Batch {
	for i := range l.Batches {
		if l.Batches[i].ID == batchID {
			batch := &l.Batches[i]
			batch.Images = dedupeSorted(append(batch.Images, image))
			if !db.IsZero() {
				batch.Database = db
			}
			return *batch
		}
	}

	sequence := 1
	var previous Batch
	var havePrevious bool
	for _, batch := range l.Batches {
		if batch.Sequence >= sequence {
			sequence = batch.Sequence + 1
		}
		if !havePrevious || batch.Sequence > previous.Sequence {
			previous = batch
			havePrevious = true
		}
	}

	batch := Batch{
		Sequence:   sequence,
		ID:         batchID,
		RecordedAt: recordedAt,
		Images:     []string{image},
		Database:   db,
	}
	if havePrevious {
		batch.PreviousBatch = previous.ID
		if !db.IsZero() && !previous.Database.IsZero() && !db.Equal(previous.Database) {
			batch.DatabaseChanged = true
		}
	}
	l.Batches = append(l.Batches, batch)
	return batch
}
