package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Identity is the stable identity of one ledger account: one vulnerability on one
// package in one image.
//
// It deliberately excludes everything about a scan that can change without the
// finding changing: the scan timestamp, the vulnerability database version, the
// order results were found or emitted in, severity metadata, fix information and
// the package version. That is what makes the same account line up across batches
// even when the database is refreshed, the package is upgraded, or the output is
// reordered.
type Identity struct {
	VulnerabilityID string
	PackageName     string
	PackageType     string
	Image           string
}

// ID returns the deterministic identifier for the identity. The same identity always
// produces the same ID, across processes and platforms.
func (i Identity) ID() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		strings.ToLower(strings.TrimSpace(i.VulnerabilityID)),
		strings.TrimSpace(i.PackageName),
		strings.TrimSpace(i.PackageType),
		strings.TrimSpace(i.Image),
	}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// BatchID returns a deterministic identifier for a batch of images. Images are
// sorted and deduplicated first, so the ID does not depend on the order images were
// scanned or the order they finished in.
func BatchID(images []string) string {
	unique := dedupeSorted(images)
	sum := sha256.Sum256([]byte(strings.Join(unique, "\x00")))
	return hex.EncodeToString(sum[:])
}

func dedupeSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
