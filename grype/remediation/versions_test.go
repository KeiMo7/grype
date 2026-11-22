package remediation

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/grype/grype/version"
)

func TestReleaseLine(t *testing.T) {
	cases := []struct {
		raw    string
		format version.Format
		want   string
	}{
		{"1.2.3", version.SemanticFormat, "1.2"},
		{"1.2", version.SemanticFormat, "1"},
		{"5", version.SemanticFormat, ""},
		{"v1.2.3", version.GolangFormat, "v1.2"},
		{"1.2.3+build.5", version.SemanticFormat, "1.2"},
		{"1.2.3-rc.1", version.SemanticFormat, "1.2"},
		{"1.2.3-4", version.DebFormat, "1.2"},
		{"2:1.2.3-4", version.DebFormat, "1.2"},
		{"1.2.3+dfsg-1", version.DebFormat, "1.2"}, // deb upstreams may legitimately contain "+"
		{"1.2.3-4.el8", version.RpmFormat, "1.2"},
		{"1:2.4.6-8.el9", version.RpmFormat, "2.4"},
		{"1.2.3-r4", version.ApkFormat, "1.2"},
		{"1.2.3.4", version.PythonFormat, "1.2.3"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			assert.Equal(t, tc.want, releaseLine(tc.raw, tc.format))
		})
	}
}

func TestSameReleaseLine(t *testing.T) {
	cases := []struct {
		name   string
		fix    string
		target string
		format version.Format
		want   bool
	}{
		{"same line", "1.2.3", "1.2.10", version.SemanticFormat, true},
		{"next minor is another line", "1.2.3", "1.3.0", version.SemanticFormat, false},
		{"next major is another line", "1.2.3", "2.0.0", version.SemanticFormat, false},
		{"single component fix covers all later", "5", "7.1", version.SemanticFormat, true},
		{"short fix line covers nested target", "1.2", "1.2.3.4", version.SemanticFormat, true},
		{"deeper fix line does not cover shallower target", "1.2.3.4", "1.2.9", version.SemanticFormat, false},
		{"deb revisions share a line", "1.2.3-4", "1.2.3-9", version.DebFormat, true},
		{"deb next upstream revision shares line", "1.2.3-4", "1.2.4-1", version.DebFormat, true},
		{"deb next minor is another line", "1.2.3-4", "1.3.0-1", version.DebFormat, false},
		{"rpm release shares a line", "1.2.3-1.el8", "1.2.3-9.el8", version.RpmFormat, true},
		{"rpm next minor is another line", "1.2.3-1.el8", "1.3.0-1.el8", version.RpmFormat, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sameReleaseLine(tc.fix, tc.target, tc.format))
		})
	}
}

func TestIsPrerelease(t *testing.T) {
	assert.True(t, isPrerelease("1.2.3-rc.1", version.SemanticFormat))
	assert.True(t, isPrerelease("v1.2.3-beta", version.GolangFormat))
	assert.False(t, isPrerelease("1.2.3", version.SemanticFormat))
	// for deb/rpm/apk a "-" introduces a distro revision, not a pre-release
	assert.False(t, isPrerelease("1.2.3-4", version.DebFormat))
	assert.False(t, isPrerelease("1.2.3-4.el8", version.RpmFormat))
	assert.False(t, isPrerelease("1.2.3-r1", version.ApkFormat))
}

func TestHasBuildMetadata(t *testing.T) {
	assert.True(t, hasBuildMetadata("1.2.3+build.5", version.SemanticFormat))
	assert.False(t, hasBuildMetadata("1.2.3", version.SemanticFormat))
	// "+" in a deb upstream is not build metadata
	assert.False(t, hasBuildMetadata("1.2.3+dfsg-1", version.DebFormat))
}
