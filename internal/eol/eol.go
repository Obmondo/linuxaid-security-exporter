// Package eol exposes OS lifecycle dates sourced from endoflife.date.
//
// Data is refreshed at build time by the generator in ./generator and
// embedded as data.json. Callers look up the three support-phase dates
// (full support, standard EOL, paid extended support) for a detected
// /etc/os-release ID + VERSION_ID.
package eol

import (
	_ "embed"
	"encoding/json"
	"log/slog"
	"strings"
	"time"
)

//go:generate go run ./generator

//go:embed data.json
var rawData []byte

const dateLayout = "2006-01-02"

// Phases holds the three support-phase end dates for a cycle. Any field
// may be the zero time.Time when the phase is unknown or not applicable
// (for example Debian has no "support" phase; Fedora has no extended
// support).
type Phases struct {
	Support  time.Time
	EOL      time.Time
	Extended time.Time
}

// Entry mirrors the on-disk per-cycle record written by the generator.
// Dates are YYYY-MM-DD strings; an empty string means unknown / N/A.
// Exported so the generator package can produce the same shape without
// redefining it.
type Entry struct {
	Cycle    string `json:"cycle"`
	Support  string `json:"support,omitempty"`
	EOL      string `json:"eol,omitempty"`
	Extended string `json:"extended,omitempty"`
}

// productBySlug maps an /etc/os-release ID to the endoflife.date product
// slug used as the key in data.json. Distros the collector does not
// currently accept (e.g. opensuse-leap) are intentionally absent.
// productSLES is the endoflife.date product both SUSE os-release IDs map to.
const productSLES = "sles"

var productBySlug = map[string]string{
	"debian":    "debian",
	"ubuntu":    "ubuntu",
	"rhel":      "rhel",
	"centos":    "centos",
	"rocky":     "rocky-linux",
	"ol":        "oracle-linux",
	"almalinux": "almalinux",
	"fedora":    "fedora",
	"sles":      productSLES,
	"suse":      productSLES,
}

var table map[string][]Entry

func init() {
	if err := json.Unmarshal(rawData, &table); err != nil {
		slog.Warn("embedded EOL data failed to parse; OS EOL metrics will not be emitted", "error", err)
		table = map[string][]Entry{}
		return
	}
	if len(table) == 0 {
		slog.Warn("embedded EOL data is empty; OS EOL metrics will not be emitted — did gen-eol run?")
	}
}

// Lookup returns the support-phase dates for the given /etc/os-release ID
// and VERSION_ID. It first tries an exact cycle match, then falls back to
// the major version (the prefix before the first '.') so RHEL-style
// "9.3" hits the "9" cycle. Returns ok=false if the ID is not mapped, no
// cycle matches, or the cycle has no known dates.
func Lookup(id, version string) (Phases, bool) {
	slug, ok := productBySlug[strings.ToLower(id)]
	if !ok {
		return Phases{}, false
	}
	entries := table[slug]
	if len(entries) == 0 {
		return Phases{}, false
	}

	if e, ok := findCycle(entries, version); ok {
		return toPhases(e), true
	}
	if major, _, dotted := strings.Cut(version, "."); dotted && major != "" {
		if e, ok := findCycle(entries, major); ok {
			return toPhases(e), true
		}
	}
	return Phases{}, false
}

// findCycle returns the entry for an exact cycle match. ok=false when no
// cycle matches or the matched cycle has no known dates.
func findCycle(entries []Entry, cycle string) (Entry, bool) {
	for _, e := range entries {
		if e.Cycle != cycle {
			continue
		}
		if e.Support == "" && e.EOL == "" && e.Extended == "" {
			return Entry{}, false
		}
		return e, true
	}
	return Entry{}, false
}

func toPhases(e Entry) Phases {
	return Phases{
		Support:  parseDate(e.Support),
		EOL:      parseDate(e.EOL),
		Extended: parseDate(e.Extended),
	}
}

func parseDate(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
