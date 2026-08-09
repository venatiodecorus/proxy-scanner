// Command genexclude generates masscan CIDR exclusion lists from the MaxMind
// GeoLite2 ASN database.
//
// The hand-maintained lists under config/exclude/ can only realistically cover
// whole /8 allocations. That is not enough: the US DoD alone announces ~1000
// prefixes, the bulk of them /16s and smaller scattered through 128.0.0.0/3
// (128.19/16, 130.22/16, 132.79/16, 143.77/16, 160.127/16, ...). Scanning those
// is exactly the outcome the exclusion lists exist to prevent, so we derive the
// full set from ASN organisation names instead of curating it by hand.
//
// Usage:
//
//	go run ./cmd/genexclude                     # regenerate config/exclude/*-asn.conf
//	go run ./cmd/genexclude -list-orgs military  # audit which orgs matched
//
// The generated files are committed to the repo so that image builds stay
// hermetic and the diff is reviewable. Regenerate whenever data/GeoLite2-ASN.mmdb
// is refreshed.
//
// Output is derived from MaxMind GeoLite2 data, which is distributed under
// CC BY-SA 4.0. See https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// category is one generated exclusion file: a regexp over ASN organisation
// names plus the prose that explains why those networks are off limits.
type category struct {
	key       string
	filename  string
	title     string
	rationale []string
	match     *regexp.Regexp
}

// falsePositives are organisation names that match a category regexp but are
// not actually the kind of network we mean to exclude. Over-exclusion is cheap
// (we merely lose proxy candidates), so this list stays deliberately short and
// only covers matches that are unambiguously commercial.
var falsePositives = regexp.MustCompile(`(?i)(mod mission critical|federal express|\bfedex\b)`)

// categories are evaluated in order and the first match wins, so an
// organisation like "Ministry of Defence" lands in military rather than
// government.
var categories = []category{
	{
		key:      "military",
		filename: "11-military-asn.conf",
		title:    "Military / Defense Networks (generated from ASN organisation names)",
		rationale: []string{
			"Every network whose announcing ASN is registered to a military or",
			"defense organisation. This covers the hundreds of DoD, Air Force,",
			"Navy and allied-military prefixes that fall outside the legacy /8",
			"allocations listed in 10-military.conf.",
			"",
			"Scanning these ranges is the single fastest way to attract federal",
			"attention. Do not narrow this list.",
		},
		match: regexp.MustCompile(`(?i)(\b(dod|dnic|disa|nato|usaf|pentagon)\b` +
			`|\bdefen[cs]e\b|\bdefensa\b|\bd(e|é)fense\b|\bverteidigung\b` +
			`|\barmy\b|\barmee\b|\barm(e|é)e\b|\bnavy\b|\bnaval\b` +
			`|\bair ?force\b|\bmarine corps\b|\bmilitar|\bmilit(a|ä)r` +
			`|\bjoint chiefs\b|ministry of defen)`),
	},
	{
		key:      "government",
		filename: "12-government-asn.conf",
		title:    "Government Networks (generated from ASN organisation names)",
		rationale: []string{
			"Federal, state, municipal and foreign government networks, plus law",
			"enforcement and intelligence agencies. These are low-value targets",
			"for open-proxy discovery and high-risk from an abuse-complaint and",
			"legal standpoint.",
			"",
			"The organisation-name match is intentionally broad. It will exclude",
			"some commercial networks whose names merely look governmental; the",
			"only cost of a false positive is a proxy candidate we never see.",
		},
		// Several patterns here deliberately omit a leading \b: real ASN
		// organisation names arrive as "KENYA_NATIONAL_POLICE_DT_SACCO" and
		// "CPV DivisionMinistry of External Affairs", where the interesting word
		// is not at a word boundary at all.
		match: regexp.MustCompile(`(?i)(\bgovern` +
			`|\bgov\b|\bgouv\b|\be-gov` +
			`|\bfederal\b|minist(ry|ry of|erio|(e|è)re)\b|\bparliament\b|\bembassy\b` +
			`|\bsenate\b|house of represent|\bnasa\b|\bfbi\b|\bnsa\b|\bcia\b` +
			`|national security|intelligence agency|law enforcement` +
			`|bureau of |department of |\bstate of \b|commonwealth of ` +
			`|\bcounty of \b|\bcity of \b|\bmunicipal|\bprefecture\b` +
			// Law enforcement. Police networks are among the worst possible
			// things to appear in a scan log, and they are almost never covered
			// by the "government"/"department of" phrasings above.
			`|police|\bpolic(ia|ía|ie)\b|\bpolizei\b|\bpolitie\b|\bpolis\b` +
			`|\bsheriff|\bconstabular|\bgendarmerie\b|\bcarabinieri\b` +
			`|\beuropol\b|\binterpol\b|\bguardia civil\b` +
			`|\bjudiciar|\bjudicial\b|\bpenitentiar|\bcustoms\b)`),
	},
	{
		key:      "selfhost",
		filename: "21-selfhost-asn.conf",
		title:    "Hosting Provider Self-Exclusion (generated from ASN organisation names)",
		rationale: []string{
			"Every prefix announced by our own hosting provider. Scanning from",
			"inside a provider's network into that same network is both pointless",
			"(we would be scanning ourselves and our immediate neighbours) and the",
			"most likely single cause of an abuse suspension.",
			"",
			"This supersedes the hand-maintained supernet list in",
			"20-cloud-providers.conf, which only approximated the allocation.",
		},
		match: regexp.MustCompile(`(?i)\bhetzner\b`),
	},
}

// asnRecord is the subset of the GeoLite2 ASN record we need.
type asnRecord struct {
	ASN int    `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

// ipRange is a closed IPv4 range in host byte order.
type ipRange struct {
	start, end uint32
}

func main() {
	dbPath := flag.String("asn-db", filepath.Join("data", "GeoLite2-ASN.mmdb"), "path to GeoLite2-ASN.mmdb")
	outDir := flag.String("out-dir", filepath.Join("config", "exclude"), "directory to write generated .conf files into")
	listOrgs := flag.String("list-orgs", "", "print matched organisations for a category (military|government|selfhost) and exit without writing files")
	flag.Parse()

	if err := run(*dbPath, *outDir, *listOrgs); err != nil {
		fmt.Fprintln(os.Stderr, "genexclude:", err)
		os.Exit(1)
	}
}

func run(dbPath, outDir, listOrgs string) error {
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return fmt.Errorf("opening ASN database: %w", err)
	}
	defer db.Close()

	// Networks per category, and the set of organisations that produced them so
	// the generated header can be audited.
	ranges := make(map[string][]ipRange, len(categories))
	orgs := make(map[string]map[string]struct{}, len(categories))
	for _, c := range categories {
		orgs[c.key] = map[string]struct{}{}
	}

	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var rec asnRecord
		network, err := networks.Network(&rec)
		if err != nil {
			return fmt.Errorf("decoding ASN record: %w", err)
		}
		// IPv4 only: masscan is invoked against 0.0.0.0/0.
		if network.IP.To4() == nil {
			continue
		}
		if rec.Org == "" || falsePositives.MatchString(rec.Org) {
			continue
		}
		for _, c := range categories {
			if !c.match.MatchString(rec.Org) {
				continue
			}
			r, ok := toRange(network)
			if !ok {
				break
			}
			ranges[c.key] = append(ranges[c.key], r)
			orgs[c.key][fmt.Sprintf("AS%d %s", rec.ASN, rec.Org)] = struct{}{}
			break // first matching category wins
		}
	}
	if err := networks.Err(); err != nil {
		return fmt.Errorf("iterating ASN database: %w", err)
	}

	if listOrgs != "" {
		found := false
		for _, c := range categories {
			if c.key != listOrgs {
				continue
			}
			found = true
			names := sortedKeys(orgs[c.key])
			for _, n := range names {
				fmt.Println(n)
			}
			fmt.Fprintf(os.Stderr, "%d organisations matched category %q\n", len(names), c.key)
		}
		if !found {
			return fmt.Errorf("unknown category %q", listOrgs)
		}
		return nil
	}

	dbBuilt := time.Unix(int64(db.Metadata.BuildEpoch), 0).UTC().Format("2006-01-02")

	for _, c := range categories {
		cidrs := coalesce(ranges[c.key])
		path := filepath.Join(outDir, c.filename)
		if err := writeConf(path, c, cidrs, len(orgs[c.key]), dbBuilt, filepath.Base(dbPath)); err != nil {
			return err
		}
		fmt.Printf("%-28s %6d CIDRs  %6d orgs  %11d addresses\n",
			c.filename, len(cidrs), len(orgs[c.key]), countAddresses(ranges[c.key]))
	}
	return nil
}

// toRange converts an *net.IPNet to a closed uint32 range, reporting false for
// anything that is not a well-formed IPv4 network.
func toRange(n *net.IPNet) (ipRange, bool) {
	ip := n.IP.To4()
	if ip == nil {
		return ipRange{}, false
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		// A /0-sized mask or an IPv6-shaped mask on an IPv4 address.
		if _, b := net.IPMask(n.Mask[len(n.Mask)-4:]).Size(); b != 32 {
			return ipRange{}, false
		}
		ones, bits = net.IPMask(n.Mask[len(n.Mask)-4:]).Size()
	}
	start := toUint32(ip)
	size := uint64(1) << uint(bits-ones)
	return ipRange{start: start, end: uint32(uint64(start) + size - 1)}, true
}

// coalesce sorts, merges overlapping and adjacent ranges, and re-expands the
// result into the minimal set of CIDRs. This keeps the generated files an order
// of magnitude smaller than the raw per-ASN network list and makes diffs
// between regenerations readable.
func coalesce(in []ipRange) []string {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].start != in[j].start {
			return in[i].start < in[j].start
		}
		return in[i].end < in[j].end
	})

	merged := []ipRange{in[0]}
	for _, r := range in[1:] {
		last := &merged[len(merged)-1]
		// Adjacent counts as overlapping: end+1 == start. Guard the +1 against
		// wrapping at 255.255.255.255.
		if r.start <= last.end || (last.end != ^uint32(0) && r.start == last.end+1) {
			if r.end > last.end {
				last.end = r.end
			}
			continue
		}
		merged = append(merged, r)
	}

	var out []string
	for _, r := range merged {
		out = append(out, rangeToCIDRs(r)...)
	}
	return out
}

// rangeToCIDRs expands a closed range into the minimal covering set of CIDRs.
func rangeToCIDRs(r ipRange) []string {
	var out []string
	start, end := uint64(r.start), uint64(r.end)
	for start <= end {
		// Largest block that is aligned at start and does not overrun end.
		prefix := 0
		for prefix = 0; prefix < 32; prefix++ {
			size := uint64(1) << uint(32-prefix)
			if start%size == 0 && start+size-1 <= end {
				break
			}
		}
		out = append(out, fmt.Sprintf("%s/%d", fromUint32(uint32(start)), prefix))
		start += uint64(1) << uint(32-prefix)
	}
	return out
}

func writeConf(path string, c category, cidrs []string, orgCount int, dbBuilt, dbName string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	line := strings.Repeat("=", 76)
	fmt.Fprintf(w, "# %s\n", line)
	fmt.Fprintf(w, "# %s\n", c.title)
	fmt.Fprintf(w, "# %s\n", line)
	fmt.Fprintln(w, "#")
	fmt.Fprintln(w, "# DO NOT EDIT BY HAND. Regenerate with:")
	fmt.Fprintln(w, "#   go run ./cmd/genexclude")
	fmt.Fprintln(w, "#")
	fmt.Fprintf(w, "# Audit which organisations matched:\n")
	fmt.Fprintf(w, "#   go run ./cmd/genexclude -list-orgs %s\n", c.key)
	fmt.Fprintln(w, "#")
	for _, l := range c.rationale {
		if l == "" {
			fmt.Fprintln(w, "#")
			continue
		}
		fmt.Fprintf(w, "# %s\n", l)
	}
	fmt.Fprintln(w, "#")
	fmt.Fprintf(w, "# Source:        MaxMind %s (database build %s)\n", dbName, dbBuilt)
	fmt.Fprintf(w, "# Organisations: %d\n", orgCount)
	fmt.Fprintf(w, "# CIDRs:         %d (adjacent ranges coalesced)\n", len(cidrs))
	fmt.Fprintf(w, "# Addresses:     %d\n", countCIDRAddresses(cidrs))
	fmt.Fprintln(w, "#")
	fmt.Fprintln(w, "# GeoLite2 data is distributed by MaxMind under CC BY-SA 4.0.")
	fmt.Fprintf(w, "# %s\n", line)
	fmt.Fprintln(w)
	for _, c := range cidrs {
		fmt.Fprintln(w, c)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func countAddresses(rs []ipRange) uint64 {
	var total uint64
	for _, r := range rs {
		total += uint64(r.end) - uint64(r.start) + 1
	}
	return total
}

func countCIDRAddresses(cidrs []string) uint64 {
	var total uint64
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			continue
		}
		ones, bits := n.Mask.Size()
		total += uint64(1) << uint(bits-ones)
	}
	return total
}

func toUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func fromUint32(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
