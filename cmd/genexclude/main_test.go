package main

import (
	"net"
	"reflect"
	"testing"
)

func TestRangeToCIDRs(t *testing.T) {
	tests := []struct {
		name  string
		start string
		end   string
		want  []string
	}{
		{"exact /8", "6.0.0.0", "6.255.255.255", []string{"6.0.0.0/8"}},
		{"single address", "1.2.3.4", "1.2.3.4", []string{"1.2.3.4/32"}},
		{"two adjacent /8s collapse to /7", "28.0.0.0", "29.255.255.255", []string{"28.0.0.0/7"}},
		{"unaligned range splits", "1.0.0.1", "1.0.0.6", []string{
			"1.0.0.1/32", "1.0.0.2/31", "1.0.0.4/31", "1.0.0.6/32",
		}},
		{"top of address space terminates", "255.255.255.252", "255.255.255.255", []string{"255.255.255.252/30"}},
		{"whole space", "0.0.0.0", "255.255.255.255", []string{"0.0.0.0/0"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := rangeToCIDRs(ipRange{
				start: toUint32(net.ParseIP(tc.start)),
				end:   toUint32(net.ParseIP(tc.end)),
			})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rangeToCIDRs(%s-%s) = %v, want %v", tc.start, tc.end, got, tc.want)
			}
		})
	}
}

func TestCoalesce(t *testing.T) {
	r := func(start, end string) ipRange {
		return ipRange{start: toUint32(net.ParseIP(start)), end: toUint32(net.ParseIP(end))}
	}

	tests := []struct {
		name string
		in   []ipRange
		want []string
	}{
		{"empty", nil, nil},
		{
			// Two /16s that touch must become one /15, not two entries.
			name: "adjacent ranges merge",
			in:   []ipRange{r("132.0.0.0", "132.0.255.255"), r("132.1.0.0", "132.1.255.255")},
			want: []string{"132.0.0.0/15"},
		},
		{
			name: "input order does not matter",
			in:   []ipRange{r("132.1.0.0", "132.1.255.255"), r("132.0.0.0", "132.0.255.255")},
			want: []string{"132.0.0.0/15"},
		},
		{
			name: "overlapping ranges merge",
			in:   []ipRange{r("10.0.0.0", "10.0.255.255"), r("10.0.128.0", "10.1.255.255")},
			want: []string{"10.0.0.0/15"},
		},
		{
			name: "fully contained range is absorbed",
			in:   []ipRange{r("10.0.0.0", "10.255.255.255"), r("10.1.0.0", "10.1.0.255")},
			want: []string{"10.0.0.0/8"},
		},
		{
			// A one-address gap must NOT be bridged: coalescing may only ever
			// widen exclusions across contiguous space, never invent coverage.
			name: "disjoint ranges stay separate",
			in:   []ipRange{r("10.0.0.0", "10.0.0.0"), r("10.0.0.2", "10.0.0.2")},
			want: []string{"10.0.0.0/32", "10.0.0.2/32"},
		},
		{
			name: "range ending at broadcast does not wrap",
			in:   []ipRange{r("255.255.255.255", "255.255.255.255")},
			want: []string{"255.255.255.255/32"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := coalesce(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("coalesce() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCoalescePreservesCoverage asserts the property that actually matters for
// safety: every address in the input must still be covered by the output.
func TestCoalescePreservesCoverage(t *testing.T) {
	in := []ipRange{
		{start: 0x0A000000, end: 0x0A00FFFF},
		{start: 0x0A020000, end: 0x0A02FFFF},
		{start: 0x84190000, end: 0x8419FFFF},
		{start: 0x84190080, end: 0x841900FF},
		{start: 0xFFFFFFFF, end: 0xFFFFFFFF},
	}
	var nets []*net.IPNet
	for _, c := range coalesce(in) {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("coalesce produced unparseable CIDR %q: %v", c, err)
		}
		nets = append(nets, n)
	}

	for _, r := range in {
		for _, v := range []uint32{r.start, r.start + (r.end-r.start)/2, r.end} {
			ip := net.ParseIP(fromUint32(v))
			var covered bool
			for _, n := range nets {
				if n.Contains(ip) {
					covered = true
					break
				}
			}
			if !covered {
				t.Fatalf("address %s from range %s-%s lost during coalescing",
					ip, fromUint32(r.start), fromUint32(r.end))
			}
		}
	}
}

func TestCategoryMatching(t *testing.T) {
	catFor := func(org string) string {
		if falsePositives.MatchString(org) {
			return ""
		}
		for _, c := range categories {
			if c.match.MatchString(org) {
				return c.key
			}
		}
		return ""
	}

	tests := []struct {
		org  string
		want string
	}{
		{"United States Department of Defense DoD", "military"},
		{"Navy Network Information Center NNIC", "military"},
		{"Air Force Systems Networking", "military"},
		{"Institute for Defense Analyses", "military"},
		{"Defence Science and Technology Laboratory", "military"},
		{"UK Ministry of Defence", "military"},
		{"NATO Communications and Information Agency", "military"},
		// Military must win over government for orgs matching both.
		{"Ministry of Defence", "military"},

		{"U.S. Department of the Interior", "government"},
		{"U.S. House of Representatives", "government"},
		{"Federal Aviation Administration", "government"},
		{"State of Wyoming Department A&I", "government"},
		{"California Department of Technology", "government"},
		{"KIFU (Governmental Info Tech Development Agency)", "government"},
		{"The City of New York", "government"},
		{"The Governors Office of Information Technology", "government"},
		{"Companhia de Governanca Eletronica do Salvador", "government"},
		{"Jeju Special Self Governing Provincial office of Education", "government"},

		// Law enforcement.
		{"New York City Police Department", "government"},
		{"Baltimore City Police Department", "government"},
		{"Rhode Island State Police", "government"},
		{"European Police Office (EuroPol)", "government"},
		{"Philippine National Police", "government"},
		{"New South Wales Police", "government"},
		{"Halton Regional Police Service", "government"},
		// Underscore-delimited names have no word boundary around POLICE.
		{"KENYA_NATIONAL_POLICE_DT_SACCO", "government"},
		// Neither does a name with a missing space before "Ministry".
		{"CPV DivisionMinistry of External Affairs", "government"},

		{"Hetzner Online GmbH", "selfhost"},

		// Known false positives must not be excluded.
		{"Mod Mission Critical LLC", ""},
		{"Federal Express Corporation", ""},

		// Ordinary commercial networks must stay in scope, or we have no scan.
		{"Cloudflare, Inc.", ""},
		{"Amazon.com, Inc.", ""},
		{"DigitalOcean, LLC", ""},
		{"OVH SAS", ""},
		{"Comcast Cable Communications, LLC", ""},
		{"Deutsche Telekom AG", ""},
		{"China Mobile Communications Corporation", ""},
	}

	for _, tc := range tests {
		if got := catFor(tc.org); got != tc.want {
			t.Errorf("category for %q = %q, want %q", tc.org, got, tc.want)
		}
	}
}

func TestToRangeRejectsIPv6(t *testing.T) {
	_, n, err := net.ParseCIDR("2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := toRange(n); ok {
		t.Fatal("expected toRange to reject an IPv6 network")
	}
}

func TestToRangeIPv4(t *testing.T) {
	_, n, err := net.ParseCIDR("128.25.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	r, ok := toRange(n)
	if !ok {
		t.Fatal("expected toRange to accept an IPv4 network")
	}
	if want := toUint32(net.ParseIP("128.25.0.0")); r.start != want {
		t.Fatalf("start = %d, want %d", r.start, want)
	}
	if want := toUint32(net.ParseIP("128.25.255.255")); r.end != want {
		t.Fatalf("end = %d, want %d", r.end, want)
	}
}
