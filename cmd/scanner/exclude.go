package main

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
)

// The scanner always targets 0.0.0.0/0, so the exclusion file is the only thing
// standing between us and scanning military, government and critical
// infrastructure networks. masscan's own safety net is weak — it only insists
// that *at least one* exclude is present for a large target range — so we
// validate the file ourselves and refuse to start if it looks wrong.
//
// This is deliberately fail-closed: a missing, truncated, or wrong-path
// exclusion file aborts the scan rather than silently sweeping the whole
// internet.

// minExcludeEntries is the floor for a plausible exclusion file. The committed
// list (IANA special-purpose + military /8s + generated military/government/
// self-host ASN lists + infrastructure) is several thousand entries, so a file
// with fewer than this has almost certainly failed to merge correctly.
const minExcludeEntries = 2000

// excludeCanaries are addresses that MUST be covered by the exclusion file.
// Each one is drawn from a different fragment under config/exclude/, so a
// missing or unmerged fragment is caught rather than assumed present.
var excludeCanaries = []canary{
	{ip: "10.0.0.1", why: "RFC1918 private-use (00-iana-special.conf)"},
	{ip: "127.0.0.1", why: "loopback (00-iana-special.conf)"},
	{ip: "6.1.2.3", why: "US Army Information Systems Center /8 (10-military.conf)"},
	{ip: "214.5.6.7", why: "US-DOD /8 (10-military.conf)"},
	{ip: "25.9.8.7", why: "UK Ministry of Defence /8 (10-military.conf)"},
	{ip: "128.25.4.5", why: "US DoD sub-/8 prefix (11-military-asn.conf)"},
	{ip: "160.127.4.5", why: "Navy Network Information Center (11-military-asn.conf)"},
	{ip: "128.202.4.5", why: "Air Force Systems Networking (11-military-asn.conf)"},
	{ip: "74.119.128.5", why: "US House of Representatives (12-government-asn.conf)"},
	{ip: "162.58.4.5", why: "Federal Aviation Administration (12-government-asn.conf)"},
	{ip: "5.9.4.5", why: "our own hosting provider (21-selfhost-asn.conf)"},
	{ip: "198.41.0.4", why: "a.root-servers.net (30-infrastructure.conf)"},
}

type canary struct {
	ip  string
	why string
}

// validateExcludeFile parses the masscan exclusion file and verifies it is
// substantial enough and actually covers every canary address. It returns an
// error — aborting the scan — if anything is off.
func validateExcludeFile(path string, logger *slog.Logger) error {
	nets, malformed, err := parseExcludeFile(path)
	if err != nil {
		return err
	}

	if len(malformed) > 0 {
		// masscan would reject these too, and a malformed line usually means the
		// build-time merge mangled the file. Don't guess.
		return fmt.Errorf("exclude file %s has %d unparseable entries (first: %q)",
			path, len(malformed), malformed[0])
	}

	if len(nets) < minExcludeEntries {
		return fmt.Errorf("exclude file %s has only %d entries, expected at least %d — "+
			"refusing to scan 0.0.0.0/0 with an incomplete exclusion list",
			path, len(nets), minExcludeEntries)
	}

	var missing []canary
	for _, c := range excludeCanaries {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			// Programmer error in the canary table itself.
			return fmt.Errorf("invalid canary address %q", c.ip)
		}
		if !covers(nets, ip) {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		var b strings.Builder
		for _, c := range missing {
			fmt.Fprintf(&b, "\n  %s — %s", c.ip, c.why)
		}
		return fmt.Errorf("exclude file %s does not cover %d canary address(es), "+
			"so at least one exclusion fragment is missing:%s",
			path, len(missing), b.String())
	}

	logger.Info("exclude file validated",
		"file", path,
		"entries", len(nets),
		"excluded_addresses", countAddresses(nets),
		"canaries_checked", len(excludeCanaries),
	)
	return nil
}

// parseExcludeFile reads a masscan-style exclusion file: one CIDR or bare IP per
// line, `#` comments and blank lines ignored. It returns the parsed networks and
// any lines it could not parse.
func parseExcludeFile(path string) (nets []*net.IPNet, malformed []string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("opening exclude file %s: %w", path, err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.Contains(line, "/") {
			// A bare address is a valid masscan exclude; normalise it to a /32.
			if ip := net.ParseIP(line); ip != nil && ip.To4() != nil {
				line += "/32"
			}
		}
		_, n, parseErr := net.ParseCIDR(line)
		if parseErr != nil {
			malformed = append(malformed, line)
			continue
		}
		nets = append(nets, n)
	}
	if err := s.Err(); err != nil {
		return nil, nil, fmt.Errorf("reading exclude file %s: %w", path, err)
	}
	return nets, malformed, nil
}

func covers(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// countAddresses sums the sizes of the excluded networks. Overlapping entries
// are counted more than once, so this is a rough scale indicator for logging,
// not an exact total.
func countAddresses(nets []*net.IPNet) uint64 {
	var total uint64
	for _, n := range nets {
		ones, bits := n.Mask.Size()
		if bits == 0 {
			continue
		}
		total += uint64(1) << uint(bits-ones)
	}
	return total
}
