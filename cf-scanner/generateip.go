package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
)

// cleanIPListLine strips leading/trailing whitespace and inline or full-line comments
// starting with '#' or '//'. Returns an empty string if the line is empty or a comment.
func cleanIPListLine(raw string) string {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return ""
	}
	if idx := strings.Index(line, "#"); idx != -1 {
		line = strings.TrimSpace(line[:idx])
	}
	if idx := strings.Index(line, "//"); idx != -1 {
		line = strings.TrimSpace(line[:idx])
	}
	return line
}

// parseIPOrPrefix parses a single IP address or a CIDR range string into a canonical netip.Prefix.
// Single IPv4 addresses are converted to /32 and single IPv6 addresses to /128.
// If expectedVersion is 4 or 6, the parsed address is validated against that IP version.
func parseIPOrPrefix(input string, expectedVersion int) (netip.Prefix, error) {
	cleaned := cleanIPListLine(input)
	if cleaned == "" {
		return netip.Prefix{}, fmt.Errorf("empty input")
	}

	var prefix netip.Prefix
	if strings.Contains(cleaned, "/") {
		p, err := netip.ParsePrefix(cleaned)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", cleaned, err)
		}
		addr := p.Addr().Unmap()
		if addr != p.Addr() {
			p = netip.PrefixFrom(addr, p.Bits())
		}
		prefix = p.Masked()
	} else {
		addr, err := netip.ParseAddr(cleaned)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid IP address %q: %w", cleaned, err)
		}
		addr = addr.Unmap()
		if addr.Is4() {
			prefix = netip.PrefixFrom(addr, 32)
		} else if addr.Is6() {
			prefix = netip.PrefixFrom(addr, 128)
		} else {
			return netip.Prefix{}, fmt.Errorf("unsupported IP address %q", cleaned)
		}
	}

	switch expectedVersion {
	case 4:
		if !prefix.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("entry %q is not IPv4 (IpVersion=4)", cleaned)
		}
	case 6:
		if !prefix.Addr().Is6() {
			return netip.Prefix{}, fmt.Errorf("entry %q is not IPv6 (IpVersion=6)", cleaned)
		}
	}

	return prefix, nil
}

// parseRangeList converts a slice of CIDR or single-IP strings (e.g. AllowRange or IgnoreRange)
// into validated netip.Prefix values, logging warnings and skipping invalid entries gracefully.
func parseRangeList(ranges []string, expectedVersion int) []netip.Prefix {
	if len(ranges) == 0 {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, len(ranges))
	for _, raw := range ranges {
		cleaned := cleanIPListLine(raw)
		if cleaned == "" {
			continue
		}
		p, err := parseIPOrPrefix(cleaned, expectedVersion)
		if err != nil {
			log.Printf("Warning: skipping invalid range entry %q: %v", raw, err)
			continue
		}
		prefixes = append(prefixes, p)
	}
	return prefixes
}

// isIPAllowed checks whether an IP address passes ignorePrefixes and allowPrefixes filters.
func isIPAllowed(addr netip.Addr, ignorePrefixes []netip.Prefix, allowPrefixes []netip.Prefix) bool {
	for _, ig := range ignorePrefixes {
		if ig.Contains(addr) {
			return false
		}
	}
	if len(allowPrefixes) > 0 {
		allowed := false
		for _, al := range allowPrefixes {
			if al.Contains(addr) {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}
	return true
}

func appendIPsFromPrefix(ips *[]string, prefix netip.Prefix, ignorePrefixes []netip.Prefix, allowPrefixes []netip.Prefix) {
	// Fast path: if any ignorePrefix completely covers prefix, skip immediately.
	for _, ig := range ignorePrefixes {
		if ig.Bits() <= prefix.Bits() && ig.Overlaps(prefix) {
			return
		}
	}

	// Fast path: if allowPrefixes is non-empty and none overlap prefix, skip immediately.
	if len(allowPrefixes) > 0 {
		anyOverlap := false
		for _, al := range allowPrefixes {
			if al.Overlaps(prefix) {
				anyOverlap = true
				break
			}
		}
		if !anyOverlap {
			return
		}
	}

	// Iterate over all addresses in prefix (including single IPs /32 and /128 without dropping network/broadcast).
	for ip := prefix.Addr(); prefix.Contains(ip); ip = ip.Next() {
		if isIPAllowed(ip, ignorePrefixes, allowPrefixes) {
			*ips = append(*ips, ip.String())
		}
	}
}

func GenIPsFromCIDR(ips *[]string, netCIDR string, subnetMaskSize int, ignoreRange []string, allowRange []string) {
	cleaned := cleanIPListLine(netCIDR)
	if cleaned == "" {
		return
	}

	expectedVersion := 4
	if subnetMaskSize == 128 {
		expectedVersion = 6
	}

	prefix, err := parseIPOrPrefix(cleaned, expectedVersion)
	if err != nil {
		log.Printf("Warning: skipping invalid IP/CIDR entry %q: %v", strings.TrimSpace(netCIDR), err)
		return
	}

	ignorePrefixes := parseRangeList(ignoreRange, expectedVersion)
	allowPrefixes := parseRangeList(allowRange, expectedVersion)
	appendIPsFromPrefix(ips, prefix, ignorePrefixes, allowPrefixes)
}

func GenIPs(ips *[]string, ipv4FilePath string, ignoreRange []string, allowRange []string) {
	file, ipListFileErr := os.ReadFile(ipv4FilePath)
	if ipListFileErr != nil {
		log.Fatalln(ipListFileErr)
	}

	ignorePrefixes := parseRangeList(ignoreRange, 4)
	allowPrefixes := parseRangeList(allowRange, 4)

	for rawLine := range strings.Lines(string(file)) {
		cleaned := cleanIPListLine(rawLine)
		if cleaned == "" {
			continue
		}
		prefix, err := parseIPOrPrefix(cleaned, 4)
		if err != nil {
			log.Printf("Warning: skipping invalid IPv4/CIDR line %q: %v", strings.TrimSpace(rawLine), err)
			continue
		}
		appendIPsFromPrefix(ips, prefix, ignorePrefixes, allowPrefixes)
	}
}

// LoadIPv6Entries loads IPv6 single IPs and CIDR ranges from ipv6FilePath,
// validating against IpVersion=6, ignoring empty/comment lines, warning on malformed lines,
// and applying IgnoreRange and AllowRange filters.
// It also returns allSingleIPs=true when every valid entry is a /128 single IPv6 address.
func LoadIPv6Entries(entries *[]string, ipv6FilePath string, ignoreRange []string, allowRange []string) (allSingleIPs bool) {
	file, ipListFileErr := os.ReadFile(ipv6FilePath)
	if ipListFileErr != nil {
		log.Fatalln(ipListFileErr)
	}

	ignorePrefixes := parseRangeList(ignoreRange, 6)
	allowPrefixes := parseRangeList(allowRange, 6)

	allSingleIPs = true
	for rawLine := range strings.Lines(string(file)) {
		cleaned := cleanIPListLine(rawLine)
		if cleaned == "" {
			continue
		}
		prefix, err := parseIPOrPrefix(cleaned, 6)
		if err != nil {
			log.Printf("Warning: skipping invalid IPv6/CIDR line %q: %v", strings.TrimSpace(rawLine), err)
			continue
		}

		// Check if completely covered by any ignorePrefix
		ignored := false
		for _, ig := range ignorePrefixes {
			if ig.Bits() <= prefix.Bits() && ig.Overlaps(prefix) {
				ignored = true
				break
			}
		}
		if ignored {
			continue
		}

		// Check if overlaps at least one allowPrefix when allowPrefixes is non-empty
		if len(allowPrefixes) > 0 {
			overlapsAllow := false
			for _, al := range allowPrefixes {
				if al.Overlaps(prefix) {
					overlapsAllow = true
					break
				}
			}
			if !overlapsAllow {
				continue
			}
		}

		if prefix.Bits() == 128 {
			*entries = append(*entries, prefix.Addr().String())
		} else {
			allSingleIPs = false
			*entries = append(*entries, prefix.String())
		}
	}

	if len(*entries) == 0 {
		allSingleIPs = false
	}
	return allSingleIPs
}

func randomIPv6FromCIDR(cidr string) (net.IP, error) {
	prefix, err := parseIPOrPrefix(cidr, 6)
	if err != nil {
		return nil, err
	}

	addr := prefix.Addr()
	raw16 := addr.As16()
	ip := net.IP(raw16[:])

	prefixLen := prefix.Bits()
	totalBits := 128
	variableBits := totalBits - prefixLen

	if variableBits <= 0 {
		return ip, nil
	}

	// Generate a random number for the variable part
	max := new(big.Int).Lsh(big.NewInt(1), uint(variableBits))
	randNum, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}

	ipInt := new(big.Int).SetBytes(ip)
	ipInt.Or(ipInt, randNum)

	// Convert back to net.IP
	randomIP := make(net.IP, 16)
	ipInt.FillBytes(randomIP)

	return randomIP, nil
}
