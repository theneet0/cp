package scanner

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
)

type IPPreviewEntry struct {
	Raw           string `json:"raw"`
	Cleaned       string `json:"cleaned"`
	CanonicalCIDR string `json:"canonicalCidr"`
	IsSingleIP    bool   `json:"isSingleIp"`
	PrefixBits    int    `json:"prefixBits"`
	HostCount     int64  `json:"hostCount"`
}

type IPPreviewResult struct {
	Entries        []IPPreviewEntry `json:"entries"`
	TotalTargets   int              `json:"totalTargets"`
	SampleTargets  []string         `json:"sampleTargets"`
	Warnings       []string         `json:"warnings"`
	SkippedLines   int              `json:"skippedLines"`
	AllSingleIPv6  bool             `json:"allSingleIpv6"`
}

// CleanIPListLine strips leading/trailing whitespace and inline or full-line comments
// starting with '#' or '//'. Returns an empty string if the line is empty or a comment.
func CleanIPListLine(raw string) string {
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

// ParseIPOrPrefix parses a single IP address or a CIDR range string into a canonical netip.Prefix.
// Single IPv4 addresses are converted to /32 and single IPv6 addresses to /128.
// If expectedVersion is 4 or 6, the parsed address is validated against that IP version.
func ParseIPOrPrefix(input string, expectedVersion int) (netip.Prefix, error) {
	cleaned := CleanIPListLine(input)
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

func ParseRangeList(ranges []string, expectedVersion int, warnFn func(string)) []netip.Prefix {
	if len(ranges) == 0 {
		return nil
	}
	prefixes := make([]netip.Prefix, 0, len(ranges))
	for _, raw := range ranges {
		cleaned := CleanIPListLine(raw)
		if cleaned == "" {
			continue
		}
		p, err := ParseIPOrPrefix(cleaned, expectedVersion)
		if err != nil {
			if warnFn != nil {
				warnFn(fmt.Sprintf("Skipping invalid range entry %q: %v", strings.TrimSpace(raw), err))
			}
			continue
		}
		prefixes = append(prefixes, p)
	}
	return prefixes
}

func IsIPAllowed(addr netip.Addr, ignorePrefixes []netip.Prefix, allowPrefixes []netip.Prefix) bool {
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

func AppendIPsFromPrefix(ips *[]string, prefix netip.Prefix, ignorePrefixes []netip.Prefix, allowPrefixes []netip.Prefix) {
	for _, ig := range ignorePrefixes {
		if ig.Bits() <= prefix.Bits() && ig.Overlaps(prefix) {
			return
		}
	}

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

	for ip := prefix.Addr(); prefix.Contains(ip); ip = ip.Next() {
		if IsIPAllowed(ip, ignorePrefixes, allowPrefixes) {
			*ips = append(*ips, ip.String())
		}
	}
}

func GenIPsFromCIDR(ips *[]string, netCIDR string, subnetMaskSize int, ignoreRange []string, allowRange []string, warnFn func(string)) {
	cleaned := CleanIPListLine(netCIDR)
	if cleaned == "" {
		return
	}

	expectedVersion := 4
	if subnetMaskSize == 128 {
		expectedVersion = 6
	}

	prefix, err := ParseIPOrPrefix(cleaned, expectedVersion)
	if err != nil {
		if warnFn != nil {
			warnFn(fmt.Sprintf("Skipping invalid IP/CIDR entry %q: %v", strings.TrimSpace(netCIDR), err))
		}
		return
	}

	ignorePrefixes := ParseRangeList(ignoreRange, expectedVersion, warnFn)
	allowPrefixes := ParseRangeList(allowRange, expectedVersion, warnFn)
	AppendIPsFromPrefix(ips, prefix, ignorePrefixes, allowPrefixes)
}

func GenIPs(ips *[]string, ipv4FilePath string, ignoreRange []string, allowRange []string, warnFn func(string)) error {
	file, err := os.ReadFile(ipv4FilePath)
	if err != nil {
		return err
	}

	ignorePrefixes := ParseRangeList(ignoreRange, 4, warnFn)
	allowPrefixes := ParseRangeList(allowRange, 4, warnFn)

	for rawLine := range strings.Lines(string(file)) {
		cleaned := CleanIPListLine(rawLine)
		if cleaned == "" {
			continue
		}
		prefix, pErr := ParseIPOrPrefix(cleaned, 4)
		if pErr != nil {
			if warnFn != nil {
				warnFn(fmt.Sprintf("Skipping invalid IPv4/CIDR line %q: %v", strings.TrimSpace(rawLine), pErr))
			}
			continue
		}
		AppendIPsFromPrefix(ips, prefix, ignorePrefixes, allowPrefixes)
	}
	return nil
}

func LoadIPv6Entries(entries *[]string, ipv6FilePath string, ignoreRange []string, allowRange []string, warnFn func(string)) (bool, error) {
	file, err := os.ReadFile(ipv6FilePath)
	if err != nil {
		return false, err
	}

	ignorePrefixes := ParseRangeList(ignoreRange, 6, warnFn)
	allowPrefixes := ParseRangeList(allowRange, 6, warnFn)

	allSingleIPs := true
	for rawLine := range strings.Lines(string(file)) {
		cleaned := CleanIPListLine(rawLine)
		if cleaned == "" {
			continue
		}
		prefix, pErr := ParseIPOrPrefix(cleaned, 6)
		if pErr != nil {
			if warnFn != nil {
				warnFn(fmt.Sprintf("Skipping invalid IPv6/CIDR line %q: %v", strings.TrimSpace(rawLine), pErr))
			}
			continue
		}

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
	return allSingleIPs, nil
}

func RandomIPv6FromCIDR(cidr string) (net.IP, error) {
	prefix, err := ParseIPOrPrefix(cidr, 6)
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

	max := new(big.Int).Lsh(big.NewInt(1), uint(variableBits))
	randNum, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}

	ipInt := new(big.Int).SetBytes(ip)
	ipInt.Or(ipInt, randNum)

	randomIP := make(net.IP, 16)
	ipInt.FillBytes(randomIP)

	return randomIP, nil
}

func PreviewIPList(content string, ipVersion int, ignoreRange []string, allowRange []string, maxSample int) IPPreviewResult {
	if maxSample <= 0 {
		maxSample = 100
	}
	res := IPPreviewResult{
		Entries:       []IPPreviewEntry{},
		SampleTargets: []string{},
		Warnings:      []string{},
		AllSingleIPv6: ipVersion == 6,
	}

	warnFn := func(msg string) {
		res.Warnings = append(res.Warnings, msg)
	}

	ignorePrefixes := ParseRangeList(ignoreRange, ipVersion, warnFn)
	allowPrefixes := ParseRangeList(allowRange, ipVersion, warnFn)

	for rawLine := range strings.Lines(content) {
		cleaned := CleanIPListLine(rawLine)
		if cleaned == "" {
			res.SkippedLines++
			continue
		}
		prefix, err := ParseIPOrPrefix(cleaned, ipVersion)
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Line %q: %v", strings.TrimSpace(rawLine), err))
			continue
		}

		bits := prefix.Bits()
		isSingle := (ipVersion == 4 && bits == 32) || (ipVersion == 6 && bits == 128)
		var hostCount int64 = 1
		if ipVersion == 4 && bits < 32 {
			hostCount = int64(1) << (32 - bits)
		} else if ipVersion == 6 && bits < 128 {
			res.AllSingleIPv6 = false
			shift := min(62, 128-bits)
			hostCount = int64(1) << shift
		}

		res.Entries = append(res.Entries, IPPreviewEntry{
			Raw:           strings.TrimSpace(rawLine),
			Cleaned:       cleaned,
			CanonicalCIDR: prefix.String(),
			IsSingleIP:    isSingle,
			PrefixBits:    bits,
			HostCount:     hostCount,
		})

		if ipVersion == 4 {
			// Count and sample allowed IPs
			ignoredAll := false
			for _, ig := range ignorePrefixes {
				if ig.Bits() <= prefix.Bits() && ig.Overlaps(prefix) {
					ignoredAll = true
					break
				}
			}
			if ignoredAll {
				continue
			}
			if len(allowPrefixes) > 0 {
				overlaps := false
				for _, al := range allowPrefixes {
					if al.Overlaps(prefix) {
						overlaps = true
						break
					}
				}
				if !overlaps {
					continue
				}
			}
			// If subnet is small (<= 65536), iterate accurately; otherwise estimate if no per-host filter
			if hostCount <= 65536 {
				for ip := prefix.Addr(); prefix.Contains(ip); ip = ip.Next() {
					if IsIPAllowed(ip, ignorePrefixes, allowPrefixes) {
						res.TotalTargets++
						if len(res.SampleTargets) < maxSample {
							res.SampleTargets = append(res.SampleTargets, ip.String())
						}
					}
				}
			} else {
				res.TotalTargets += int(hostCount)
				for ip := prefix.Addr(); prefix.Contains(ip) && len(res.SampleTargets) < maxSample; ip = ip.Next() {
					if IsIPAllowed(ip, ignorePrefixes, allowPrefixes) {
						res.SampleTargets = append(res.SampleTargets, ip.String())
					}
				}
			}
		} else {
			res.TotalTargets++
			if len(res.SampleTargets) < maxSample {
				if isSingle {
					res.SampleTargets = append(res.SampleTargets, prefix.Addr().String())
				} else {
					res.SampleTargets = append(res.SampleTargets, prefix.String())
				}
			}
		}
	}

	if len(res.Entries) == 0 {
		res.AllSingleIPv6 = false
	}
	return res
}
