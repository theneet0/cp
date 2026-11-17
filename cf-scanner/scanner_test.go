package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestUploadTest_SuccessAndFormatting(t *testing.T) {
	var receivedBytes atomic.Int64
	var receivedMethod string
	var receivedHost string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		receivedHost = r.Host
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			t.Errorf("unexpected body read error: %v", err)
		}
		receivedBytes.Store(n)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tcpAddr := srv.Listener.Addr().(*net.TCPAddr)
	conf := defaultConf()
	conf.UploadTest = UploadConfig{
		Enable:             true,
		SeparateConnection: false,
		Url:                "http://speed.cloudflare.com/__up",
		SNI:                "cp.cloudflare.com",
		PayloadBytes:       256 * 1024, // 256 KB
		TargetBytes:        128 * 1024, // 128 KB
		Timeout:            3000,
	}

	report := uploadTest(srv.Client(), &conf, *tcpAddr, utls.HelloChrome_Auto, &Fragment{})
	if !strings.HasSuffix(report, "MB/S") {
		t.Fatalf("expected upload speed in MB/S format, got %q", report)
	}
	if receivedMethod != http.MethodPost {
		t.Fatalf("expected POST method, got %q", receivedMethod)
	}
	if receivedHost != "speed.cloudflare.com" {
		t.Fatalf("expected Host header speed.cloudflare.com, got %q", receivedHost)
	}
	if receivedBytes.Load() != int64(conf.UploadTest.PayloadBytes) {
		t.Fatalf("expected %d uploaded bytes, got %d", conf.UploadTest.PayloadBytes, receivedBytes.Load())
	}
}

func TestUploadTest_JammedWhenTargetBytesNotReached(t *testing.T) {
	// Server stalls so TargetBytes cannot be uploaded within Timeout
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		_, _ = r.Body.Read(buf)
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tcpAddr := srv.Listener.Addr().(*net.TCPAddr)
	conf := defaultConf()
	conf.UploadTest = UploadConfig{
		Enable:             true,
		SeparateConnection: false,
		Url:                "http://speed.cloudflare.com/__up",
		SNI:                "cp.cloudflare.com",
		PayloadBytes:       10000000,
		TargetBytes:        5000000,
		Timeout:            150,
	}

	// Reader that throttles after 16KB to simulate a jammed uplink
	origUpload := uploadTest(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			buf := make([]byte, 4096)
			_, _ = req.Body.Read(buf)
			<-req.Context().Done()
			return nil, req.Context().Err()
		}),
	}, &conf, *tcpAddr, utls.HelloChrome_Auto, &Fragment{})

	if origUpload != "JAMMED" {
		t.Fatalf("expected JAMMED when TargetBytes not reached within Timeout, got %q", origUpload)
	}
}

func TestUploadTest_JammedOnMidTransferDrop(t *testing.T) {
	conf := defaultConf()
	conf.UploadTest = UploadConfig{
		Enable:             true,
		SeparateConnection: false,
		Url:                "http://speed.cloudflare.com/__up",
		SNI:                "cp.cloudflare.com",
		PayloadBytes:       1000000,
		TargetBytes:        500000,
		Timeout:            2000,
	}

	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			buf := make([]byte, 32*1024)
			_, _ = req.Body.Read(buf)
			return nil, io.ErrUnexpectedEOF
		}),
	}

	addr := net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
	report := uploadTest(client, &conf, addr, utls.HelloChrome_Auto, &Fragment{})
	if report != "JAMMED" {
		t.Fatalf("expected JAMMED when connection drops mid-transfer, got %q", report)
	}
}

func TestUploadTest_BackwardCompatibilityConfig(t *testing.T) {
	legacyJSON := `{
		"Hostname": "cp.cloudflare.com",
		"IpVersion": 4,
		"DownloadTest": {
			"Enable": true,
			"Url": "https://speed.cloudflare.com/__down?bytes=10000000",
			"SNI": "cp.cloudflare.com",
			"TargetBytes": 5000000,
			"Timeout": 5000
		}
	}`
	conf := defaultConf()
	if err := json.Unmarshal([]byte(legacyJSON), &conf); err != nil {
		t.Fatalf("failed to unmarshal legacy conf.json: %v", err)
	}
	if conf.UploadTest.Enable {
		t.Fatalf("expected UploadTest.Enable to default to false on legacy config")
	}
	if conf.UploadTest.Url != defaultUploadURL {
		t.Fatalf("expected default UploadTest.Url %q, got %q", defaultUploadURL, conf.UploadTest.Url)
	}
	if conf.UploadTest.PayloadBytes != defaultUploadPayloadBytes {
		t.Fatalf("expected default PayloadBytes %d, got %d", defaultUploadPayloadBytes, conf.UploadTest.PayloadBytes)
	}
}

func TestGenIPs_MixedSingleIPAndCIDRWithFilters(t *testing.T) {
	tmpDir := t.TempDir()
	ipListFile := filepath.Join(tmpDir, "mixed_ipv4.txt")
	content := strings.Join([]string{
		"# Full line comment",
		"// Another comment style",
		"",
		"104.16.132.229 # single IPv4 with inline comment",
		"104.16.132.230/32 // explicit /32 CIDR",
		"104.16.0.0/30",
		"2606:4700::6810:84e5", // Wrong IP version for IpVersion=4 -> should warn & skip
		"invalid-ip-line",      // Malformed -> should warn & skip
	}, "\n")

	if err := os.WriteFile(ipListFile, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test IP list: %v", err)
	}

	var ips []string
	// Ignore single IP 104.16.0.1, allow everything in 104.16.0.0/16
	GenIPs(&ips, ipListFile, []string{"104.16.0.1"}, []string{"104.16.132.229", "104.16.132.230/32", "104.16.0.0/30"})

	expected := []string{
		"104.16.132.229",
		"104.16.132.230",
		"104.16.0.0",
		"104.16.0.2",
		"104.16.0.3",
	}

	if len(ips) != len(expected) {
		t.Fatalf("expected %d IPs (%v), got %d (%v)", len(expected), expected, len(ips), ips)
	}
	for i := range expected {
		if ips[i] != expected[i] {
			t.Fatalf("index %d: expected %q, got %q", i, expected[i], ips[i])
		}
	}
}

func TestIPv6_SingleIPAndCIDRSupport(t *testing.T) {
	// 1. Test randomIPv6FromCIDR with single IPv6 (no /128)
	singleIP, err := randomIPv6FromCIDR("2606:4700::6810:84e5")
	if err != nil {
		t.Fatalf("randomIPv6FromCIDR failed on single IPv6: %v", err)
	}
	if singleIP.String() != "2606:4700::6810:84e5" {
		t.Fatalf("expected 2606:4700::6810:84e5, got %s", singleIP.String())
	}

	// 2. Test randomIPv6FromCIDR with /128 CIDR
	cidr128, err := randomIPv6FromCIDR("2606:4700::6810:84e5/128")
	if err != nil {
		t.Fatalf("randomIPv6FromCIDR failed on /128 CIDR: %v", err)
	}
	if cidr128.String() != "2606:4700::6810:84e5" {
		t.Fatalf("expected 2606:4700::6810:84e5, got %s", cidr128.String())
	}

	// 3. Test LoadIPv6Entries with mixed single IPs, CIDRs, comments, and filters
	tmpDir := t.TempDir()
	ipv6File := filepath.Join(tmpDir, "mixed_ipv6.txt")
	content := strings.Join([]string{
		"# IPv6 test file",
		"2606:4700::6810:84e5",
		"2606:4700::6810:84e6/128",
		"2606:4700:10::/48",
		"104.16.132.229", // IPv4 in IPv6 file -> should be skipped gracefully
		"bad_ipv6_line",
	}, "\n")
	if err := os.WriteFile(ipv6File, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test IPv6 list: %v", err)
	}

	var entries []string
	allSingle := LoadIPv6Entries(&entries, ipv6File, []string{"2606:4700::6810:84e6"}, nil)
	if allSingle {
		t.Fatalf("expected allSingle=false when /48 CIDR is present")
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries after ignoring 2606:4700::6810:84e6, got %v", entries)
	}
	if entries[0] != "2606:4700::6810:84e5" || entries[1] != "2606:4700:10::/48" {
		t.Fatalf("unexpected entries: %v", entries)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestSequentialDownloadAndUpload(t *testing.T) {
	var activeConcurrent atomic.Int32
	var maxConcurrent atomic.Int32
	var order []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := activeConcurrent.Add(1)
		for {
			prev := maxConcurrent.Load()
			if cur <= prev || maxConcurrent.CompareAndSwap(prev, cur) {
				break
			}
		}
		defer activeConcurrent.Add(-1)

		switch r.URL.Path {
		case "/__down":
			order = append(order, "download")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(make([]byte, 64*1024))
		case "/__up":
			order = append(order, "upload")
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	tcpAddr := srv.Listener.Addr().(*net.TCPAddr)
	portStr := strconv.Itoa(tcpAddr.Port)
	conf := defaultConf()
	conf.DownloadTest = DownloadConfig{
		Enable:             true,
		SeparateConnection: false,
		Url:                "http://127.0.0.1:" + portStr + "/__down",
		TargetBytes:        32 * 1024,
		Timeout:            2000,
	}
	conf.UploadTest = UploadConfig{
		Enable:             true,
		SeparateConnection: false,
		Url:                "http://127.0.0.1:" + portStr + "/__up",
		PayloadBytes:       64 * 1024,
		TargetBytes:        32 * 1024,
		Timeout:            2000,
	}

	dl := downloadTest(srv.Client(), &conf, *tcpAddr, utls.HelloChrome_Auto, &Fragment{})
	ul := uploadTest(srv.Client(), &conf, *tcpAddr, utls.HelloChrome_Auto, &Fragment{})

	if !strings.HasSuffix(dl, "MB/S") || !strings.HasSuffix(ul, "MB/S") {
		t.Fatalf("expected both download and upload to succeed, got dl=%q ul=%q", dl, ul)
	}
	if maxConcurrent.Load() > 1 {
		t.Fatalf("expected sequential execution (maxConcurrent=1), got %d", maxConcurrent.Load())
	}
	if len(order) != 2 || order[0] != "download" || order[1] != "upload" {
		t.Fatalf("expected [download, upload] execution order, got %v", order)
	}
}
