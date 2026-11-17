package scanner

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseConfigAndLegacyNoiseAlias(t *testing.T) {
	raw := `{
		"Hostname": "cp.cloudflare.com",
		"IpVersion": 4,
		"HTTP/3": true,
		"Noise": {
			"Enable": true,
			"Packets": [{"Type": "rand", "Payload": "1-10", "Sleep": "10-20"}]
		}
	}`
	cfg, err := ParseConfigJSON([]byte(raw))
	if err != nil {
		t.Fatalf("ParseConfigJSON failed: %v", err)
	}
	if !cfg.HTTP3 {
		t.Fatalf("expected HTTP/3 to be true")
	}
	if !cfg.Noises.Enable || len(cfg.Noises.Packets) != 1 {
		t.Fatalf("expected legacy Noise key to populate cfg.Noises")
	}
	if cfg.UploadTest.Url != DefaultUploadURL {
		t.Fatalf("expected default UploadTest.Url %q, got %q", DefaultUploadURL, cfg.UploadTest.Url)
	}
}

func TestPreviewIPListAndMixedIPGen(t *testing.T) {
	content := strings.Join([]string{
		"# Comment line",
		"104.16.132.229 # Single IPv4",
		"104.16.132.230/32 // Explicit /32",
		"104.16.0.0/30",
		"2606:4700::6810:84e5",
		"invalid_line",
	}, "\n")

	prev := PreviewIPList(content, 4, []string{"104.16.0.1"}, []string{"104.16.132.229", "104.16.132.230/32", "104.16.0.0/30"}, 50)
	if prev.TotalTargets != 5 {
		t.Fatalf("expected 5 total targets, got %d (%v)", prev.TotalTargets, prev.SampleTargets)
	}
	if len(prev.Warnings) != 2 {
		t.Fatalf("expected 2 warnings for IPv6-in-v4 and invalid_line, got %v", prev.Warnings)
	}
}

func TestRunnerLifecycleStartAndStop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__down":
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(make([]byte, 32*1024))
		case "/__up":
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(http.StatusOK)
		default:
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	tcpAddr := srv.Listener.Addr().(*net.TCPAddr)
	tmpDir := t.TempDir()
	ipFile := filepath.Join(tmpDir, "ips.txt")
	if err := os.WriteFile(ipFile, []byte("127.0.0.1\n"), 0600); err != nil {
		t.Fatalf("write ips.txt: %v", err)
	}

	origDir, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origDir) }()

	cfg := DefaultConfig()
	cfg.Ping.Enable = false
	cfg.TLS.Enable = false
	cfg.Ports = []int{tcpAddr.Port}
	cfg.IplistPath = ipFile
	cfg.Goroutines = 1
	cfg.Jitter.Enable = true
	cfg.Jitter.Samples = 2
	cfg.Jitter.Interval = 5
	cfg.DownloadTest = DownloadConfig{
		Enable:      true,
		Url:         srv.URL + "/__down",
		TargetBytes: 16 * 1024,
		Timeout:     2000,
	}
	cfg.UploadTest = UploadConfig{
		Enable:       true,
		Url:          srv.URL + "/__up",
		PayloadBytes: 32 * 1024,
		TargetBytes:  16 * 1024,
		Timeout:      2000,
	}

	runner := NewRunner()
	var resultsCount atomic.Int32
	var sawCompleted atomic.Bool

	err := runner.Run(context.Background(), cfg, Hooks{
		OnStateChange: func(s ScanState) {
			if s == StateCompleted {
				sawCompleted.Store(true)
			}
		},
		OnResult: func(res ScanResult) {
			resultsCount.Add(1)
			if res.Status != "PASSED" {
				t.Errorf("expected PASSED status, got %s (dl=%s, ul=%s)", res.Status, res.DownloadSpeed, res.UploadSpeed)
			}
		},
	})
	if err != nil {
		t.Fatalf("runner.Run error: %v", err)
	}
	if resultsCount.Load() != 1 {
		t.Fatalf("expected 1 scan result, got %d", resultsCount.Load())
	}
	if !sawCompleted.Load() {
		t.Fatalf("expected StateCompleted callback")
	}

	// Test immediate Stop() cancellation on a slow scan
	ipFileMany := filepath.Join(tmpDir, "many.txt")
	if err := os.WriteFile(ipFileMany, []byte("127.0.0.1/26\n"), 0600); err != nil {
		t.Fatalf("write many.txt: %v", err)
	}
	cfg.IplistPath = ipFileMany
	cfg.Jitter.Interval = 100

	doneCh := make(chan error, 1)
	go func() {
		doneCh <- runner.Run(context.Background(), cfg, Hooks{})
	}()

	time.Sleep(80 * time.Millisecond)
	runner.Stop()

	select {
	case <-doneCh:
		if runner.State() != StateStopped && runner.State() != StateCompleted {
			t.Fatalf("expected StateStopped after Stop(), got %s", runner.State())
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("runner did not stop promptly after Stop()")
	}
}
