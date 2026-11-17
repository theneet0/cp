package scanner

import (
	"context"
	"fmt"
	"maps"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	utls "github.com/refraction-networking/utls"
)

type ScanState string

const (
	StateIdle      ScanState = "idle"
	StateRunning   ScanState = "running"
	StateStopping  ScanState = "stopping"
	StateCompleted ScanState = "completed"
	StateStopped   ScanState = "stopped"
	StateError     ScanState = "error"
)

type ProgressEvent struct {
	Scanned     int64   `json:"scanned"`
	Total       int64   `json:"total"`
	Passed      int64   `json:"passed"`
	Failed      int64   `json:"failed"`
	Percent     float64 `json:"percent"`
	ElapsedMs   int64   `json:"elapsedMs"`
	ElapsedText string  `json:"elapsedText"`
	State       string  `json:"state"`
}

type LogEvent struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"` // "info", "success", "warn", "error"
	Message   string `json:"message"`
}

type ScanResult struct {
	ID            int64    `json:"id"`
	Timestamp     string   `json:"timestamp"`
	Domain        string   `json:"domain"`
	IP            string   `json:"ip"`
	Port          int      `json:"port"`
	Addr          string   `json:"addr"`
	PingMs        float64  `json:"pingMs"`
	PingText      string   `json:"pingText"`
	LatencyMs     int64    `json:"latencyMs"`
	JitterMs      *float64 `json:"jitterMs"`
	JitterText    string   `json:"jitterText"`
	DownloadSpeed string   `json:"downloadSpeed"`
	DownloadMbps  float64  `json:"downloadMbps"`
	UploadSpeed   string   `json:"uploadSpeed"`
	UploadMbps    float64  `json:"uploadMbps"`
	Status        string   `json:"status"` // "PASSED", "JAMMED", "HIGH_JITTER"
}

type Hooks struct {
	OnStateChange func(ScanState)
	OnProgress    func(ProgressEvent)
	OnLog         func(LogEvent)
	OnResult      func(ScanResult)
}

type Runner struct {
	mu      sync.Mutex
	cancel  context.CancelFunc
	state   ScanState
	scanned atomic.Int64
	total   atomic.Int64
	passed  atomic.Int64
	failed  atomic.Int64
	startAt time.Time
}

func NewRunner() *Runner {
	return &Runner{
		state: StateIdle,
	}
}

func (r *Runner) State() ScanState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

func (r *Runner) Stop() {
	r.mu.Lock()
	cancel := r.cancel
	if r.state == StateRunning {
		r.state = StateStopping
	}
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (r *Runner) Snapshot() ProgressEvent {
	r.mu.Lock()
	st := r.state
	start := r.startAt
	r.mu.Unlock()

	scanned := r.scanned.Load()
	total := r.total.Load()
	passed := r.passed.Load()
	failed := r.failed.Load()

	var pct float64
	if total > 0 {
		pct = min(100.0, float64(scanned)*100.0/float64(total))
	}
	var elapsedMs int64
	var elapsedText = "0.0s"
	if !start.IsZero() {
		d := time.Since(start)
		elapsedMs = d.Milliseconds()
		elapsedText = fmt.Sprintf("%.1fs", d.Seconds())
	}
	return ProgressEvent{
		Scanned:     scanned,
		Total:       total,
		Passed:      passed,
		Failed:      failed,
		Percent:     pct,
		ElapsedMs:   elapsedMs,
		ElapsedText: elapsedText,
		State:       string(st),
	}
}

func (r *Runner) Run(parentCtx context.Context, conf Conf, hooks Hooks) error {
	r.mu.Lock()
	if r.state == StateRunning || r.state == StateStopping {
		r.mu.Unlock()
		return fmt.Errorf("a scan is already running")
	}
	NormalizeConfig(&conf)
	ctx, cancel := context.WithCancel(parentCtx)
	r.cancel = cancel
	r.state = StateRunning
	r.scanned.Store(0)
	r.total.Store(0)
	r.passed.Store(0)
	r.failed.Store(0)
	r.startAt = time.Now()
	r.mu.Unlock()

	emitState := func(s ScanState) {
		r.mu.Lock()
		r.state = s
		r.mu.Unlock()
		if hooks.OnStateChange != nil {
			hooks.OnStateChange(s)
		}
	}

	emitLog := func(level, msg string) {
		if hooks.OnLog != nil {
			hooks.OnLog(LogEvent{
				Timestamp: time.Now().Format("15:04:05"),
				Level:     level,
				Message:   msg,
			})
		}
	}

	emitProgress := func() {
		if hooks.OnProgress != nil {
			hooks.OnProgress(r.Snapshot())
		}
	}

	emitState(StateRunning)
	for _, w := range ValidateConfig(&conf) {
		emitLog("warn", w)
	}

	fingerprint := FingerprintID(conf.TLS.Utls.Fingerprint)
	scheme := "http"
	ports := slices.Clone(conf.Ports)
	if conf.TLS.Enable {
		scheme = "https"
		if len(ports) == 0 {
			ports = []int{443}
		}
	} else if len(ports) == 0 {
		ports = []int{80}
	}

	fragment := BuildFragment(conf.TLS.Utls.Fragment)

	file, fileErr := OpenResultFile(conf.CSV)
	if fileErr != nil {
		emitLog("error", fmt.Sprintf("Failed to open result file: %v", fileErr))
		emitState(StateError)
		return fileErr
	}
	defer file.Close()

	var resultSeq atomic.Int64

	// Periodic progress ticker
	tickerDone := make(chan struct{})
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-tickerDone:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				emitProgress()
			}
		}
	}()
	defer close(tickerDone)

	if !conf.DomainScan.Enable {
		ips := make([]string, 0, 256)
		ipv6AllSingle := false
		switch conf.IpVersion {
		case 4:
			emitLog("info", fmt.Sprintf("Loading IPv4 targets from %s...", conf.IplistPath))
			if err := GenIPs(&ips, conf.IplistPath, conf.IgnoreRange, conf.AllowRange, func(w string) {
				emitLog("warn", w)
			}); err != nil {
				emitLog("error", fmt.Sprintf("Failed to read %s: %v", conf.IplistPath, err))
				emitState(StateError)
				return err
			}
		case 6:
			emitLog("info", fmt.Sprintf("Loading IPv6 targets from %s...", conf.IplistPath))
			var err error
			ipv6AllSingle, err = LoadIPv6Entries(&ips, conf.IplistPath, conf.IgnoreRange, conf.AllowRange, func(w string) {
				emitLog("warn", w)
			})
			if err != nil {
				emitLog("error", fmt.Sprintf("Failed to read %s: %v", conf.IplistPath, err))
				emitState(StateError)
				return err
			}
		default:
			err := fmt.Errorf("invalid IpVersion: %d", conf.IpVersion)
			emitLog("error", err.Error())
			emitState(StateError)
			return err
		}

		if len(ips) == 0 {
			emitLog("warn", "No valid IP addresses or CIDR ranges found to scan.")
			emitState(StateCompleted)
			emitProgress()
			return nil
		}

		if conf.IpVersion == 4 || ipv6AllSingle {
			r.total.Store(int64(len(ips)))
			emitLog("info", fmt.Sprintf("Prepared %d IP targets across %d worker goroutine(s).", len(ips), conf.Goroutines))
		} else {
			emitLog("info", fmt.Sprintf("Loaded %d IPv6 CIDR/address entries across %d worker goroutine(s).", len(ips), conf.Goroutines))
		}
		emitProgress()

		ipCh := make(chan string, conf.Goroutines)
		var wg sync.WaitGroup

		for range conf.Goroutines {
			wg.Go(func() {
				var client *http.Client
				if conf.TLS.Enable {
					if conf.HTTP3 {
						client = H3Transporter(&conf, nil, nil)
					} else if !conf.TLS.Utls.Enable {
						client = TLSTransporter(&conf, nil)
					}
				} else {
					client = &http.Client{}
				}

				for {
					select {
					case <-ctx.Done():
						return
					case ipStr, ok := <-ipCh:
						if !ok {
							return
						}
						r.scanSingleIP(ctx, ipStr, "", ports, scheme, &conf, client, fingerprint, &fragment, file, &resultSeq, hooks, emitLog)
						r.scanned.Add(1)
						emitProgress()
					}
				}
			})
		}

		feedLoop:
		switch conf.IpVersion {
		case 4:
			if conf.RandomScan {
				rand.Shuffle(len(ips), func(i, j int) {
					ips[i], ips[j] = ips[j], ips[i]
				})
			}
			for _, ip := range ips {
				select {
				case <-ctx.Done():
					break feedLoop
				case ipCh <- ip:
				}
			}
		case 6:
			if ipv6AllSingle {
				if conf.RandomScan {
					rand.Shuffle(len(ips), func(i, j int) {
						ips[i], ips[j] = ips[j], ips[i]
					})
				}
				for _, ip := range ips {
					select {
					case <-ctx.Done():
						break feedLoop
					case ipCh <- ip:
					}
				}
			} else {
				ignorePrefixes := ParseRangeList(conf.IgnoreRange, 6, nil)
				allowPrefixes := ParseRangeList(conf.AllowRange, 6, nil)
				for {
					select {
					case <-ctx.Done():
						break feedLoop
					default:
					}
					ipv6, e := RandomIPv6FromCIDR(strings.TrimSpace(ips[rand.Intn(len(ips))]))
					if e != nil {
						continue
					}
					if addr, ok := netip.AddrFromSlice(ipv6); ok {
						if !IsIPAllowed(addr.Unmap(), ignorePrefixes, allowPrefixes) {
							continue
						}
					}
					select {
					case <-ctx.Done():
						break feedLoop
					case ipCh <- ipv6.String():
					}
				}
			}
		}

		close(ipCh)
		wg.Wait()
	} else {
		// Domain Scan
		domainBytes, err := os.ReadFile(conf.DomainScan.DomainListPath)
		if err != nil {
			emitLog("error", fmt.Sprintf("Failed to read domain list %s: %v", conf.DomainScan.DomainListPath, err))
			emitState(StateError)
			return err
		}
		rawLines := strings.Split(string(domainBytes), "\n")
		domains := make([]string, 0, len(rawLines))
		for _, d := range rawLines {
			cleaned := CleanIPListLine(d)
			if cleaned != "" {
				domains = append(domains, cleaned)
			}
		}
		if len(domains) == 0 {
			emitLog("warn", "No valid domains found in DomainListPath.")
			emitState(StateCompleted)
			return nil
		}

		if conf.DomainScan.Shuffle {
			rand.Shuffle(len(domains), func(i, j int) {
				domains[i], domains[j] = domains[j], domains[i]
			})
		}

		r.total.Store(int64(len(domains)))
		emitLog("info", fmt.Sprintf("Scanning %d domain(s) with %d worker goroutine(s)...", len(domains), conf.Goroutines))
		emitProgress()

		domainCh := make(chan string, conf.Goroutines)
		var wg sync.WaitGroup
		for range conf.Goroutines {
			wg.Go(func() {
				for {
					select {
					case <-ctx.Done():
						return
					case domain, ok := <-domainCh:
						if !ok {
							return
						}
						ips, resolveErr := net.DefaultResolver.LookupIP(ctx, "ip", domain)
						if resolveErr != nil {
							r.failed.Add(1)
							if conf.Log {
								emitLog("warn", fmt.Sprintf("DNS lookup failed for %s: %v", domain, resolveErr))
							}
							r.scanned.Add(1)
							emitProgress()
							continue
						}
						for _, ip := range ips {
							if ctx.Err() != nil {
								return
							}
							if conf.DomainScan.SkipIPV6 && ip.To4() == nil && ip.To16() != nil {
								continue
							}
							r.scanSingleIP(ctx, ip.String(), domain, ports, scheme, &conf, nil, fingerprint, &fragment, file, &resultSeq, hooks, emitLog)
						}
						r.scanned.Add(1)
						emitProgress()
					}
				}
			})
		}

		for _, domain := range domains {
			select {
			case <-ctx.Done():
				break
			case domainCh <- domain:
			}
		}
		close(domainCh)
		wg.Wait()
	}

	emitProgress()
	if ctx.Err() != nil {
		emitLog("warn", "Scan stopped by user.")
		emitState(StateStopped)
	} else {
		emitLog("success", fmt.Sprintf("Scan completed. Scanned: %d, Passed: %d.", r.scanned.Load(), r.passed.Load()))
		emitState(StateCompleted)
	}
	return nil
}

func (r *Runner) scanSingleIP(
	ctx context.Context,
	ipStr string,
	domain string,
	ports []int,
	scheme string,
	conf *Conf,
	sharedClient *http.Client,
	fingerprint utls.ClientHelloID,
	fragment *Fragment,
	file *FileMutex,
	resultSeq *atomic.Int64,
	hooks Hooks,
	emitLog func(string, string),
) {
	if ctx.Err() != nil {
		return
	}

	minrtt := time.Millisecond
	if conf.Ping.Enable {
		pinger, err := probing.NewPinger(ipStr)
		if err != nil {
			r.failed.Add(1)
			if conf.Log {
				emitLog("error", fmt.Sprintf("PING init %s: %v", ipStr, err))
			}
			return
		}
		pinger.SetPrivileged(conf.Ping.Privileged)
		pinger.Size = RandomRange(conf.Ping.Size)
		pinger.Timeout = time.Duration(conf.Ping.MaxPing) * time.Millisecond
		pinger.Count = 1

		pingDone := make(chan error, 1)
		go func() {
			pingDone <- pinger.Run()
		}()

		select {
		case <-ctx.Done():
			pinger.Stop()
			return
		case pErr := <-pingDone:
			if pErr != nil {
				r.failed.Add(1)
				if conf.Log {
					emitLog("error", fmt.Sprintf("PING %s: %v", ipStr, pErr))
				}
				return
			}
		}

		stats := pinger.Statistics()
		if stats.PacketLoss > 0 || stats.MinRtt > (time.Duration(conf.Ping.MaxPing)*time.Millisecond) {
			r.failed.Add(1)
			if conf.Log {
				emitLog("error", fmt.Sprintf("PING %s\t%s (exceeded MaxPing)", ipStr, stats.MinRtt))
			}
			return
		}
		minrtt = stats.AvgRtt
	}

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		r.failed.Add(1)
		return
	}

	for _, port := range ports {
		if ctx.Err() != nil {
			return
		}
		addr := net.TCPAddr{IP: parsedIP, Port: port}

		hostname := conf.Hostname
		if domain != "" && conf.DomainScan.DomainAsHost {
			hostname = domain
		} else if strings.Contains(conf.Hostname, "{ip}") {
			hostname = addr.String()
		}

		sni := conf.TLS.SNI
		if domain != "" && conf.DomainScan.DomainAsSNI {
			sni = domain
		}

		headers := http.Header{}
		if conf.Headers != nil {
			headers = maps.Clone(conf.Headers)
		}
		headers.Set("Host", hostname)
		if conf.Padding {
			headers.Set("Cookie", RandomString(conf.PaddingSize))
		}

		req := (&http.Request{
			Method: http.MethodGet,
			URL:    &url.URL{Scheme: scheme, Host: addr.String(), Path: conf.Path},
			Host:   hostname,
			Header: headers,
		}).WithContext(ctx)

		client := sharedClient
		if client == nil {
			if conf.TLS.Enable {
				if conf.HTTP3 {
					client = H3Transporter(conf, &sni, nil)
				} else if !conf.TLS.Utls.Enable {
					client = TLSTransporter(conf, &sni)
				}
			} else {
				client = &http.Client{}
			}
		}

		s := time.Now()
		if conf.TLS.Utls.Enable && conf.TLS.Enable && !conf.HTTP3 {
			uclient, utlsE := UtlsTransporter(ctx, conf, fingerprint, sni, addr, fragment)
			if utlsE != nil {
				r.failed.Add(1)
				if conf.Log && ctx.Err() == nil {
					emitLog("error", utlsE.Error())
				}
				continue
			}
			client = uclient
		}
		client.Timeout = time.Millisecond * time.Duration(conf.Maxlatency)

		resp, httpErr := client.Do(req)
		latency := time.Since(s).Milliseconds()
		if httpErr != nil {
			r.failed.Add(1)
			if conf.Log && ctx.Err() == nil {
				emitLog("error", fmt.Sprintf("%s: %v", addr.String(), httpErr))
			}
			continue
		}
		_ = resp.Body.Close()

		if !slices.Contains(conf.ResponseStatusCode, resp.StatusCode) {
			r.failed.Add(1)
			if conf.Log {
				emitLog("error", fmt.Sprintf("%s\t%s\tHTTP.StatusCode=%d", addr.String(), minrtt, resp.StatusCode))
			}
			continue
		}

		if err := matchHeaders(resp.Header, conf.ResponseHeader); err != nil {
			r.failed.Add(1)
			if conf.Log {
				emitLog("error", fmt.Sprintf("%s: %v", addr.String(), err))
			}
			continue
		}

		jitterStr := "Null"
		var jitterVal *float64
		downloadRes := "Null"
		uploadRes := "Null"

		if conf.Jitter.Enable {
			samples := conf.Jitter.Samples
			if samples <= 0 {
				samples = 5
			}
			latencies := make([]float64, 0, samples)
			jammed := false
			for range samples {
				if ctx.Err() != nil {
					return
				}
				js := time.Now()
				jResp, jErr := client.Do(req)
				jLat := time.Since(js).Milliseconds()
				if jErr != nil {
					jammed = true
					break
				}
				_ = jResp.Body.Close()
				latencies = append(latencies, float64(jLat))
				if conf.Jitter.Interval > 0 {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Millisecond * time.Duration(conf.Jitter.Interval)):
					}
				}
			}
			if jammed {
				r.failed.Add(1)
				if conf.Log {
					emitLog("warn", fmt.Sprintf("%s\t%s\t%dms\tJAMMED", addr.String(), minrtt, latency))
				}
				continue
			}
			jitter := CalcJitter(latencies)
			jitterVal = &jitter
			if jitter > conf.Jitter.MaxJitter {
				r.failed.Add(1)
				if conf.Log {
					emitLog("warn", fmt.Sprintf("%s\t%s\t%dms\tjitter=%f (exceeds MaxJitter)", addr.String(), minrtt, latency, jitter))
				}
				continue
			}
			jitterStr = fmt.Sprintf("%f", jitter)
		}

		if conf.DownloadTest.Enable {
			downloadRes = DownloadTest(ctx, client, conf, addr, fingerprint, fragment, func(m string) {
				if conf.Log {
					emitLog("error", m)
				}
			})
		}
		if conf.UploadTest.Enable {
			uploadRes = UploadTest(ctx, client, conf, addr, fingerprint, fragment, func(m string) {
				if conf.Log {
					emitLog("error", m)
				}
			})
		}

		var rep string
		if domain != "" {
			rep = fmt.Sprintf("%s:\t%s\t%s\t%d\t%s\t%s\t%s\n", domain, ipStr, minrtt, latency, jitterStr, downloadRes, uploadRes)
		} else {
			rep = fmt.Sprintf("%-21s %-12s %d\t%s\t%s\t%s\n", addr.String(), minrtt, latency, jitterStr, downloadRes, uploadRes)
		}

		if conf.Log {
			emitLog("success", strings.TrimSpace(rep))
		}

		if conf.CSV {
			if domain != "" {
				_ = file.Write(fmt.Sprintf("%s:%s,%s,%d,%s,%s,%s\n", domain, ipStr, minrtt, latency, jitterStr, downloadRes, uploadRes))
			} else {
				_ = file.Write(fmt.Sprintf("%s,%s,%d,%s,%s,%s\n", addr.String(), minrtt, latency, jitterStr, downloadRes, uploadRes))
			}
		} else {
			_ = file.Write(rep)
		}

		status := "PASSED"
		if downloadRes == "JAMMED" || uploadRes == "JAMMED" || downloadRes == "FAILED" || uploadRes == "FAILED" || downloadRes == "Timeout" {
			status = "JAMMED"
		}

		r.passed.Add(1)
		if hooks.OnResult != nil {
			hooks.OnResult(ScanResult{
				ID:            resultSeq.Add(1),
				Timestamp:     time.Now().Format("15:04:05"),
				Domain:        domain,
				IP:            ipStr,
				Port:          port,
				Addr:          addr.String(),
				PingMs:        float64(minrtt.Microseconds()) / 1000.0,
				PingText:      minrtt.String(),
				LatencyMs:     latency,
				JitterMs:      jitterVal,
				JitterText:    jitterStr,
				DownloadSpeed: downloadRes,
				DownloadMbps:  ParseMbps(downloadRes),
				UploadSpeed:   uploadRes,
				UploadMbps:    ParseMbps(uploadRes),
				Status:        status,
			})
		}
	}
}

func matchHeaders(headers http.Header, tomatch map[string]string) error {
	for header, value := range tomatch {
		if headers.Get(header) != value {
			return fmt.Errorf("response header %q not matching %q", header, value)
		}
	}
	return nil
}
