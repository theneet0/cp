export interface GoFileItem {
  filename: string;
  status: 'NEW' | 'MODIFIED';
  language: 'go' | 'json' | 'markdown';
  summary: string;
  content: string;
}

export const GO_FILES: GoFileItem[] = [
  {
    filename: 'upload.go',
    status: 'NEW',
    language: 'go',
    summary:
      'Implements uploadTest() with HTTP/1.1, HTTP/2, HTTP/3, UTLS, Fragment, Noise, custom SNI, SeparateConnection, and zero-allocation streaming uploadPayloadReader with JAMMED detection.',
    content: `package main

import (
\t"context"
\t"errors"
\t"fmt"
\t"io"
\t"log"
\t"maps"
\t"net"
\t"net/http"
\t"net/url"
\t"sync"
\t"sync/atomic"
\t"time"

\t"github.com/fatih/color"
\t"github.com/quic-go/quic-go"
\tutls "github.com/refraction-networking/utls"
)

const (
\tdefaultUploadURL          = "https://speed.cloudflare.com/__up"
\tdefaultUploadPayloadBytes = 10000000
\tdefaultUploadTargetBytes  = 5000000
\tdefaultUploadTimeoutMs    = 5000
\tuploadChunkSize           = 1024 * 8
)

var uploadPatternChunk [uploadChunkSize]byte

func init() {
\tconst pattern = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
\tfor i := range uploadPatternChunk {
\t\tuploadPatternChunk[i] = pattern[i%len(pattern)]
\t}
}

// uploadPayloadReader streams a fixed-size payload without allocating a large buffer
// in memory per test, while tracking actual bytes read by the HTTP transport.
type uploadPayloadReader struct {
\tctx       context.Context
\ttotal     int64
\tuploaded  atomic.Int64
\tstartOnce sync.Once
\tstartNano atomic.Int64
\tlastNano  atomic.Int64
}

func newUploadPayloadReader(ctx context.Context, totalBytes int) *uploadPayloadReader {
\tr := &uploadPayloadReader{
\t\tctx:   ctx,
\t\ttotal: int64(totalBytes),
\t}
\tnow := time.Now().UnixNano()
\tr.startNano.Store(now)
\tr.lastNano.Store(now)
\treturn r
}

func (r *uploadPayloadReader) Read(p []byte) (int, error) {
\tselect {
\tcase <-r.ctx.Done():
\t\treturn 0, r.ctx.Err()
\tdefault:
\t}

\tr.startOnce.Do(func() {
\t\tnow := time.Now().UnixNano()
\t\tr.startNano.Store(now)
\t\tr.lastNano.Store(now)
\t})

\tcurrent := r.uploaded.Load()
\tremaining := r.total - current
\tif remaining <= 0 {
\t\treturn 0, io.EOF
\t}

\tn := len(p)
\tif n > uploadChunkSize {
\t\tn = uploadChunkSize
\t}
\tif int64(n) > remaining {
\t\tn = int(remaining)
\t}

\tcopy(p[:n], uploadPatternChunk[:n])
\tr.uploaded.Add(int64(n))
\tr.lastNano.Store(time.Now().UnixNano())
\treturn n, nil
}

func (r *uploadPayloadReader) Close() error {
\treturn nil
}

func (r *uploadPayloadReader) BytesUploaded() int {
\treturn int(r.uploaded.Load())
}

func (r *uploadPayloadReader) ElapsedSeconds(fallbackStart time.Time) float32 {
\tstart := r.startNano.Load()
\tend := time.Now().UnixNano()
\tif end <= start {
\t\td := time.Since(fallbackStart)
\t\tif d <= 0 {
\t\t\treturn 0.001
\t\t}
\t\treturn float32(d.Milliseconds()) / 1000
\t}
\tms := (end - start) / int64(time.Millisecond)
\tif ms <= 0 {
\t\treturn float32(end-start) / 1e9
\t}
\treturn float32(ms) / 1000
}

func uploadTest(preclient *http.Client, conf *Conf, addr net.TCPAddr, fingerprint utls.ClientHelloID, fragment *Fragment) string {
\trawURL := conf.UploadTest.Url
\tif rawURL == "" {
\t\trawURL = defaultUploadURL
\t}

\tconfigUrl, configUrlErr := url.Parse(rawURL)
\tif configUrlErr != nil {
\t\tlog.Fatalln(configUrlErr)
\t}

\tpayloadBytes := conf.UploadTest.PayloadBytes
\tif payloadBytes <= 0 {
\t\tif conf.UploadTest.TargetBytes > 0 {
\t\t\tpayloadBytes = conf.UploadTest.TargetBytes
\t\t} else {
\t\t\tpayloadBytes = defaultUploadPayloadBytes
\t\t}
\t}

\ttargetBytes := conf.UploadTest.TargetBytes
\tif targetBytes <= 0 {
\t\ttargetBytes = min(payloadBytes, defaultUploadTargetBytes)
\t}

\ttimeoutMs := conf.UploadTest.Timeout
\tif timeoutMs <= 0 {
\t\ttimeoutMs = defaultUploadTimeoutMs
\t}

\tsni := conf.UploadTest.SNI
\tif sni == "" && conf.TLS.SNI != "" {
\t\tsni = conf.TLS.SNI
\t}

\tvar client *http.Client
\tif !conf.UploadTest.SeparateConnection && preclient != nil {
\t\tclient = preclient
\t} else {
\t\tif configUrl.Scheme == "https" {
\t\t\tif conf.HTTP3 {
\t\t\t\tclient = h3transporter(
\t\t\t\t\tconf,
\t\t\t\t\t&sni,
\t\t\t\t\t&quic.Config{},
\t\t\t\t)
\t\t\t} else {
\t\t\t\tif conf.TLS.Utls.Enable {
\t\t\t\t\tuclient, utlsE := utlsTransporter(conf, fingerprint, sni, addr, fragment)
\t\t\t\t\tif utlsE != nil {
\t\t\t\t\t\treturn "FAILED"
\t\t\t\t\t}
\t\t\t\t\tclient = uclient
\t\t\t\t} else {
\t\t\t\t\tclient = tlsTransporter(conf, &sni)
\t\t\t\t}
\t\t\t}
\t\t} else {
\t\t\tclient = &http.Client{}
\t\t}
\t}

\tprevTimeout := client.Timeout
\tclient.Timeout = 0
\tdefer func() {
\t\tclient.Timeout = prevTimeout
\t}()

\ttimeoutDuration := time.Millisecond * time.Duration(timeoutMs)
\tctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
\tdefer cancel()

\ttype uploadResult struct {
\t\treport string
\t}
\tch := make(chan uploadResult, 1)

\tgo func() {
\t\tstart := time.Now()
\t\tbodyReader := newUploadPayloadReader(ctx, payloadBytes)

\t\theaders := http.Header{}
\t\tif conf.Headers != nil {
\t\t\theaders = maps.Clone(conf.Headers)
\t\t}
\t\theaders.Set("Host", configUrl.Host)
\t\theaders.Set("Content-Type", "application/octet-stream")

\t\treq := &http.Request{
\t\t\tMethod:        http.MethodPost,
\t\t\tURL:           &url.URL{Scheme: configUrl.Scheme, Host: addr.String(), Path: configUrl.Path, RawQuery: configUrl.RawQuery},
\t\t\tHost:          configUrl.Host,
\t\t\tHeader:        headers,
\t\t\tBody:          bodyReader,
\t\t\tContentLength: int64(payloadBytes),
\t\t}
\t\treq = req.WithContext(ctx)

\t\trespone, http_err := client.Do(req)
\t\tuploaded := bodyReader.BytesUploaded()

\t\tif http_err != nil {
\t\t\tif errors.Is(http_err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
\t\t\t\tif uploaded < targetBytes {
\t\t\t\t\tch <- uploadResult{report: "JAMMED"}
\t\t\t\t\treturn
\t\t\t\t}
\t\t\t\tlatency := bodyReader.ElapsedSeconds(start)
\t\t\t\tbytesPerSecond := float32(uploaded) / latency
\t\t\t\tch <- uploadResult{report: fmt.Sprintf("%fMB/S", bytesPerSecond/1000000)}
\t\t\t\treturn
\t\t\t}

\t\t\tif uploaded > 0 {
\t\t\t\tch <- uploadResult{report: "JAMMED"}
\t\t\t\treturn
\t\t\t}

\t\t\tcolor.Red("%s", http_err.Error())
\t\t\tch <- uploadResult{report: "FAILED"}
\t\t\treturn
\t\t}
\t\tdefer respone.Body.Close()
\t\t_, _ = io.Copy(io.Discard, respone.Body)

\t\tif respone.StatusCode < 200 || respone.StatusCode >= 300 {
\t\t\tcolor.Red("Upload host status code: %s", respone.Status)
\t\t\tch <- uploadResult{report: "FAILED"}
\t\t\treturn
\t\t}

\t\tif uploaded < targetBytes {
\t\t\tch <- uploadResult{report: "JAMMED"}
\t\t\treturn
\t\t}

\t\tlatency := bodyReader.ElapsedSeconds(start)
\t\tbytesPerSecond := float32(uploaded) / latency
\t\tch <- uploadResult{report: fmt.Sprintf("%fMB/S", bytesPerSecond/1000000)}
\t}()

\tselect {
\tcase res := <-ch:
\t\treturn res.report
\tcase <-time.After(timeoutDuration + 250*time.Millisecond):
\t\tcancel()
\t\treturn "JAMMED"
\t}
}`,
  },
  {
    filename: 'generateip.go',
    status: 'MODIFIED',
    language: 'go',
    summary:
      'Supports mixed single IPs (/32 IPv4, /128 IPv6) and CIDR blocks in IplistPath, AllowRange, and IgnoreRange. Skips comments/empty lines and logs warnings on malformed lines.',
    content: `package main

import (
\t"crypto/rand"
\t"fmt"
\t"log"
\t"math/big"
\t"net"
\t"net/netip"
\t"os"
\t"strings"
)

func cleanIPListLine(raw string) string {
\tline := strings.TrimSpace(raw)
\tif line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
\t\treturn ""
\t}
\tif idx := strings.Index(line, "#"); idx != -1 {
\t\tline = strings.TrimSpace(line[:idx])
\t}
\tif idx := strings.Index(line, "//"); idx != -1 {
\t\tline = strings.TrimSpace(line[:idx])
\t}
\treturn line
}

func parseIPOrPrefix(input string, expectedVersion int) (netip.Prefix, error) {
\tcleaned := cleanIPListLine(input)
\tif cleaned == "" {
\t\treturn netip.Prefix{}, fmt.Errorf("empty input")
\t}

\tvar prefix netip.Prefix
\tif strings.Contains(cleaned, "/") {
\t\tp, err := netip.ParsePrefix(cleaned)
\t\tif err != nil {
\t\t\treturn netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", cleaned, err)
\t\t}
\t\taddr := p.Addr().Unmap()
\t\tif addr != p.Addr() {
\t\t\tp = netip.PrefixFrom(addr, p.Bits())
\t\t}
\t\tprefix = p.Masked()
\t} else {
\t\taddr, err := netip.ParseAddr(cleaned)
\t\tif err != nil {
\t\t\treturn netip.Prefix{}, fmt.Errorf("invalid IP address %q: %w", cleaned, err)
\t\t}
\t\taddr = addr.Unmap()
\t\tif addr.Is4() {
\t\t\tprefix = netip.PrefixFrom(addr, 32)
\t\t} else if addr.Is6() {
\t\t\tprefix = netip.PrefixFrom(addr, 128)
\t\t} else {
\t\t\treturn netip.Prefix{}, fmt.Errorf("unsupported IP address %q", cleaned)
\t\t}
\t}

\tswitch expectedVersion {
\tcase 4:
\t\tif !prefix.Addr().Is4() {
\t\t\treturn netip.Prefix{}, fmt.Errorf("entry %q is not IPv4 (IpVersion=4)", cleaned)
\t\t}
\tcase 6:
\t\tif !prefix.Addr().Is6() {
\t\t\treturn netip.Prefix{}, fmt.Errorf("entry %q is not IPv6 (IpVersion=6)", cleaned)
\t\t}
\t}

\treturn prefix, nil
}

func parseRangeList(ranges []string, expectedVersion int) []netip.Prefix {
\tif len(ranges) == 0 {
\t\treturn nil
\t}
\tprefixes := make([]netip.Prefix, 0, len(ranges))
\tfor _, raw := range ranges {
\t\tcleaned := cleanIPListLine(raw)
\t\tif cleaned == "" {
\t\t\tcontinue
\t\t}
\t\tp, err := parseIPOrPrefix(cleaned, expectedVersion)
\t\tif err != nil {
\t\t\tlog.Printf("Warning: skipping invalid range entry %q: %v", raw, err)
\t\t\tcontinue
\t\t}
\t\tprefixes = append(prefixes, p)
\t}
\treturn prefixes
}

func isIPAllowed(addr netip.Addr, ignorePrefixes []netip.Prefix, allowPrefixes []netip.Prefix) bool {
\tfor _, ig := range ignorePrefixes {
\t\tif ig.Contains(addr) {
\t\t\treturn false
\t\t}
\t}
\tif len(allowPrefixes) > 0 {
\t\tallowed := false
\t\tfor _, al := range allowPrefixes {
\t\t\tif al.Contains(addr) {
\t\t\t\tallowed = true
\t\t\t\tbreak
\t\t\t}
\t\t}
\t\tif !allowed {
\t\t\treturn false
\t\t}
\t}
\treturn true
}

func appendIPsFromPrefix(ips *[]string, prefix netip.Prefix, ignorePrefixes []netip.Prefix, allowPrefixes []netip.Prefix) {
\tfor _, ig := range ignorePrefixes {
\t\tif ig.Bits() <= prefix.Bits() && ig.Overlaps(prefix) {
\t\t\treturn
\t\t}
\t}

\tif len(allowPrefixes) > 0 {
\t\tanyOverlap := false
\t\tfor _, al := range allowPrefixes {
\t\t\tif al.Overlaps(prefix) {
\t\t\t\tanyOverlap = true
\t\t\t\tbreak
\t\t\t}
\t\t}
\t\tif !anyOverlap {
\t\t\treturn
\t\t}
\t}

\tfor ip := prefix.Addr(); prefix.Contains(ip); ip = ip.Next() {
\t\tif isIPAllowed(ip, ignorePrefixes, allowPrefixes) {
\t\t\t*ips = append(*ips, ip.String())
\t\t}
\t}
}

func GenIPsFromCIDR(ips *[]string, netCIDR string, subnetMaskSize int, ignoreRange []string, allowRange []string) {
\tcleaned := cleanIPListLine(netCIDR)
\tif cleaned == "" {
\t\treturn
\t}

\texpectedVersion := 4
\tif subnetMaskSize == 128 {
\t\texpectedVersion = 6
\t}

\tprefix, err := parseIPOrPrefix(cleaned, expectedVersion)
\tif err != nil {
\t\tlog.Printf("Warning: skipping invalid IP/CIDR entry %q: %v", strings.TrimSpace(netCIDR), err)
\t\treturn
\t}

\tignorePrefixes := parseRangeList(ignoreRange, expectedVersion)
\tallowPrefixes := parseRangeList(allowRange, expectedVersion)
\tappendIPsFromPrefix(ips, prefix, ignorePrefixes, allowPrefixes)
}

func GenIPs(ips *[]string, ipv4FilePath string, ignoreRange []string, allowRange []string) {
\tfile, ipListFileErr := os.ReadFile(ipv4FilePath)
\tif ipListFileErr != nil {
\t\tlog.Fatalln(ipListFileErr)
\t}

\tignorePrefixes := parseRangeList(ignoreRange, 4)
\tallowPrefixes := parseRangeList(allowRange, 4)

\tfor rawLine := range strings.Lines(string(file)) {
\t\tcleaned := cleanIPListLine(rawLine)
\t\tif cleaned == "" {
\t\t\tcontinue
\t\t}
\t\tprefix, err := parseIPOrPrefix(cleaned, 4)
\t\tif err != nil {
\t\t\tlog.Printf("Warning: skipping invalid IPv4/CIDR line %q: %v", strings.TrimSpace(rawLine), err)
\t\t\tcontinue
\t\t}
\t\tappendIPsFromPrefix(ips, prefix, ignorePrefixes, allowPrefixes)
\t}
}

func LoadIPv6Entries(entries *[]string, ipv6FilePath string, ignoreRange []string, allowRange []string) (allSingleIPs bool) {
\tfile, ipListFileErr := os.ReadFile(ipv6FilePath)
\tif ipListFileErr != nil {
\t\tlog.Fatalln(ipListFileErr)
\t}

\tignorePrefixes := parseRangeList(ignoreRange, 6)
\tallowPrefixes := parseRangeList(allowRange, 6)

\tallSingleIPs = true
\tfor rawLine := range strings.Lines(string(file)) {
\t\tcleaned := cleanIPListLine(rawLine)
\t\tif cleaned == "" {
\t\t\tcontinue
\t\t}
\t\tprefix, err := parseIPOrPrefix(cleaned, 6)
\t\tif err != nil {
\t\t\tlog.Printf("Warning: skipping invalid IPv6/CIDR line %q: %v", strings.TrimSpace(rawLine), err)
\t\t\tcontinue
\t\t}

\t\tignored := false
\t\tfor _, ig := range ignorePrefixes {
\t\t\tif ig.Bits() <= prefix.Bits() && ig.Overlaps(prefix) {
\t\t\t\tignored = true
\t\t\t\tbreak
\t\t\t}
\t\t}
\t\tif ignored {
\t\t\tcontinue
\t\t}

\t\tif len(allowPrefixes) > 0 {
\t\t\toverlapsAllow := false
\t\t\tfor _, al := range allowPrefixes {
\t\t\t\tif al.Overlaps(prefix) {
\t\t\t\t\toverlapsAllow = true
\t\t\t\t\tbreak
\t\t\t\t}
\t\t\t}
\t\t\tif !overlapsAllow {
\t\t\t\tcontinue
\t\t\t}
\t\t}

\t\tif prefix.Bits() == 128 {
\t\t\t*entries = append(*entries, prefix.Addr().String())
\t\t} else {
\t\t\tallSingleIPs = false
\t\t\t*entries = append(*entries, prefix.String())
\t\t}
\t}

\tif len(*entries) == 0 {
\t\tallSingleIPs = false
\t}
\treturn allSingleIPs
}

func randomIPv6FromCIDR(cidr string) (net.IP, error) {
\tprefix, err := parseIPOrPrefix(cidr, 6)
\tif err != nil {
\t\treturn nil, err
\t}

\taddr := prefix.Addr()
\traw16 := addr.As16()
\tip := net.IP(raw16[:])

\tprefixLen := prefix.Bits()
\ttotalBits := 128
\tvariableBits := totalBits - prefixLen

\tif variableBits <= 0 {
\t\treturn ip, nil
\t}

\tmax := new(big.Int).Lsh(big.NewInt(1), uint(variableBits))
\trandNum, err := rand.Int(rand.Reader, max)
\tif err != nil {
\t\treturn nil, err
\t}

\tipInt := new(big.Int).SetBytes(ip)
\tipInt.Or(ipInt, randNum)

\trandomIP := make(net.IP, 16)
\tipInt.FillBytes(randomIP)

\treturn randomIP, nil
}`,
  },
  {
    filename: 'conf.json',
    status: 'MODIFIED',
    language: 'json',
    summary:
      'Adds the UploadTest configuration block mirroring DownloadTest with PayloadBytes, TargetBytes, Timeout, SNI, SeparateConnection, and Url.',
    content: `{
\t"ProgressBar": true,
\t"Log": true,
\t"CSV": false,
\t"RandomScan": true,
\t"Hostname": "cp.cloudflare.com",
\t"Ports": [],
\t"Path": "/",
\t"Headers": {
\t\t"User-Agent": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0"]
\t},
\t"ResponseHeader": {
\t\t"Server": "cloudflare"
\t},
\t"ResponseStatusCode": [200, 204],
\t"Padding": true,
\t"PaddingSize": "100-1000",
\t"Ping": {
\t\t"Enable": true,
\t\t"MaxPing": 300,
\t\t"Privileged": true,
\t\t"Size": "24-65"
\t},
\t"Goroutines": 16,
\t"Maxlatency": 2000,
\t"Jitter": {
\t\t"Enable": true,
\t\t"MaxJitter": 50.0,
\t\t"Samples": 5,
\t\t"Interval": 200
\t},
\t"IpVersion": 4,
\t"IplistPath": "ipv4.txt",
\t"IgnoreRange": [],
\t"AllowRange": [],
\t"TLS": {
\t\t"Enable": true,
\t\t"SNI": "cp.cloudflare.com",
\t\t"Insecure": false,
\t\t"Alpn": ["h2", "http/1.1"],
\t\t"Utls": {
\t\t\t"Enable": true,
\t\t\t"Fingerprint": "chrome",
\t\t\t"TcpTimeout": 1000,
\t\t\t"TcpConnectAttempt": 1,
\t\t\t"Fragment": {
\t\t\t\t"Enable": false,
\t\t\t\t"Length": "50-100",
\t\t\t\t"Delay": "10-15",
\t\t\t\t"MaxSplit": null
\t\t\t}
\t\t}
\t},
\t"HTTP/3": false,
\t"Noises": {
\t\t"Enable": false,
\t\t"Packets": [
\t\t\t{
\t\t\t\t"Type": "rand",
\t\t\t\t"Payload": "1-10",
\t\t\t\t"Sleep": "20-50"
\t\t\t},
\t\t\t{
\t\t\t\t"Type": "rand",
\t\t\t\t"Payload": "1-20",
\t\t\t\t"Sleep": "20-50"
\t\t\t}
\t\t]
\t},
\t"DomainScan": {
\t\t"Enable": false,
\t\t"DomainAsSNI": false,
\t\t"DomainAsHost": false,
\t\t"Shuffle": true,
\t\t"SkipIPV6": true,
\t\t"DomainListPath": "cloudfalare-domains.txt"
\t},
\t"DownloadTest": {
\t\t"Enable": false,
\t\t"SeparateConnection": false,
\t\t"Url": "https://speed.cloudflare.com/__down?bytes=10000000",
\t\t"SNI": "cp.cloudflare.com",
\t\t"TargetBytes": 5000000,
\t\t"Timeout": 5000
\t},
\t"UploadTest": {
\t\t"Enable": false,
\t\t"SeparateConnection": false,
\t\t"Url": "https://speed.cloudflare.com/__up",
\t\t"SNI": "cp.cloudflare.com",
\t\t"PayloadBytes": 10000000,
\t\t"TargetBytes": 5000000,
\t\t"Timeout": 5000
\t}
}`,
  },
  {
    filename: 'fileutils.go',
    status: 'MODIFIED',
    language: 'go',
    summary:
      'Updates the CSV header in result.csv to ip:port,ping,latency,jitter,download,upload.',
    content: `package main

import (
\t"log"
\t"os"
\t"sync"
)

type FileMutex struct {
\tfile   *os.File
\tlocker sync.Mutex
}

func (fm *FileMutex) Write(data string) error {
\tfm.locker.Lock()
\tdefer fm.locker.Unlock()

\t_, err := fm.file.WriteString(data)
\treturn err
}

func (fm *FileMutex) Close() error {
\tfm.locker.Lock()
\tdefer fm.locker.Unlock()

\treturn fm.file.Close()
}

func resultFile(csv bool) *os.File {
\tif csv {
\t\twill_be_created := false
\t\t_, exist := os.Stat("result.csv")
\t\tif exist != nil {
\t\t\twill_be_created = true
\t\t}
\t\tcsv_file, err := os.OpenFile("result.csv", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
\t\tif err != nil {
\t\t\tlog.Fatalln(err)
\t\t}
\t\tif will_be_created {
\t\t\tcsv_file.Write([]byte("ip:port,ping,latency,jitter,download,upload\\n"))
\t\t}
\t\treturn csv_file
\t} else {
\t\tfile, err := os.OpenFile("result.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
\t\tif err != nil {
\t\t\tlog.Fatalln(err)
\t\t}
\t\treturn file
\t}
}`,
  },
  {
    filename: 'main.go',
    status: 'MODIFIED',
    language: 'go',
    summary:
      'Adds UploadConfig struct, backward-compatible defaultConf(), sequential DownloadTest + UploadTest execution, console/CSV/result.txt upload column formatting, and IPv4/IPv6 single-IP + CIDR handling.',
    content: `// Excerpt of key changes in main.go (full file compiled in /cf-scanner/main.go):

type UploadConfig struct {
\tEnable             bool   \`json:"Enable"\`
\tSeparateConnection bool   \`json:"SeparateConnection"\`
\tUrl                string \`json:"Url"\`
\tSNI                string \`json:"SNI"\`
\tPayloadBytes       int    \`json:"PayloadBytes"\`
\tTargetBytes        int    \`json:"TargetBytes"\`
\tTimeout            int    \`json:"Timeout"\`
}

func defaultConf() Conf {
\treturn Conf{
\t\tUploadTest: UploadConfig{
\t\t\tEnable:             false,
\t\t\tSeparateConnection: false,
\t\t\tUrl:                defaultUploadURL,
\t\t\tSNI:                "cp.cloudflare.com",
\t\t\tPayloadBytes:       defaultUploadPayloadBytes,
\t\t\tTargetBytes:        defaultUploadTargetBytes,
\t\t\tTimeout:            defaultUploadTimeoutMs,
\t\t},
\t}
}

// Inside IP & Domain scan workers (sequential execution):
if conf.DownloadTest.Enable {
\tdownload_test = downloadTest(client, &conf, addr, fingerprint, &fragment)
}
if conf.UploadTest.Enable {
\tupload_test = uploadTest(client, &conf, addr, fingerprint, &fragment)
}
rep := fmt.Sprintf("%-21s %-12s %d\\t%s\\t%s\\t%s\\n", addr.String(), minrtt, latency, jitter_str, download_test, upload_test)
if LOG {
\tcolor.Green("%s", rep)
}
if conf.CSV {
\tfile.Write(fmt.Sprintf("%s,%s,%d,%s,%s,%s\\n", addr.String(), minrtt, latency, jitter_str, download_test, upload_test))
} else {
\tfile.Write(rep)
}`,
  },
];
