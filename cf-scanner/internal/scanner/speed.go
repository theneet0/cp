package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
)

const uploadChunkSize = 1024 * 8

var uploadPatternChunk [uploadChunkSize]byte

func init() {
	const pattern = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for i := range uploadPatternChunk {
		uploadPatternChunk[i] = pattern[i%len(pattern)]
	}
}

type uploadPayloadReader struct {
	ctx       context.Context
	total     int64
	uploaded  atomic.Int64
	startOnce sync.Once
	startNano atomic.Int64
	lastNano  atomic.Int64
}

func newUploadPayloadReader(ctx context.Context, totalBytes int) *uploadPayloadReader {
	r := &uploadPayloadReader{
		ctx:   ctx,
		total: int64(totalBytes),
	}
	now := time.Now().UnixNano()
	r.startNano.Store(now)
	r.lastNano.Store(now)
	return r
}

func (r *uploadPayloadReader) Read(p []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
	}

	r.startOnce.Do(func() {
		now := time.Now().UnixNano()
		r.startNano.Store(now)
		r.lastNano.Store(now)
	})

	current := r.uploaded.Load()
	remaining := r.total - current
	if remaining <= 0 {
		return 0, io.EOF
	}

	n := len(p)
	if n > uploadChunkSize {
		n = uploadChunkSize
	}
	if int64(n) > remaining {
		n = int(remaining)
	}

	copy(p[:n], uploadPatternChunk[:n])
	r.uploaded.Add(int64(n))
	r.lastNano.Store(time.Now().UnixNano())
	return n, nil
}

func (r *uploadPayloadReader) Close() error {
	return nil
}

func (r *uploadPayloadReader) BytesUploaded() int {
	return int(r.uploaded.Load())
}

func (r *uploadPayloadReader) ElapsedSeconds(fallbackStart time.Time) float32 {
	start := r.startNano.Load()
	end := time.Now().UnixNano()
	if end <= start {
		d := time.Since(fallbackStart)
		if d <= 0 {
			return 0.001
		}
		return float32(d.Milliseconds()) / 1000
	}
	ms := (end - start) / int64(time.Millisecond)
	if ms <= 0 {
		return float32(end-start) / 1e9
	}
	return float32(ms) / 1000
}

func DownloadTest(parentCtx context.Context, preclient *http.Client, conf *Conf, addr net.TCPAddr, fingerprint utls.ClientHelloID, fragment *Fragment, logErr func(string)) string {
	rawURL := conf.DownloadTest.Url
	if rawURL == "" {
		rawURL = DefaultDownloadURL
	}
	configUrl, err := url.Parse(rawURL)
	if err != nil {
		if logErr != nil {
			logErr(fmt.Sprintf("Invalid DownloadTest URL: %v", err))
		}
		return "FAILED"
	}

	targetBytes := conf.DownloadTest.TargetBytes
	if targetBytes <= 0 {
		targetBytes = DefaultDownloadTargetBytes
	}
	timeoutMs := conf.DownloadTest.Timeout
	if timeoutMs <= 0 {
		timeoutMs = DefaultDownloadTimeoutMs
	}

	sni := conf.DownloadTest.SNI
	if sni == "" && conf.TLS.SNI != "" {
		sni = conf.TLS.SNI
	}

	var client *http.Client
	if !conf.DownloadTest.SeparateConnection && preclient != nil {
		client = preclient
	} else {
		if configUrl.Scheme == "https" {
			if conf.HTTP3 {
				client = H3Transporter(conf, &sni, &quic.Config{})
			} else if conf.TLS.Utls.Enable {
				uclient, utlsE := UtlsTransporter(parentCtx, conf, fingerprint, sni, addr, fragment)
				if utlsE != nil {
					return "FAILED"
				}
				client = uclient
			} else {
				client = TLSTransporter(conf, &sni)
			}
		} else {
			client = &http.Client{}
		}
	}

	prevTimeout := client.Timeout
	client.Timeout = 0
	defer func() {
		client.Timeout = prevTimeout
	}()

	timeoutDur := time.Millisecond * time.Duration(timeoutMs)
	ctx, cancel := context.WithTimeout(parentCtx, timeoutDur)
	defer cancel()

	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: configUrl.Scheme, Host: addr.String(), Path: configUrl.Path, RawQuery: configUrl.RawQuery},
		Host:   configUrl.Host,
	}
	req = req.WithContext(ctx)

	resp, httpErr := client.Do(req)
	if httpErr != nil {
		if logErr != nil {
			logErr(httpErr.Error())
		}
		return "FAILED"
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if logErr != nil {
			logErr(fmt.Sprintf("Download host status code: %s", resp.Status))
		}
		return "FAILED"
	}

	ch := make(chan string, 1)
	go func() {
		buf := make([]byte, 1024*8)
		read := 0
		start := time.Now()
		for {
			if read >= targetBytes {
				break
			}
			size, readErr := resp.Body.Read(buf)
			read += size
			if readErr != nil {
				break
			}
		}
		elapsed := time.Now()
		if read < targetBytes {
			ch <- "JAMMED"
			return
		}
		latency := float32(elapsed.UnixMilli()-start.UnixMilli()) / 1000
		if latency <= 0 {
			latency = float32(time.Since(start).Nanoseconds()) / 1e9
		}
		bytesPerSecond := float32(read) / latency
		ch <- fmt.Sprintf("%fMB/S", bytesPerSecond/1000000)
	}()

	select {
	case <-parentCtx.Done():
		return "FAILED"
	case report := <-ch:
		return report
	case <-time.After(timeoutDur):
		return "Timeout"
	}
}

func UploadTest(parentCtx context.Context, preclient *http.Client, conf *Conf, addr net.TCPAddr, fingerprint utls.ClientHelloID, fragment *Fragment, logErr func(string)) string {
	rawURL := conf.UploadTest.Url
	if rawURL == "" {
		rawURL = DefaultUploadURL
	}
	configUrl, err := url.Parse(rawURL)
	if err != nil {
		if logErr != nil {
			logErr(fmt.Sprintf("Invalid UploadTest URL: %v", err))
		}
		return "FAILED"
	}

	payloadBytes := conf.UploadTest.PayloadBytes
	if payloadBytes <= 0 {
		if conf.UploadTest.TargetBytes > 0 {
			payloadBytes = conf.UploadTest.TargetBytes
		} else {
			payloadBytes = DefaultUploadPayloadBytes
		}
	}
	targetBytes := conf.UploadTest.TargetBytes
	if targetBytes <= 0 {
		targetBytes = min(payloadBytes, DefaultUploadTargetBytes)
	}
	timeoutMs := conf.UploadTest.Timeout
	if timeoutMs <= 0 {
		timeoutMs = DefaultUploadTimeoutMs
	}

	sni := conf.UploadTest.SNI
	if sni == "" && conf.TLS.SNI != "" {
		sni = conf.TLS.SNI
	}

	var client *http.Client
	if !conf.UploadTest.SeparateConnection && preclient != nil {
		client = preclient
	} else {
		if configUrl.Scheme == "https" {
			if conf.HTTP3 {
				client = H3Transporter(conf, &sni, &quic.Config{})
			} else if conf.TLS.Utls.Enable {
				uclient, utlsE := UtlsTransporter(parentCtx, conf, fingerprint, sni, addr, fragment)
				if utlsE != nil {
					return "FAILED"
				}
				client = uclient
			} else {
				client = TLSTransporter(conf, &sni)
			}
		} else {
			client = &http.Client{}
		}
	}

	prevTimeout := client.Timeout
	client.Timeout = 0
	defer func() {
		client.Timeout = prevTimeout
	}()

	timeoutDuration := time.Millisecond * time.Duration(timeoutMs)
	ctx, cancel := context.WithTimeout(parentCtx, timeoutDuration)
	defer cancel()

	ch := make(chan string, 1)
	go func() {
		start := time.Now()
		bodyReader := newUploadPayloadReader(ctx, payloadBytes)

		headers := http.Header{}
		if conf.Headers != nil {
			headers = maps.Clone(conf.Headers)
		}
		headers.Set("Host", configUrl.Host)
		headers.Set("Content-Type", "application/octet-stream")

		req := &http.Request{
			Method:        http.MethodPost,
			URL:           &url.URL{Scheme: configUrl.Scheme, Host: addr.String(), Path: configUrl.Path, RawQuery: configUrl.RawQuery},
			Host:          configUrl.Host,
			Header:        headers,
			Body:          bodyReader,
			ContentLength: int64(payloadBytes),
		}
		req = req.WithContext(ctx)

		resp, httpErr := client.Do(req)
		uploaded := bodyReader.BytesUploaded()

		if httpErr != nil {
			if parentCtx.Err() != nil {
				ch <- "FAILED"
				return
			}
			if errors.Is(httpErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				if uploaded < targetBytes {
					ch <- "JAMMED"
					return
				}
				latency := bodyReader.ElapsedSeconds(start)
				bytesPerSecond := float32(uploaded) / latency
				ch <- fmt.Sprintf("%fMB/S", bytesPerSecond/1000000)
				return
			}
			if uploaded > 0 {
				ch <- "JAMMED"
				return
			}
			if logErr != nil {
				logErr(httpErr.Error())
			}
			ch <- "FAILED"
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if logErr != nil {
				logErr(fmt.Sprintf("Upload host status code: %s", resp.Status))
			}
			ch <- "FAILED"
			return
		}

		if uploaded < targetBytes {
			ch <- "JAMMED"
			return
		}

		latency := bodyReader.ElapsedSeconds(start)
		bytesPerSecond := float32(uploaded) / latency
		ch <- fmt.Sprintf("%fMB/S", bytesPerSecond/1000000)
	}()

	select {
	case <-parentCtx.Done():
		cancel()
		return "FAILED"
	case report := <-ch:
		return report
	case <-time.After(timeoutDuration + 250*time.Millisecond):
		cancel()
		return "JAMMED"
	}
}

func ParseMbps(report string) float64 {
	s := strings.TrimSuffix(strings.TrimSpace(report), "MB/S")
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0
	}
	return v
}
