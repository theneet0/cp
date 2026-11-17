package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/quic-go/quic-go"
	utls "github.com/refraction-networking/utls"
)

const (
	defaultUploadURL          = "https://speed.cloudflare.com/__up"
	defaultUploadPayloadBytes = 10000000
	defaultUploadTargetBytes  = 5000000
	defaultUploadTimeoutMs    = 5000
	uploadChunkSize           = 1024 * 8
)

var uploadPatternChunk [uploadChunkSize]byte

func init() {
	const pattern = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for i := range uploadPatternChunk {
		uploadPatternChunk[i] = pattern[i%len(pattern)]
	}
}

// uploadPayloadReader streams a fixed-size payload without allocating a large buffer
// in memory per test, while tracking actual bytes read by the HTTP transport.
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

func uploadTest(preclient *http.Client, conf *Conf, addr net.TCPAddr, fingerprint utls.ClientHelloID, fragment *Fragment) string {
	rawURL := conf.UploadTest.Url
	if rawURL == "" {
		rawURL = defaultUploadURL
	}

	configUrl, configUrlErr := url.Parse(rawURL)
	if configUrlErr != nil {
		log.Fatalln(configUrlErr)
	}

	payloadBytes := conf.UploadTest.PayloadBytes
	if payloadBytes <= 0 {
		if conf.UploadTest.TargetBytes > 0 {
			payloadBytes = conf.UploadTest.TargetBytes
		} else {
			payloadBytes = defaultUploadPayloadBytes
		}
	}

	targetBytes := conf.UploadTest.TargetBytes
	if targetBytes <= 0 {
		targetBytes = min(payloadBytes, defaultUploadTargetBytes)
	}

	timeoutMs := conf.UploadTest.Timeout
	if timeoutMs <= 0 {
		timeoutMs = defaultUploadTimeoutMs
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
				client = h3transporter(
					conf,
					&sni,
					&quic.Config{},
				)
			} else {
				if conf.TLS.Utls.Enable {
					uclient, utlsE := utlsTransporter(conf, fingerprint, sni, addr, fragment)
					if utlsE != nil {
						return "FAILED"
					}
					client = uclient
				} else {
					client = tlsTransporter(conf, &sni)
				}
			}
		} else {
			client = &http.Client{}
		}
	}

	// Ensure preclient's shorter Maxlatency timeout does not prematurely abort the upload test;
	// timeout is enforced via UploadTest.Timeout context and timer.
	prevTimeout := client.Timeout
	client.Timeout = 0
	defer func() {
		client.Timeout = prevTimeout
	}()

	timeoutDuration := time.Millisecond * time.Duration(timeoutMs)
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	type uploadResult struct {
		report string
	}
	ch := make(chan uploadResult, 1)

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

		respone, http_err := client.Do(req)
		uploaded := bodyReader.BytesUploaded()

		if http_err != nil {
			// If timeout occurred or connection dropped/errored mid-transfer:
			if errors.Is(http_err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				if uploaded < targetBytes {
					ch <- uploadResult{report: "JAMMED"}
					return
				}
				latency := bodyReader.ElapsedSeconds(start)
				bytesPerSecond := float32(uploaded) / latency
				ch <- uploadResult{report: fmt.Sprintf("%fMB/S", bytesPerSecond/1000000)}
				return
			}

			if uploaded > 0 {
				ch <- uploadResult{report: "JAMMED"}
				return
			}

			color.Red("%s", http_err.Error())
			ch <- uploadResult{report: "FAILED"}
			return
		}
		defer respone.Body.Close()
		_, _ = io.Copy(io.Discard, respone.Body)

		if respone.StatusCode < 200 || respone.StatusCode >= 300 {
			color.Red("Upload host status code: %s", respone.Status)
			ch <- uploadResult{report: "FAILED"}
			return
		}

		if uploaded < targetBytes {
			ch <- uploadResult{report: "JAMMED"}
			return
		}

		latency := bodyReader.ElapsedSeconds(start)
		bytesPerSecond := float32(uploaded) / latency
		ch <- uploadResult{report: fmt.Sprintf("%fMB/S", bytesPerSecond/1000000)}
	}()

	select {
	case res := <-ch:
		return res.report
	case <-time.After(timeoutDuration + 250*time.Millisecond):
		cancel()
		return "JAMMED"
	}
}
