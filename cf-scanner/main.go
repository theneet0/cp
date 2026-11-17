package main

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/radioactiveAHM/cf-scanner/internal/scanner"
	utls "github.com/refraction-networking/utls"
	"github.com/schollz/progressbar/v3"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"golang.org/x/net/http2"
)

//go:embed all:frontend
var assets embed.FS

type DS = scanner.DS
type NoisePacket = scanner.NoisePacket
type NoiseConfig = scanner.NoiseConfig
type DownloadConfig = scanner.DownloadConfig
type UploadConfig = scanner.UploadConfig
type FragmentConfig = scanner.FragmentConfig
type UtlsConfig = scanner.UtlsConfig
type TLSConfig = scanner.TLSConfig
type JitterConfig = scanner.JitterConfig
type PingConfig = scanner.PingConfig
type Conf = scanner.Conf

func defaultConf() Conf {
	return scanner.DefaultConfig()
}

func main() {
	cliMode := flag.Bool("cli", false, "Run cf-scanner in headless CLI mode")
	confPath := flag.String("c", "conf.json", "Path to configuration JSON file")
	flag.Parse()

	if *cliMode {
		runCLI(*confPath)
		return
	}

	app := NewApp()

	err := wails.Run(&options.App{
		Title:     "CF-Scanner — Cloudflare CDN & Edge IP Scanner",
		Width:     1340,
		Height:    860,
		MinWidth:  1024,
		MinHeight: 680,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 15, G: 23, B: 42, A: 1},
		OnStartup:        app.startup,
		OnBeforeClose:    app.beforeClose,
		OnShutdown:       app.shutdown,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			DisableWindowIcon:    false,
			Theme:                windows.SystemDefault,
		},
	})
	if err != nil {
		log.Fatalln(err)
	}
}

func runCLI(confPath string) {
	conf, err := scanner.LoadConfig(confPath)
	if err != nil {
		log.Fatalln(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runner := scanner.NewRunner()
	var pbar *progressbar.ProgressBar
	var lastScanned int64

	err = runner.Run(ctx, conf, scanner.Hooks{
		OnProgress: func(p scanner.ProgressEvent) {
			if conf.ProgressBar && p.Total > 0 {
				if pbar == nil {
					pbar = progressbar.Default(p.Total)
				}
				delta := p.Scanned - lastScanned
				if delta > 0 {
					_ = pbar.Add64(delta)
					lastScanned = p.Scanned
				}
			}
		},
		OnLog: func(l scanner.LogEvent) {
			if conf.ProgressBar || !conf.Log {
				return
			}
			switch l.Level {
			case "error":
				color.Red("%s", l.Message)
			case "warn":
				color.Yellow("%s", l.Message)
			case "success":
				color.Green("%s", l.Message)
			default:
				fmt.Println(l.Message)
			}
		},
	})
	if err != nil {
		log.Fatalln(err)
	}
}

func matchHeaders(headers http.Header, tomatch map[string]string) error {
	for header, value := range tomatch {
		if headers.Get(header) == value {
			continue
		}
		return fmt.Errorf("response header not matching")
	}
	return nil
}

func fgen(f string) utls.ClientHelloID {
	return scanner.FingerprintID(f)
}

func RandomString(n string) string {
	bytes := make([]byte, randomRange(n))
	_, err := crand.Read(bytes)
	if err != nil {
		log.Fatalln(err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func parseRange(r string) (a int, b int) {
	return scanner.ParseRange(r)
}

func randomRange(r string) int {
	ab := strings.Split(r, "-")
	if len(ab) != 2 {
		return 0
	}
	a, aErr := strconv.Atoi(ab[0])
	if aErr != nil {
		return 0
	}
	b, bErr := strconv.Atoi(ab[1])
	if bErr != nil || b < a {
		return a
	}
	return rand.Intn(b-a+1) + a
}

func h3transporter(conf *Conf, sni *string, qc *quic.Config) *http.Client {
	if sni == nil {
		sni = &conf.TLS.SNI
	}

	tconf := tls.Config{ServerName: *sni, NextProtos: []string{"h3"}, InsecureSkipVerify: conf.TLS.Insecure}
	var h3tr http3.Transport
	if conf.Noises.Enable {
		h3tr = http3.Transport{
			QUICConfig:      qc,
			TLSClientConfig: &tconf,
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				udp, udpErr := net.ListenPacket("udp", "0.0.0.0:0")
				if udpErr != nil {
					return nil, udpErr
				}
				uaddr, uaddrErr := net.ResolveUDPAddr("udp", addr)
				if uaddrErr != nil {
					return nil, uaddrErr
				}
				SendNoises(udp, uaddr, conf.Noises.Packets)
				return quic.Dial(ctx, udp, uaddr, tlsCfg, cfg)
			},
		}
	} else {
		h3tr = http3.Transport{TLSClientConfig: &tconf}
	}
	return &http.Client{
		Transport: &h3tr,
	}
}

func utlsTransporter(conf *Conf, fingerprint utls.ClientHelloID, sni string, addr net.TCPAddr, fragment *Fragment) (*http.Client, error) {
	dialer := &net.Dialer{Timeout: time.Millisecond * time.Duration(conf.TLS.Utls.TcpTimeout)}

	var dialConn net.Conn
	var err error
	attempts := max(1, conf.TLS.Utls.TcpConnectAttempt)
	for reconnect := range attempts {
		dialConn, err = dialer.Dial("tcp", addr.String())
		if err != nil {
			if !errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
		} else {
			break
		}

		if reconnect+1 == attempts {
			return nil, err
		}
	}

	uTlsConf := utls.Config{InsecureSkipVerify: conf.TLS.Insecure}
	if strings.Contains(sni, "{ip}") {
		sni = addr.IP.String()
	}
	if sni != "" {
		uTlsConf.ServerName = sni
	}

	if conf.TLS.Utls.Fragment.Enable {
		dialConn = ConnWrap{
			fragment: fragment,
			conn:     dialConn,
			count:    0,
		}
	}

	uTlsConn := utls.UClient(dialConn, &uTlsConf, fingerprint)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*time.Duration(conf.Maxlatency))
	defer cancel()
	if err := uTlsConn.HandshakeContext(ctx); err != nil {
		_ = uTlsConn.Close()
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%s: UTLS handshake timeout", addr.String())
		}
		return nil, fmt.Errorf("%s: UTLS handshake error: %w", addr.String(), err)
	}

	if uTlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		return &http.Client{
			Transport: &http2.Transport{
				DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
					return uTlsConn, nil
				},
			},
		}, nil
	}
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return uTlsConn, nil
			},
		},
	}, nil
}

func tlsTransporter(conf *Conf, sni *string) *http.Client {
	return scanner.TLSTransporter(conf, sni)
}
