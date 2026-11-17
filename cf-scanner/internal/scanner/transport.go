package scanner

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type Fragment struct {
	PacketsFrom uint64
	PacketsTo   uint64
	LengthMin   uint64
	LengthMax   uint64
	IntervalMin uint64
	IntervalMax uint64
	MaxSplitMin uint64
	MaxSplitMax uint64
}

type ConnWrap struct {
	fragment *Fragment
	conn     net.Conn
	count    uint64
}

func (c ConnWrap) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

func (c ConnWrap) Close() error {
	return c.conn.Close()
}

func (c ConnWrap) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c ConnWrap) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c ConnWrap) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c ConnWrap) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c ConnWrap) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (f ConnWrap) Write(b []byte) (n int, err error) {
	f.count++

	if f.fragment.PacketsFrom == 0 && f.fragment.PacketsTo == 1 {
		if f.count != 1 || len(b) <= 5 || b[0] != 22 {
			return f.conn.Write(b)
		}
		recordLen := 5 + ((int(b[3]) << 8) | int(b[4]))
		if len(b) < recordLen {
			return f.conn.Write(b)
		}
		data := b[5:recordLen]
		buff := make([]byte, 2048)
		var hello []byte
		maxSplit := RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
		var splitNum int64
		for from := 0; ; {
			to := from + int(RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
			splitNum++
			if to > len(data) || (maxSplit > 0 && splitNum >= maxSplit) {
				to = len(data)
			}
			l := to - from
			if 5+l > len(buff) {
				buff = make([]byte, 5+l)
			}
			copy(buff[:3], b)
			copy(buff[5:], data[from:to])
			from = to
			buff[3] = byte(l >> 8)
			buff[4] = byte(l)
			if f.fragment.IntervalMax == 0 {
				hello = append(hello, buff[:5+l]...)
			} else {
				_, err := f.conn.Write(buff[:5+l])
				time.Sleep(time.Duration(RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
				if err != nil {
					return 0, err
				}
			}
			if from == len(data) {
				if len(hello) > 0 {
					_, err := f.conn.Write(hello)
					if err != nil {
						return 0, err
					}
				}
				if len(b) > recordLen {
					n, err := f.conn.Write(b[recordLen:])
					if err != nil {
						return recordLen + n, err
					}
				}
				return len(b), nil
			}
		}
	}

	if f.fragment.PacketsFrom != 0 && (f.count < f.fragment.PacketsFrom || f.count > f.fragment.PacketsTo) {
		return f.conn.Write(b)
	}
	maxSplit := RandBetween(int64(f.fragment.MaxSplitMin), int64(f.fragment.MaxSplitMax))
	var splitNum int64
	for from := 0; ; {
		to := from + int(RandBetween(int64(f.fragment.LengthMin), int64(f.fragment.LengthMax)))
		splitNum++
		if to > len(b) || (maxSplit > 0 && splitNum >= maxSplit) {
			to = len(b)
		}
		n, err := f.conn.Write(b[from:to])
		from += n
		if err != nil {
			return from, err
		}
		time.Sleep(time.Duration(RandBetween(int64(f.fragment.IntervalMin), int64(f.fragment.IntervalMax))) * time.Millisecond)
		if from >= len(b) {
			return from, nil
		}
	}
}

func RandBetween(from int64, to int64) int64 {
	if from == to {
		return from
	}
	if from > to {
		from, to = to, from
	}
	bigInt, err := crand.Int(crand.Reader, big.NewInt(to-from))
	if err != nil {
		return from
	}
	return from + bigInt.Int64()
}

func SendNoises(ctx context.Context, udp net.PacketConn, addr *net.UDPAddr, packets []NoisePacket) {
	for _, packet := range packets {
		select {
		case <-ctx.Done():
			return
		default:
		}
		switch packet.Type {
		case "str":
			_, _ = udp.WriteTo([]byte(packet.Payload), addr)
		case "base64":
			if b64, err := base64.StdEncoding.DecodeString(packet.Payload); err == nil {
				_, _ = udp.WriteTo(b64, addr)
			}
		case "hex":
			if h, err := hex.DecodeString(packet.Payload); err == nil {
				_, _ = udp.WriteTo(h, addr)
			}
		case "rand":
			sz := RandomRange(packet.Payload)
			if sz > 0 {
				bytes := make([]byte, sz)
				if _, err := crand.Read(bytes); err == nil {
					_, _ = udp.WriteTo(bytes, addr)
				}
			}
		}
		sleepMs := RandomRange(packet.Sleep)
		if sleepMs > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Millisecond * time.Duration(sleepMs)):
			}
		}
	}
}

func CalcJitter(list []float64) float64 {
	if len(list) == 0 {
		return 0
	}
	sum := 0.0
	for _, el := range list {
		sum += el
	}
	avg := sum / float64(len(list))
	zigma := 0.0
	for _, el := range list {
		zigma += math.Abs(el - avg)
	}
	return zigma / float64(len(list))
}

func ParseRange(r string) (int, int) {
	r = strings.TrimSpace(r)
	if r == "" || !strings.Contains(r, "-") {
		v, err := strconv.Atoi(r)
		if err != nil {
			return 0, 0
		}
		return v, v
	}
	ab := strings.SplitN(r, "-", 2)
	a, errA := strconv.Atoi(strings.TrimSpace(ab[0]))
	b, errB := strconv.Atoi(strings.TrimSpace(ab[1]))
	if errA != nil || errB != nil {
		return 0, 0
	}
	if a > b {
		a, b = b, a
	}
	return a, b
}

func RandomRange(r string) int {
	a, b := ParseRange(r)
	if b <= a {
		return max(0, a)
	}
	return rand.Intn(b-a+1) + a
}

func RandomString(n string) string {
	sz := RandomRange(n)
	if sz <= 0 {
		sz = 16
	}
	bytes := make([]byte, sz)
	_, _ = crand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func FingerprintID(f string) utls.ClientHelloID {
	switch strings.ToLower(strings.TrimSpace(f)) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "chrome", "":
		return utls.HelloChrome_Auto
	case "360":
		return utls.Hello360_Auto
	case "ios":
		return utls.HelloIOS_Auto
	default:
		return utls.HelloChrome_Auto
	}
}

func BuildFragment(cfg FragmentConfig) Fragment {
	lMin, lMax := ParseRange(cfg.Length)
	dMin, dMax := ParseRange(cfg.Delay)
	sMin, sMax := ParseRange(cfg.MaxSplitValue())
	return Fragment{
		PacketsFrom: 0,
		PacketsTo:   1,
		LengthMin:   uint64(lMin),
		LengthMax:   uint64(lMax),
		IntervalMin: uint64(dMin),
		IntervalMax: uint64(dMax),
		MaxSplitMin: uint64(sMin),
		MaxSplitMax: uint64(sMax),
	}
}

func H3Transporter(conf *Conf, sni *string, qc *quic.Config) *http.Client {
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
					_ = udp.Close()
					return nil, uaddrErr
				}
				SendNoises(ctx, udp, uaddr, conf.Noises.Packets)
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

func UtlsTransporter(ctx context.Context, conf *Conf, fingerprint utls.ClientHelloID, sni string, addr net.TCPAddr, fragment *Fragment) (*http.Client, error) {
	tcpTimeout := conf.TLS.Utls.TcpTimeout
	if tcpTimeout <= 0 {
		tcpTimeout = 1000
	}
	attempts := conf.TLS.Utls.TcpConnectAttempt
	if attempts <= 0 {
		attempts = 1
	}

	dialer := &net.Dialer{Timeout: time.Millisecond * time.Duration(tcpTimeout)}

	var dialConn net.Conn
	var err error
	for reconnect := range attempts {
		dialConn, err = dialer.DialContext(ctx, "tcp", addr.String())
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
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
	hsCtx, cancel := context.WithTimeout(ctx, time.Millisecond*time.Duration(conf.Maxlatency))
	defer cancel()
	if err := uTlsConn.HandshakeContext(hsCtx); err != nil {
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

func TLSTransporter(conf *Conf, sni *string) *http.Client {
	if sni == nil {
		sni = &conf.TLS.SNI
	}
	tr := http.Transport{
		TLSClientConfig: &tls.Config{ServerName: *sni, InsecureSkipVerify: conf.TLS.Insecure, NextProtos: conf.TLS.Alpn},
		Protocols:       &http.Protocols{},
	}
	tr.Protocols.SetHTTP1(true)
	tr.Protocols.SetHTTP2(true)

	return &http.Client{
		Transport: &tr,
	}
}

type FileMutex struct {
	file   *os.File
	locker sync.Mutex
}

func OpenResultFile(csv bool) (*FileMutex, error) {
	if csv {
		willBeCreated := false
		if _, err := os.Stat("result.csv"); err != nil {
			willBeCreated = true
		}
		f, err := os.OpenFile("result.csv", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			return nil, err
		}
		if willBeCreated {
			_, _ = f.WriteString("ip:port,ping,latency,jitter,download,upload\n")
		}
		return &FileMutex{file: f}, nil
	}
	f, err := os.OpenFile("result.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	return &FileMutex{file: f}, nil
}

func (fm *FileMutex) Write(data string) error {
	if fm == nil || fm.file == nil {
		return nil
	}
	fm.locker.Lock()
	defer fm.locker.Unlock()
	_, err := fm.file.WriteString(data)
	return err
}

func (fm *FileMutex) Close() error {
	if fm == nil || fm.file == nil {
		return nil
	}
	fm.locker.Lock()
	defer fm.locker.Unlock()
	return fm.file.Close()
}
