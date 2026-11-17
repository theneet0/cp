package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

const (
	DefaultUploadURL          = "https://speed.cloudflare.com/__up"
	DefaultUploadPayloadBytes = 10000000
	DefaultUploadTargetBytes  = 5000000
	DefaultUploadTimeoutMs    = 5000

	DefaultDownloadURL         = "https://speed.cloudflare.com/__down?bytes=10000000"
	DefaultDownloadTargetBytes = 5000000
	DefaultDownloadTimeoutMs   = 5000
)

type DS struct {
	Enable         bool   `json:"Enable"`
	DomainAsSNI    bool   `json:"DomainAsSNI"`
	DomainAsHost   bool   `json:"DomainAsHost"`
	SkipIPV6       bool   `json:"SkipIPV6"`
	Shuffle        bool   `json:"Shuffle"`
	DomainListPath string `json:"DomainListPath"`
}

type NoisePacket struct {
	Type    string `json:"Type"`
	Payload string `json:"Payload"`
	Sleep   string `json:"Sleep"`
}

type NoiseConfig struct {
	Enable  bool          `json:"Enable"`
	Packets []NoisePacket `json:"Packets"`
}

type DownloadConfig struct {
	Enable             bool   `json:"Enable"`
	SeparateConnection bool   `json:"SeparateConnection"`
	Url                string `json:"Url"`
	SNI                string `json:"SNI"`
	TargetBytes        int    `json:"TargetBytes"`
	Timeout            int    `json:"Timeout"`
}

type UploadConfig struct {
	Enable             bool   `json:"Enable"`
	SeparateConnection bool   `json:"SeparateConnection"`
	Url                string `json:"Url"`
	SNI                string `json:"SNI"`
	PayloadBytes       int    `json:"PayloadBytes"`
	TargetBytes        int    `json:"TargetBytes"`
	Timeout            int    `json:"Timeout"`
}

type FragmentConfig struct {
	Enable   bool    `json:"Enable"`
	Length   string  `json:"Length"`
	Delay    string  `json:"Delay"`
	MaxSplit *string `json:"MaxSplit"`
}

func (f FragmentConfig) MaxSplitValue() string {
	if f.MaxSplit == nil {
		return ""
	}
	return *f.MaxSplit
}

type UtlsConfig struct {
	Enable            bool           `json:"Enable"`
	Fingerprint       string         `json:"Fingerprint"`
	TcpTimeout        int64          `json:"TcpTimeout"`
	TcpConnectAttempt int            `json:"TcpConnectAttempt"`
	Fragment          FragmentConfig `json:"Fragment"`
}

type TLSConfig struct {
	Enable   bool       `json:"Enable"`
	SNI      string     `json:"SNI"`
	Insecure bool       `json:"Insecure"`
	Alpn     []string   `json:"Alpn"`
	Utls     UtlsConfig `json:"Utls"`
}

type JitterConfig struct {
	Enable    bool    `json:"Enable"`
	MaxJitter float64 `json:"MaxJitter"`
	Samples   int     `json:"Samples"`
	Interval  int64   `json:"Interval"`
}

type PingConfig struct {
	Enable     bool    `json:"Enable"`
	MaxPing    float64 `json:"MaxPing"`
	Privileged bool    `json:"Privileged"`
	Size       string  `json:"Size"`
}

type Conf struct {
	ProgressBar        bool                `json:"ProgressBar"`
	Log                bool                `json:"Log"`
	CSV                bool                `json:"CSV"`
	RandomScan         bool                `json:"RandomScan"`
	Hostname           string              `json:"Hostname"`
	Ports              []int               `json:"Ports"`
	Path               string              `json:"Path"`
	Headers            map[string][]string `json:"Headers"`
	ResponseHeader     map[string]string   `json:"ResponseHeader"`
	ResponseStatusCode []int               `json:"ResponseStatusCode"`
	Padding            bool                `json:"Padding"`
	PaddingSize        string              `json:"PaddingSize"`
	Ping               PingConfig          `json:"Ping"`
	Goroutines         int                 `json:"Goroutines"`
	Maxlatency         int64               `json:"Maxlatency"`
	Jitter             JitterConfig        `json:"Jitter"`
	IpVersion          int                 `json:"IpVersion"`
	IplistPath         string              `json:"IplistPath"`
	IgnoreRange        []string            `json:"IgnoreRange"`
	AllowRange         []string            `json:"AllowRange"`
	TLS                TLSConfig           `json:"TLS"`
	HTTP3              bool                `json:"HTTP/3"`
	Noises             NoiseConfig         `json:"Noises"`
	DomainScan         DS                  `json:"DomainScan"`
	DownloadTest       DownloadConfig      `json:"DownloadTest"`
	UploadTest         UploadConfig        `json:"UploadTest"`
}

func DefaultConfig() Conf {
	return Conf{
		ProgressBar: true,
		Log:         true,
		CSV:         false,
		RandomScan:  true,
		Hostname:    "cp.cloudflare.com",
		Ports:       []int{},
		Path:        "/",
		Headers: map[string][]string{
			"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0"},
		},
		ResponseHeader: map[string]string{
			"Server": "cloudflare",
		},
		ResponseStatusCode: []int{200, 204},
		Padding:            true,
		PaddingSize:        "100-1000",
		Ping: PingConfig{
			Enable:     true,
			MaxPing:    300,
			Privileged: true,
			Size:       "24-65",
		},
		Goroutines: 16,
		Maxlatency: 2000,
		Jitter: JitterConfig{
			Enable:    true,
			MaxJitter: 50.0,
			Samples:   5,
			Interval:  200,
		},
		IpVersion:   4,
		IplistPath:  "ipv4.txt",
		IgnoreRange: []string{},
		AllowRange:  []string{},
		TLS: TLSConfig{
			Enable:   true,
			SNI:      "cp.cloudflare.com",
			Insecure: false,
			Alpn:     []string{"h2", "http/1.1"},
			Utls: UtlsConfig{
				Enable:            true,
				Fingerprint:       "chrome",
				TcpTimeout:        1000,
				TcpConnectAttempt: 1,
				Fragment: FragmentConfig{
					Enable:   false,
					Length:   "50-100",
					Delay:    "10-15",
					MaxSplit: nil,
				},
			},
		},
		HTTP3: false,
		Noises: NoiseConfig{
			Enable: false,
			Packets: []NoisePacket{
				{
					Type:    "rand",
					Payload: "1-10",
					Sleep:   "20-50",
				},
				{
					Type:    "rand",
					Payload: "1-20",
					Sleep:   "20-50",
				},
			},
		},
		DomainScan: DS{
			Enable:         false,
			DomainAsSNI:    false,
			DomainAsHost:   false,
			Shuffle:        true,
			SkipIPV6:       true,
			DomainListPath: "cloudfalare-domains.txt",
		},
		DownloadTest: DownloadConfig{
			Enable:             false,
			SeparateConnection: false,
			Url:                DefaultDownloadURL,
			SNI:                "cp.cloudflare.com",
			TargetBytes:        DefaultDownloadTargetBytes,
			Timeout:            DefaultDownloadTimeoutMs,
		},
		UploadTest: UploadConfig{
			Enable:             false,
			SeparateConnection: false,
			Url:                DefaultUploadURL,
			SNI:                "cp.cloudflare.com",
			PayloadBytes:       DefaultUploadPayloadBytes,
			TargetBytes:        DefaultUploadTargetBytes,
			Timeout:            DefaultUploadTimeoutMs,
		},
	}
}

func ParseConfigJSON(data []byte) (Conf, error) {
	cfg := DefaultConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}

	// Support optional legacy "Noise" key if "Noises" was not explicitly populated
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err == nil {
		if _, hasNoises := rawMap["Noises"]; !hasNoises {
			if noiseRaw, hasNoise := rawMap["Noise"]; hasNoise {
				_ = json.Unmarshal(noiseRaw, &cfg.Noises)
			}
		}
	}

	NormalizeConfig(&cfg)
	return cfg, nil
}

func NormalizeConfig(cfg *Conf) {
	if cfg.Ports == nil {
		cfg.Ports = []int{}
	}
	if cfg.IgnoreRange == nil {
		cfg.IgnoreRange = []string{}
	}
	if cfg.AllowRange == nil {
		cfg.AllowRange = []string{}
	}
	if cfg.Headers == nil {
		cfg.Headers = map[string][]string{}
	}
	if cfg.ResponseHeader == nil {
		cfg.ResponseHeader = map[string]string{}
	}
	if cfg.ResponseStatusCode == nil {
		cfg.ResponseStatusCode = []int{200, 204}
	}
	if cfg.TLS.Alpn == nil {
		cfg.TLS.Alpn = []string{"h2", "http/1.1"}
	}
	if cfg.Noises.Packets == nil {
		cfg.Noises.Packets = []NoisePacket{}
	}
	if cfg.Goroutines <= 0 {
		cfg.Goroutines = 1
	}
	if cfg.Maxlatency <= 0 {
		cfg.Maxlatency = 2000
	}
	if cfg.IpVersion != 4 && cfg.IpVersion != 6 {
		cfg.IpVersion = 4
	}
	if cfg.DownloadTest.Url == "" {
		cfg.DownloadTest.Url = DefaultDownloadURL
	}
	if cfg.DownloadTest.TargetBytes <= 0 {
		cfg.DownloadTest.TargetBytes = DefaultDownloadTargetBytes
	}
	if cfg.DownloadTest.Timeout <= 0 {
		cfg.DownloadTest.Timeout = DefaultDownloadTimeoutMs
	}
	if cfg.UploadTest.Url == "" {
		cfg.UploadTest.Url = DefaultUploadURL
	}
	if cfg.UploadTest.PayloadBytes <= 0 {
		if cfg.UploadTest.TargetBytes > 0 {
			cfg.UploadTest.PayloadBytes = cfg.UploadTest.TargetBytes
		} else {
			cfg.UploadTest.PayloadBytes = DefaultUploadPayloadBytes
		}
	}
	if cfg.UploadTest.TargetBytes <= 0 {
		cfg.UploadTest.TargetBytes = min(cfg.UploadTest.PayloadBytes, DefaultUploadTargetBytes)
	}
	if cfg.UploadTest.Timeout <= 0 {
		cfg.UploadTest.Timeout = DefaultUploadTimeoutMs
	}
}

func LoadConfig(path string) (Conf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return DefaultConfig(), err
	}
	return ParseConfigJSON(data)
}

func SaveConfig(path string, cfg Conf) error {
	NormalizeConfig(&cfg)
	data, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
}

func ValidateConfig(cfg *Conf) []string {
	var warnings []string
	if (cfg.DownloadTest.Enable || cfg.UploadTest.Enable) && cfg.Goroutines > 1 {
		warnings = append(warnings, fmt.Sprintf(
			"Speed test is enabled with Goroutines=%d. Set Goroutines to 1 to prevent bandwidth contention and inaccurate speed measurements.",
			cfg.Goroutines,
		))
	}
	if cfg.TLS.Utls.Enable && len(cfg.TLS.Alpn) > 0 {
		alpnJoined := strings.Join(cfg.TLS.Alpn, ",")
		if alpnJoined != "h2,http/1.1" {
			warnings = append(warnings, "When uTLS is enabled, ALPN is automatically negotiated by the uTLS fingerprint (h2, http/1.1).")
		}
	}
	if cfg.HTTP3 && (cfg.DownloadTest.Enable && !cfg.DownloadTest.SeparateConnection || cfg.UploadTest.Enable && !cfg.UploadTest.SeparateConnection) {
		warnings = append(warnings, "When HTTP/3 is enabled with speed tests, enabling SeparateConnection is recommended.")
	}
	return warnings
}
