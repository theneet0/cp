package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/radioactiveAHM/cf-scanner/internal/scanner"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx        context.Context
	mu         sync.Mutex
	configPath string
	config     scanner.Conf
	runner     *scanner.Runner
	results    []scanner.ScanResult
}

func NewApp() *App {
	cfgPath := "conf.json"
	cfg, err := scanner.LoadConfig(cfgPath)
	if err != nil {
		cfg = scanner.DefaultConfig()
	}
	return &App{
		configPath: cfgPath,
		config:     cfg,
		runner:     scanner.NewRunner(),
		results:    make([]scanner.ScanResult, 0, 128),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) beforeClose(ctx context.Context) (prevent bool) {
	a.runner.Stop()
	return false
}

func (a *App) shutdown(ctx context.Context) {
	a.runner.Stop()
}

func (a *App) GetConfig() (scanner.Conf, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg, err := scanner.LoadConfig(a.configPath)
	if err == nil {
		a.config = cfg
	}
	return a.config, nil
}

func (a *App) SaveConfig(cfg scanner.Conf) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	scanner.NormalizeConfig(&cfg)
	a.config = cfg
	return scanner.SaveConfig(a.configPath, cfg)
}

func (a *App) LoadConfigFromDisk(path string) (scanner.Conf, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if strings.TrimSpace(path) == "" {
		path = a.configPath
	}
	cfg, err := scanner.LoadConfig(path)
	if err != nil {
		return a.config, err
	}
	a.configPath = path
	a.config = cfg
	return cfg, nil
}

func (a *App) ResetDefaultConfig() scanner.Conf {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = scanner.DefaultConfig()
	return a.config
}

func (a *App) ValidateConfig(cfg scanner.Conf) []string {
	scanner.NormalizeConfig(&cfg)
	return scanner.ValidateConfig(&cfg)
}

func (a *App) ParseRawConfig(rawJSON string) (scanner.Conf, error) {
	return scanner.ParseConfigJSON([]byte(rawJSON))
}

func (a *App) ImportConfigDialog() (scanner.Conf, error) {
	if a.ctx == nil {
		return a.GetConfig()
	}
	selected, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Import Configuration JSON",
		Filters: []runtime.FileFilter{
			{DisplayName: "JSON Config (*.json)", Pattern: "*.json"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return a.config, err
	}
	if selected == "" {
		return a.config, nil
	}
	return a.LoadConfigFromDisk(selected)
}

func (a *App) SaveConfigAs(cfg scanner.Conf) (string, error) {
	scanner.NormalizeConfig(&cfg)
	if a.ctx == nil {
		err := scanner.SaveConfig("conf.json", cfg)
		return "conf.json", err
	}
	dest, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Save Configuration As",
		DefaultFilename: "conf.json",
		Filters: []runtime.FileFilter{
			{DisplayName: "JSON Config (*.json)", Pattern: "*.json"},
		},
	})
	if err != nil || dest == "" {
		return "", err
	}
	if err := scanner.SaveConfig(dest, cfg); err != nil {
		return "", err
	}
	a.mu.Lock()
	a.configPath = dest
	a.config = cfg
	a.mu.Unlock()
	return dest, nil
}

func (a *App) BrowseFile(title string, defaultFile string) (string, error) {
	if a.ctx == nil {
		return defaultFile, nil
	}
	selected, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title:           title,
		DefaultFilename: defaultFile,
		Filters: []runtime.FileFilter{
			{DisplayName: "Text / IP Lists (*.txt;*.csv;*.list)", Pattern: "*.txt;*.csv;*.list"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return "", err
	}
	if selected == "" {
		return defaultFile, nil
	}
	if cwd, err := os.Getwd(); err == nil {
		if rel, relErr := filepath.Rel(cwd, selected); relErr == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel), nil
		}
	}
	return selected, nil
}

func (a *App) ReadTextFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("empty file path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	const maxEditorBytes = 512 * 1024
	if len(data) > maxEditorBytes {
		return string(data[:maxEditorBytes]), nil
	}
	return string(data), nil
}

func (a *App) WriteTextFile(path string, content string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("empty file path")
	}
	return os.WriteFile(path, []byte(content), 0600)
}

func (a *App) PreviewIPList(content string, ipVersion int, ignoreRange []string, allowRange []string) scanner.IPPreviewResult {
	return scanner.PreviewIPList(content, ipVersion, ignoreRange, allowRange, 120)
}

func (a *App) StartScan(cfg scanner.Conf) error {
	if a.runner.State() == scanner.StateRunning || a.runner.State() == scanner.StateStopping {
		return fmt.Errorf("a scan is already running")
	}

	scanner.NormalizeConfig(&cfg)
	a.mu.Lock()
	a.config = cfg
	a.results = a.results[:0]
	a.mu.Unlock()

	runCtx := a.ctx
	if runCtx == nil {
		runCtx = context.Background()
	}

	go func() {
		_ = a.runner.Run(runCtx, cfg, scanner.Hooks{
			OnStateChange: func(st scanner.ScanState) {
				if a.ctx != nil {
					runtime.EventsEmit(a.ctx, "scan:state", string(st))
				}
			},
			OnProgress: func(p scanner.ProgressEvent) {
				if a.ctx != nil {
					runtime.EventsEmit(a.ctx, "scan:progress", p)
				}
			},
			OnLog: func(l scanner.LogEvent) {
				if a.ctx != nil {
					runtime.EventsEmit(a.ctx, "scan:log", l)
				}
			},
			OnResult: func(res scanner.ScanResult) {
				a.mu.Lock()
				a.results = append(a.results, res)
				a.mu.Unlock()
				if a.ctx != nil {
					runtime.EventsEmit(a.ctx, "scan:result", res)
				}
			},
		})
	}()

	return nil
}

func (a *App) StopScan() {
	a.runner.Stop()
}

func (a *App) GetScanSnapshot() scanner.ProgressEvent {
	return a.runner.Snapshot()
}

func (a *App) GetResults() []scanner.ScanResult {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]scanner.ScanResult, len(a.results))
	copy(out, a.results)
	return out
}

func (a *App) ExportResults(format string, results []scanner.ScanResult) (string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	defaultName := "scan_results.txt"
	filterName := "Text File (*.txt)"
	filterPattern := "*.txt"
	if format == "csv" {
		defaultName = "scan_results.csv"
		filterName = "CSV File (*.csv)"
		filterPattern = "*.csv"
	} else if format == "json" {
		defaultName = "scan_results.json"
		filterName = "JSON File (*.json)"
		filterPattern = "*.json"
	}

	dest := defaultName
	if a.ctx != nil {
		selected, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
			Title:           "Export Scan Results",
			DefaultFilename: defaultName,
			Filters: []runtime.FileFilter{
				{DisplayName: filterName, Pattern: filterPattern},
			},
		})
		if err != nil || selected == "" {
			return "", err
		}
		dest = selected
	}

	var sb strings.Builder
	switch format {
	case "csv":
		sb.WriteString("ip:port,domain,ping,latency,jitter,download,upload,status\n")
		for _, r := range results {
			sb.WriteString(fmt.Sprintf("%s,%s,%s,%d,%s,%s,%s,%s\n",
				r.Addr, r.Domain, r.PingText, r.LatencyMs, r.JitterText, r.DownloadSpeed, r.UploadSpeed, r.Status))
		}
	case "json":
		b, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return "", err
		}
		sb.Write(b)
	default:
		for _, r := range results {
			if r.Domain != "" {
				sb.WriteString(fmt.Sprintf("%s:\t%s\t%s\t%d\t%s\t%s\t%s\n",
					r.Domain, r.IP, r.PingText, r.LatencyMs, r.JitterText, r.DownloadSpeed, r.UploadSpeed))
			} else {
				sb.WriteString(fmt.Sprintf("%-21s %-12s %d\t%s\t%s\t%s\n",
					r.Addr, r.PingText, r.LatencyMs, r.JitterText, r.DownloadSpeed, r.UploadSpeed))
			}
		}
	}

	if err := os.WriteFile(dest, []byte(sb.String()), 0600); err != nil {
		return "", err
	}
	return dest, nil
}
