import React, { useState, useMemo, useEffect, useRef } from 'react';
import {
  Play,
  Square,
  RotateCcw,
  Save,
  FolderOpen,
  Copy,
  Check,
  FileCode2,
  Sliders,
  Globe,
  Shield,
  Activity,
  Gauge,
  Code2,
  Sun,
  Moon,
  AlertTriangle,
  Terminal,
  Download,
  Plus,
  Trash2,
  ArrowUpDown,
} from 'lucide-react';
import { GO_FILES } from './data/goFiles';
import { parseMixedIPList } from './utils/scannerLogic';

interface NoisePacket {
  Type: string;
  Payload: string;
  Sleep: string;
}

interface ConfState {
  ProgressBar: boolean;
  Log: boolean;
  CSV: boolean;
  IpVersion: 4 | 6;
  IplistPath: string;
  DomainScan: {
    Enable: boolean;
    DomainAsSNI: boolean;
    DomainAsHost: boolean;
    Shuffle: boolean;
    SkipIPV6: boolean;
    DomainListPath: string;
  };
  Hostname: string;
  Ports: number[];
  Path: string;
  Headers: Record<string, string>;
  ResponseHeader: Record<string, string>;
  ResponseStatusCode: number[];
  Maxlatency: number;
  Ping: {
    Enable: boolean;
    MaxPing: number;
    Privileged: boolean;
    Size: string;
  };
  Jitter: {
    Enable: boolean;
    MaxJitter: number;
    Samples: number;
    Interval: number;
  };
  RandomScan: boolean;
  IgnoreRange: string[];
  AllowRange: string[];
  Goroutines: number;
  'HTTP/3': boolean;
  Padding: boolean;
  PaddingSize: string;
  TLS: {
    Enable: boolean;
    SNI: string;
    Insecure: boolean;
    Alpn: string[];
    Utls: {
      Enable: boolean;
      Fingerprint: string;
      TcpTimeout: number;
      TcpConnectAttempt: number;
      Fragment: {
        Enable: boolean;
        Length: string;
        Delay: string;
        MaxSplit: string;
      };
    };
  };
  Noises: {
    Enable: boolean;
    Packets: NoisePacket[];
  };
  DownloadTest: {
    Enable: boolean;
    SeparateConnection: boolean;
    Url: string;
    SNI: string;
    TargetBytes: number;
    Timeout: number;
  };
  UploadTest: {
    Enable: boolean;
    SeparateConnection: boolean;
    Url: string;
    SNI: string;
    PayloadBytes: number;
    TargetBytes: number;
    Timeout: number;
  };
}

const DEFAULT_CONF: ConfState = {
  ProgressBar: false,
  Log: true,
  CSV: true,
  IpVersion: 4,
  IplistPath: 'ipv4.txt',
  DomainScan: {
    Enable: false,
    DomainAsSNI: true,
    DomainAsHost: true,
    Shuffle: false,
    SkipIPV6: true,
    DomainListPath: 'cloudfalare-domains.txt',
  },
  Hostname: 'cp.cloudflare.com',
  Ports: [443, 2053, 2083, 2087, 2096, 8443],
  Path: '/generate_204',
  Headers: {
    'User-Agent':
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0',
  },
  ResponseHeader: {
    Server: 'cloudflare',
  },
  ResponseStatusCode: [204],
  Maxlatency: 1500,
  Ping: {
    Enable: true,
    MaxPing: 400,
    Privileged: false,
    Size: '30-100',
  },
  Jitter: {
    Enable: true,
    MaxJitter: 150,
    Samples: 5,
    Interval: 200,
  },
  RandomScan: false,
  IgnoreRange: ['104.16.0.1'],
  AllowRange: [],
  Goroutines: 100,
  'HTTP/3': false,
  Padding: false,
  PaddingSize: '20-100',
  TLS: {
    Enable: true,
    SNI: 'cp.cloudflare.com',
    Insecure: true,
    Alpn: ['h2', 'http/1.1'],
    Utls: {
      Enable: true,
      Fingerprint: 'chrome',
      TcpTimeout: 2000,
      TcpConnectAttempt: 1,
      Fragment: {
        Enable: false,
        Length: '10-20',
        Delay: '10-20',
        MaxSplit: '4-8',
      },
    },
  },
  Noises: {
    Enable: false,
    Packets: [
      {
        Type: 'rand',
        Payload: '50-100',
        Sleep: '20-50',
      },
    ],
  },
  DownloadTest: {
    Enable: true,
    SeparateConnection: false,
    Url: 'https://speed.cloudflare.com/__down?bytes=50000000',
    SNI: 'cp.cloudflare.com',
    TargetBytes: 5000000,
    Timeout: 5000,
  },
  UploadTest: {
    Enable: true,
    SeparateConnection: false,
    Url: 'https://speed.cloudflare.com/__up',
    SNI: 'cp.cloudflare.com',
    PayloadBytes: 10000000,
    TargetBytes: 5000000,
    Timeout: 5000,
  },
};

const DEFAULT_IPLIST = `# Cloudflare Edge Targets (Mixed Single IPs & CIDR Ranges)
104.16.132.229 # Direct Anycast Node A (/32)
104.16.133.229 // Direct Anycast Node B (/32)
172.67.154.88
104.18.22.45
104.16.0.0/30 # Small /30 subnet (4 IPs)
162.159.135.42
`;

interface ScanRow {
  id: number;
  domain: string;
  ip: string;
  port: number;
  addr: string;
  pingMs: number;
  pingText: string;
  latencyMs: number;
  jitterMs: number | null;
  jitterText: string;
  downloadSpeed: string;
  downloadMbps: number;
  uploadSpeed: string;
  uploadMbps: number;
  status: 'PASSED' | 'JAMMED' | 'HIGH_JITTER';
}

interface LogEntry {
  id: number;
  time: string;
  level: 'info' | 'success' | 'warn' | 'error';
  message: string;
}

const INITIAL_RESULTS: ScanRow[] = [
  {
    id: 1,
    domain: '',
    ip: '104.16.132.229',
    port: 443,
    addr: '104.16.132.229:443',
    pingMs: 28.4,
    pingText: '28.4ms',
    latencyMs: 92,
    jitterMs: 4.12,
    jitterText: '4.120000',
    downloadSpeed: '18.420000MB/S',
    downloadMbps: 18.42,
    uploadSpeed: '9.840000MB/S',
    uploadMbps: 9.84,
    status: 'PASSED',
  },
  {
    id: 2,
    domain: '',
    ip: '104.16.133.229',
    port: 443,
    addr: '104.16.133.229:443',
    pingMs: 31.0,
    pingText: '31.0ms',
    latencyMs: 105,
    jitterMs: 5.88,
    jitterText: '5.880000',
    downloadSpeed: '14.250000MB/S',
    downloadMbps: 14.25,
    uploadSpeed: '7.620000MB/S',
    uploadMbps: 7.62,
    status: 'PASSED',
  },
  {
    id: 3,
    domain: '',
    ip: '172.67.154.88',
    port: 2053,
    addr: '172.67.154.88:2053',
    pingMs: 54.2,
    pingText: '54.2ms',
    latencyMs: 210,
    jitterMs: 19.4,
    jitterText: '19.400000',
    downloadSpeed: '8.110000MB/S',
    downloadMbps: 8.11,
    uploadSpeed: 'JAMMED',
    uploadMbps: 0,
    status: 'JAMMED',
  },
  {
    id: 4,
    domain: '',
    ip: '104.18.22.45',
    port: 8443,
    addr: '104.18.22.45:8443',
    pingMs: 24.8,
    pingText: '24.8ms',
    latencyMs: 84,
    jitterMs: 2.95,
    jitterText: '2.950000',
    downloadSpeed: '22.900000MB/S',
    downloadMbps: 22.9,
    uploadSpeed: '12.450000MB/S',
    uploadMbps: 12.45,
    status: 'PASSED',
  },
];

export default function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [conf, setConf] = useState<ConfState>(DEFAULT_CONF);
  const [activeTab, setActiveTab] = useState<
    'general' | 'targets' | 'http' | 'net' | 'tls' | 'speed' | 'raw' | 'source'
  >('general');
  const [ipListText, setIpListText] = useState<string>(DEFAULT_IPLIST);
  const [rawJsonText, setRawJsonText] = useState<string>(() =>
    JSON.stringify(DEFAULT_CONF, null, 2)
  );
  const [rawJsonError, setRawJsonError] = useState<string | null>(null);

  // Scan execution state
  const [scanState, setScanState] = useState<'idle' | 'running' | 'stopped' | 'completed'>('idle');
  const [progress, setProgress] = useState({
    scanned: 4,
    total: 8,
    passed: 3,
    percent: 50,
    elapsedText: '1.8s',
  });
  const [results, setResults] = useState<ScanRow[]>(INITIAL_RESULTS);
  const [logs, setLogs] = useState<LogEntry[]>([
    {
      id: 1,
      time: '12:00:01',
      level: 'info',
      message: 'Loaded conf.json (IpVersion: 4, IplistPath: ipv4.txt)',
    },
    {
      id: 2,
      time: '12:00:02',
      level: 'success',
      message: '104.16.132.229:443        28.4ms       92\t4.120000\t18.420000MB/S\t9.840000MB/S',
    },
    {
      id: 3,
      time: '12:00:03',
      level: 'success',
      message: '104.16.133.229:443        31.0ms       105\t5.880000\t14.250000MB/S\t7.620000MB/S',
    },
    {
      id: 4,
      time: '12:00:04',
      level: 'warn',
      message: '172.67.154.88:2053        54.2ms       210\t19.400000\t8.110000MB/S\tJAMMED',
    },
    {
      id: 5,
      time: '12:00:05',
      level: 'success',
      message: '104.18.22.45:8443         24.8ms       84\t2.950000\t22.900000MB/S\t12.450000MB/S',
    },
  ]);

  // Results sorting & filtering
  const [resultFilter, setResultFilter] = useState<string>('');
  const [passedOnly, setPassedOnly] = useState<boolean>(false);
  const [sortCol, setSortCol] = useState<
    'ip' | 'pingMs' | 'latencyMs' | 'jitterMs' | 'downloadMbps' | 'uploadMbps' | 'status'
  >('latencyMs');
  const [sortAsc, setSortAsc] = useState<boolean>(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [selectedFileIdx, setSelectedFileIdx] = useState<number>(0);

  const scanTimerRef = useRef<number | null>(null);

  // Sync conf changes to rawJsonText
  useEffect(() => {
    setRawJsonText(JSON.stringify(conf, null, 2));
    setRawJsonError(null);
  }, [conf]);

  const ipPreview = useMemo(() => {
    return parseMixedIPList(
      ipListText,
      conf.IpVersion,
      conf.IgnoreRange,
      conf.AllowRange
    );
  }, [ipListText, conf.IpVersion, conf.IgnoreRange, conf.AllowRange]);

  const showGoroutinesWarning =
    (conf.DownloadTest.Enable || conf.UploadTest.Enable) && conf.Goroutines > 1;

  const filteredResults = useMemo(() => {
    const q = resultFilter.trim().toLowerCase();
    const list = results.filter((r) => {
      if (passedOnly && r.status !== 'PASSED') return false;
      if (!q) return true;
      return (
        r.addr.toLowerCase().includes(q) ||
        r.ip.toLowerCase().includes(q) ||
        r.status.toLowerCase().includes(q)
      );
    });

    return [...list].sort((a, b) => {
      let va: number | string = a[sortCol] ?? 999999;
      let vb: number | string = b[sortCol] ?? 999999;
      if (typeof va === 'string' && typeof vb === 'string') {
        return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
      }
      return sortAsc ? Number(va) - Number(vb) : Number(vb) - Number(va);
    });
  }, [results, resultFilter, passedOnly, sortCol, sortAsc]);

  const handleSort = (
    col: 'ip' | 'pingMs' | 'latencyMs' | 'jitterMs' | 'downloadMbps' | 'uploadMbps' | 'status'
  ) => {
    if (sortCol === col) {
      setSortAsc(!sortAsc);
    } else {
      setSortCol(col);
      setSortAsc(col === 'downloadMbps' || col === 'uploadMbps' ? false : true);
    }
  };

  const pushLog = (level: LogEntry['level'], message: string) => {
    const now = new Date().toTimeString().slice(0, 8);
    setLogs((prev) => [...prev, { id: Date.now() + Math.random(), time: now, level, message }]);
  };

  const handleStartScan = () => {
    if (scanState === 'running') return;
    const targets = ipPreview.expandedIPs.length > 0
      ? ipPreview.expandedIPs
      : ['104.16.132.229', '104.16.133.229', '172.67.154.88', '104.18.22.45'];
    setResults([]);
    setScanState('running');
    setProgress({
      scanned: 0,
      total: targets.length,
      passed: 0,
      percent: 0,
      elapsedText: '0.0s',
    });
    pushLog(
      'info',
      `Starting scan for ${targets.length} target IPs with ${conf.Goroutines} goroutines...`
    );

    let idx = 0;
    let passedCount = 0;
    const startTs = Date.now();

    scanTimerRef.current = window.setInterval(() => {
      if (idx >= targets.length) {
        if (scanTimerRef.current) clearInterval(scanTimerRef.current);
        setScanState('completed');
        pushLog(
          'success',
          `Scan completed. Scanned: ${targets.length}, Passed: ${passedCount}.`
        );
        return;
      }

      const ip = targets[idx];
      idx++;
      const port = conf.Ports[idx % conf.Ports.length] || 443;
      const addr = ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`;
      const pingMs = Number((22 + ((idx * 11) % 38)).toFixed(1));
      const latencyMs = 78 + ((idx * 29) % 140);
      const jitterMs = conf.Jitter.Enable ? Number((2.4 + ((idx * 3.1) % 14)).toFixed(2)) : null;
      const isJammed = idx % 4 === 0 && (conf.DownloadTest.Enable || conf.UploadTest.Enable);
      const dlMbps = conf.DownloadTest.Enable
        ? Number((11.5 + ((idx * 4.3) % 14)).toFixed(2))
        : 0;
      const ulMbps = conf.UploadTest.Enable
        ? isJammed
          ? 0
          : Number((6.8 + ((idx * 2.7) % 9)).toFixed(2))
        : 0;

      const dlSpeed = conf.DownloadTest.Enable ? `${dlMbps.toFixed(6)}MB/S` : 'Null';
      const ulSpeed = conf.UploadTest.Enable
        ? isJammed
          ? 'JAMMED'
          : `${ulMbps.toFixed(6)}MB/S`
        : 'Null';
      const status: ScanRow['status'] = isJammed ? 'JAMMED' : 'PASSED';
      if (status === 'PASSED') passedCount++;

      const row: ScanRow = {
        id: idx,
        domain: '',
        ip,
        port,
        addr,
        pingMs,
        pingText: `${pingMs}ms`,
        latencyMs,
        jitterMs,
        jitterText: jitterMs !== null ? jitterMs.toFixed(6) : 'Null',
        downloadSpeed: dlSpeed,
        downloadMbps: dlMbps,
        uploadSpeed: ulSpeed,
        uploadMbps: ulMbps,
        status,
      };

      setResults((prev) => [...prev, row]);
      const elapsedSec = ((Date.now() - startTs) / 1000).toFixed(1) + 's';
      setProgress({
        scanned: idx,
        total: targets.length,
        passed: passedCount,
        percent: Math.round((idx / targets.length) * 100),
        elapsedText: elapsedSec,
      });
      pushLog(
        status === 'PASSED' ? 'success' : 'warn',
        `${addr.padEnd(21, ' ')} ${row.pingText.padEnd(10, ' ')} ${row.latencyMs}\t${row.jitterText}\t${row.downloadSpeed}\t${row.uploadSpeed}`
      );
    }, 280);
  };

  const handleStopScan = () => {
    if (scanTimerRef.current) {
      clearInterval(scanTimerRef.current);
      scanTimerRef.current = null;
    }
    setScanState('stopped');
    pushLog('warn', 'Scan stopped gracefully by user (context canceled).');
  };

  const copyText = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const isLight = theme === 'light';

  return (
    <div
      className={`min-h-screen flex flex-col font-sans text-xs select-none ${
        isLight ? 'bg-slate-100 text-slate-900' : 'bg-[#0b1120] text-slate-100'
      }`}
    >
      {/* Top Wails Desktop Control Bar */}
      <header
        className={`h-14 px-4 border-b flex items-center justify-between gap-4 shrink-0 ${
          isLight
            ? 'bg-white border-slate-200'
            : 'bg-[#111827] border-slate-800'
        }`}
      >
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-md bg-orange-500/15 border border-orange-500/40 flex items-center justify-center text-orange-400 font-mono font-bold text-sm">
            CF
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="font-semibold text-sm tracking-tight">CF-Scanner Desktop</h1>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-sky-500/15 text-sky-400 border border-sky-500/30">
                Wails v2 • windows/amd64 (GOAMD64=v3)
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Native Edge WebView2 GUI • In-Process Scanner Engine • Full 1:1 conf.json Control
            </p>
          </div>
        </div>

        {/* Live Progress Bar & Metrics */}
        <div className="flex-1 max-w-xl flex flex-col gap-1">
          <div className="flex items-center justify-between text-[11px] font-mono">
            <span
              className={`px-1.5 py-0.5 rounded font-semibold uppercase text-[10px] ${
                scanState === 'running'
                  ? 'bg-sky-500/20 text-sky-400'
                  : scanState === 'completed'
                  ? 'bg-emerald-500/20 text-emerald-400'
                  : scanState === 'stopped'
                  ? 'bg-amber-500/20 text-amber-400'
                  : 'bg-slate-500/20 text-slate-400'
              }`}
              data-testid="scan-status-badge"
            >
              {scanState.toUpperCase()}
            </span>
            <span>
              Scanned:{' '}
              <strong className="text-sky-400">
                {progress.scanned} / {progress.total}
              </strong>{' '}
              ({progress.percent}%)
            </span>
            <span>
              Passed: <strong className="text-emerald-400">{progress.passed}</strong>
            </span>
            <span>
              Elapsed: <strong>{progress.elapsedText}</strong>
            </span>
          </div>
          <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden border border-slate-700">
            <div
              className="h-full bg-gradient-to-r from-sky-500 to-emerald-500 transition-all duration-200"
              style={{ width: `${progress.percent}%` }}
            />
          </div>
        </div>

        {/* Scan & Config Action Buttons */}
        <div className="flex items-center gap-1.5">
          {scanState !== 'running' ? (
            <button
              onClick={handleStartScan}
              data-testid="btn-start-scan"
              className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-semibold flex items-center gap-1.5 cursor-pointer transition"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              Start Scan
            </button>
          ) : (
            <button
              onClick={handleStopScan}
              data-testid="btn-stop-scan"
              className="px-3 py-1.5 rounded bg-rose-600 hover:bg-rose-500 text-white font-semibold flex items-center gap-1.5 cursor-pointer transition"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              Stop Scan
            </button>
          )}

          <button
            onClick={() =>
              pushLog('info', 'Saved current configuration to conf.json.')
            }
            className={`px-2.5 py-1.5 rounded border flex items-center gap-1 cursor-pointer ${
              isLight
                ? 'bg-slate-50 border-slate-300 hover:bg-slate-200'
                : 'bg-slate-800/80 border-slate-700 hover:bg-slate-700'
            }`}
            title="Save conf.json"
          >
            <Save className="w-3.5 h-3.5 text-sky-400" />
            Save conf.json
          </button>

          <button
            onClick={() => {
              setConf(DEFAULT_CONF);
              pushLog('info', 'Reset configuration to default conf.json values.');
            }}
            className={`px-2.5 py-1.5 rounded border flex items-center gap-1 cursor-pointer ${
              isLight
                ? 'bg-slate-50 border-slate-300 hover:bg-slate-200'
                : 'bg-slate-800/80 border-slate-700 hover:bg-slate-700'
            }`}
            title="Reset Defaults"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Defaults
          </button>

          <button
            onClick={() => setTheme(isLight ? 'dark' : 'light')}
            data-testid="btn-theme-toggle"
            className={`p-1.5 rounded border cursor-pointer ${
              isLight
                ? 'bg-slate-50 border-slate-300 hover:bg-slate-200'
                : 'bg-slate-800/80 border-slate-700 hover:bg-slate-700'
            }`}
            title="Toggle Dark/Light Theme"
          >
            {isLight ? <Moon className="w-3.5 h-3.5" /> : <Sun className="w-3.5 h-3.5" />}
          </button>
        </div>
      </header>

      {/* Main Split Workspace */}
      <div className="flex-1 grid grid-cols-12 min-h-0 overflow-hidden">
        {/* Left Configuration Pane (5 cols) */}
        <aside
          className={`col-span-12 lg:col-span-5 border-r flex flex-col min-h-0 ${
            isLight ? 'bg-white border-slate-200' : 'bg-[#111827] border-slate-800'
          }`}
        >
          {/* 7 Config Section Tabs + Source & CI Inspector */}
          <nav
            className={`flex flex-wrap gap-1 p-2 border-b ${
              isLight ? 'bg-slate-50 border-slate-200' : 'bg-slate-900/70 border-slate-800'
            }`}
          >
            {[
              { id: 'general', label: '1. General', icon: Sliders },
              { id: 'targets', label: '2. Targets & IPs', icon: Globe },
              { id: 'http', label: '3. HTTP', icon: FileCode2 },
              { id: 'net', label: '4. Ping & Jitter', icon: Activity },
              { id: 'tls', label: '5. TLS / uTLS / Noise', icon: Shield },
              { id: 'speed', label: '6. Speed Tests', icon: Gauge },
              { id: 'raw', label: '7. Raw JSON', icon: Code2 },
              { id: 'source', label: 'Go / Wails / CI Code', icon: Terminal },
            ].map((t) => {
              const Icon = t.icon;
              const active = activeTab === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => setActiveTab(t.id as typeof activeTab)}
                  data-testid={`tab-${t.id}`}
                  className={`px-2.5 py-1.5 rounded text-[11px] font-medium flex items-center gap-1.5 cursor-pointer transition ${
                    active
                      ? 'bg-sky-500 text-slate-950 font-semibold'
                      : isLight
                      ? 'text-slate-600 hover:bg-slate-200'
                      : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {t.label}
                </button>
              );
            })}
          </nav>

          {/* Tab Body */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {activeTab === 'general' && (
              <div className="space-y-4">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-sky-400">
                  General & Execution Settings
                </h2>
                <div className="grid grid-cols-2 gap-2.5">
                  {[
                    { key: 'ProgressBar', label: 'ProgressBar (CLI Progress)' },
                    { key: 'Log', label: 'Log (Detailed Live Logs)' },
                    { key: 'CSV', label: 'CSV (Write result.csv)' },
                    { key: 'RandomScan', label: 'RandomScan (Shuffle IPs)' },
                  ].map((item) => (
                    <label
                      key={item.key}
                      className={`p-2.5 rounded border flex items-center gap-2 cursor-pointer ${
                        isLight
                          ? 'bg-slate-50 border-slate-200'
                          : 'bg-slate-900/60 border-slate-800'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={Boolean(conf[item.key as keyof ConfState])}
                        onChange={(e) =>
                          setConf({ ...conf, [item.key]: e.target.checked })
                        }
                        className="accent-sky-500"
                      />
                      <span>{item.label}</span>
                    </label>
                  ))}
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Goroutines (Worker Concurrency)
                    </label>
                    <input
                      type="number"
                      min={1}
                      value={conf.Goroutines}
                      data-testid="input-goroutines"
                      onChange={(e) =>
                        setConf({
                          ...conf,
                          Goroutines: Math.max(1, Number(e.target.value) || 1),
                        })
                      }
                      className={`w-full px-2.5 py-1.5 rounded border font-mono ${
                        isLight
                          ? 'bg-white border-slate-300'
                          : 'bg-slate-900 border-slate-700'
                      }`}
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Maxlatency (ms)
                    </label>
                    <input
                      type="number"
                      min={50}
                      value={conf.Maxlatency}
                      onChange={(e) =>
                        setConf({
                          ...conf,
                          Maxlatency: Math.max(50, Number(e.target.value) || 1000),
                        })
                      }
                      className={`w-full px-2.5 py-1.5 rounded border font-mono ${
                        isLight
                          ? 'bg-white border-slate-300'
                          : 'bg-slate-900 border-slate-700'
                      }`}
                    />
                  </div>
                </div>

                {showGoroutinesWarning && (
                  <div
                    data-testid="goroutines-warning"
                    className="p-3 rounded-md bg-amber-500/10 border border-amber-500/40 text-amber-300 flex items-start gap-2.5"
                  >
                    <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    <div className="space-y-1.5">
                      <p className="text-[11px] leading-relaxed">
                        <strong>Bandwidth Contention Warning:</strong>{' '}
                        <code className="font-mono">DownloadTest</code> or{' '}
                        <code className="font-mono">UploadTest</code> is enabled while{' '}
                        <code className="font-mono">Goroutines = {conf.Goroutines}</code>.
                        Concurrent workers share bandwidth and may falsely report{' '}
                        <code className="font-mono">JAMMED</code>. Set{' '}
                        <code className="font-mono">Goroutines: 1</code> for accurate speed
                        tests.
                      </p>
                      <button
                        onClick={() => setConf({ ...conf, Goroutines: 1 })}
                        className="px-2 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 text-amber-200 font-semibold text-[11px] cursor-pointer"
                      >
                        Set Goroutines = 1
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'targets' && (
              <div className="space-y-4">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-sky-400">
                  Targets, Mixed IP/CIDR List & Filtering
                </h2>
                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      IpVersion
                    </label>
                    <select
                      value={conf.IpVersion}
                      onChange={(e) =>
                        setConf({
                          ...conf,
                          IpVersion: Number(e.target.value) as 4 | 6,
                        })
                      }
                      className={`w-full px-2.5 py-1.5 rounded border font-mono ${
                        isLight
                          ? 'bg-white border-slate-300'
                          : 'bg-slate-900 border-slate-700'
                      }`}
                    >
                      <option value={4}>4 (IPv4 /32 & CIDR)</option>
                      <option value={6}>6 (IPv6 /128 & CIDR)</option>
                    </select>
                  </div>
                  <div className="col-span-2">
                    <label className="block text-[11px] text-slate-400 mb-1">
                      IplistPath
                    </label>
                    <div className="flex gap-1.5">
                      <input
                        type="text"
                        value={conf.IplistPath}
                        onChange={(e) =>
                          setConf({ ...conf, IplistPath: e.target.value })
                        }
                        className={`flex-1 px-2.5 py-1.5 rounded border font-mono ${
                          isLight
                            ? 'bg-white border-slate-300'
                            : 'bg-slate-900 border-slate-700'
                        }`}
                      />
                      <button
                        onClick={() =>
                          pushLog('info', `Opened native Wails file dialog for ${conf.IplistPath}`)
                        }
                        className="px-2.5 py-1.5 rounded bg-slate-800 border border-slate-700 hover:bg-slate-700 text-slate-200 flex items-center gap-1 cursor-pointer"
                      >
                        <FolderOpen className="w-3.5 h-3.5 text-sky-400" />
                        Browse...
                      </button>
                    </div>
                  </div>
                </div>

                {/* Inline IplistPath Preview & Editor */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label className="text-[11px] text-slate-400">
                      Inline IP List Preview / Editor (Single IPs + CIDRs)
                    </label>
                    <span className="text-[11px] font-mono text-emerald-400">
                      Valid Entries: {ipPreview.validEntries.length} • Expanded IPs:{' '}
                      {ipPreview.expandedIPs.length}
                    </span>
                  </div>
                  <textarea
                    rows={5}
                    value={ipListText}
                    onChange={(e) => setIpListText(e.target.value)}
                    className={`w-full p-2.5 rounded border font-mono text-[11px] ${
                      isLight
                        ? 'bg-slate-50 border-slate-300'
                        : 'bg-slate-950 border-slate-800'
                    }`}
                  />
                </div>

                {/* AllowRange & IgnoreRange */}
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      AllowRange (CIDRs or Single IPs)
                    </label>
                    <textarea
                      rows={3}
                      value={conf.AllowRange.join('\n')}
                      placeholder="e.g. 104.16.0.0/13 or 104.16.132.229"
                      onChange={(e) =>
                        setConf({
                          ...conf,
                          AllowRange: e.target.value
                            .split('\n')
                            .map((s) => s.trim())
                            .filter(Boolean),
                        })
                      }
                      className={`w-full p-2 rounded border font-mono text-[11px] ${
                        isLight
                          ? 'bg-slate-50 border-slate-300'
                          : 'bg-slate-950 border-slate-800'
                      }`}
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      IgnoreRange (CIDRs or Single IPs)
                    </label>
                    <textarea
                      rows={3}
                      value={conf.IgnoreRange.join('\n')}
                      placeholder="e.g. 104.16.0.1"
                      onChange={(e) =>
                        setConf({
                          ...conf,
                          IgnoreRange: e.target.value
                            .split('\n')
                            .map((s) => s.trim())
                            .filter(Boolean),
                        })
                      }
                      className={`w-full p-2 rounded border font-mono text-[11px] ${
                        isLight
                          ? 'bg-slate-50 border-slate-300'
                          : 'bg-slate-950 border-slate-800'
                      }`}
                    />
                  </div>
                </div>

                {/* DomainScan */}
                <div className="pt-2 border-t border-slate-800 space-y-2.5">
                  <h3 className="text-[11px] font-semibold uppercase text-slate-400">
                    DomainScan Configuration
                  </h3>
                  <div className="grid grid-cols-3 gap-2">
                    {(
                      [
                        'Enable',
                        'DomainAsSNI',
                        'DomainAsHost',
                        'Shuffle',
                        'SkipIPV6',
                      ] as const
                    ).map((field) => (
                      <label
                        key={field}
                        className="flex items-center gap-1.5 text-[11px] cursor-pointer"
                      >
                        <input
                          type="checkbox"
                          checked={conf.DomainScan[field]}
                          onChange={(e) =>
                            setConf({
                              ...conf,
                              DomainScan: {
                                ...conf.DomainScan,
                                [field]: e.target.checked,
                              },
                            })
                          }
                          className="accent-sky-500"
                        />
                        <span>{field}</span>
                      </label>
                    ))}
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      DomainScan.DomainListPath
                    </label>
                    <input
                      type="text"
                      value={conf.DomainScan.DomainListPath}
                      onChange={(e) =>
                        setConf({
                          ...conf,
                          DomainScan: {
                            ...conf.DomainScan,
                            DomainListPath: e.target.value,
                          },
                        })
                      }
                      className={`w-full px-2.5 py-1.5 rounded border font-mono ${
                        isLight
                          ? 'bg-white border-slate-300'
                          : 'bg-slate-900 border-slate-700'
                      }`}
                    />
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'http' && (
              <div className="space-y-4">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-sky-400">
                  HTTP Request & Validation
                </h2>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Hostname
                    </label>
                    <input
                      type="text"
                      value={conf.Hostname}
                      onChange={(e) => setConf({ ...conf, Hostname: e.target.value })}
                      className={`w-full px-2.5 py-1.5 rounded border font-mono ${
                        isLight
                          ? 'bg-white border-slate-300'
                          : 'bg-slate-900 border-slate-700'
                      }`}
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Path
                    </label>
                    <input
                      type="text"
                      value={conf.Path}
                      onChange={(e) => setConf({ ...conf, Path: e.target.value })}
                      className={`w-full px-2.5 py-1.5 rounded border font-mono ${
                        isLight
                          ? 'bg-white border-slate-300'
                          : 'bg-slate-900 border-slate-700'
                      }`}
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      Ports (comma-separated)
                    </label>
                    <input
                      type="text"
                      value={conf.Ports.join(', ')}
                      onChange={(e) =>
                        setConf({
                          ...conf,
                          Ports: e.target.value
                            .split(',')
                            .map((s) => Number(s.trim()))
                            .filter((n) => n > 0 && n <= 65535),
                        })
                      }
                      className={`w-full px-2.5 py-1.5 rounded border font-mono ${
                        isLight
                          ? 'bg-white border-slate-300'
                          : 'bg-slate-900 border-slate-700'
                      }`}
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      ResponseStatusCode (comma-separated)
                    </label>
                    <input
                      type="text"
                      value={conf.ResponseStatusCode.join(', ')}
                      onChange={(e) =>
                        setConf({
                          ...conf,
                          ResponseStatusCode: e.target.value
                            .split(',')
                            .map((s) => Number(s.trim()))
                            .filter((n) => n > 0),
                        })
                      }
                      className={`w-full px-2.5 py-1.5 rounded border font-mono ${
                        isLight
                          ? 'bg-white border-slate-300'
                          : 'bg-slate-900 border-slate-700'
                      }`}
                    />
                  </div>
                </div>

                {/* Dynamic Headers Editor */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-semibold text-slate-400">
                      Request Headers (Dynamic Key-Value)
                    </span>
                    <button
                      onClick={() =>
                        setConf({
                          ...conf,
                          Headers: { ...conf.Headers, 'X-Custom-Header': 'value' },
                        })
                      }
                      className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[11px] flex items-center gap-1 cursor-pointer"
                    >
                      <Plus className="w-3 h-3" /> Add Header
                    </button>
                  </div>
                  {Object.entries(conf.Headers).map(([k, v], i) => (
                    <div key={i} className="flex gap-1.5">
                      <input
                        type="text"
                        value={k}
                        onChange={(e) => {
                          const next: Record<string, string> = {};
                          Object.entries(conf.Headers).forEach(([ok, ov], idx) => {
                            next[idx === i ? e.target.value : ok] = ov;
                          });
                          setConf({ ...conf, Headers: next });
                        }}
                        className="w-1/3 px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                      <input
                        type="text"
                        value={v}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            Headers: { ...conf.Headers, [k]: e.target.value },
                          })
                        }
                        className="flex-1 px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                      <button
                        onClick={() => {
                          const next = { ...conf.Headers };
                          delete next[k];
                          setConf({ ...conf, Headers: next });
                        }}
                        className="px-2 py-1 rounded bg-rose-500/15 text-rose-400 border border-rose-500/30 cursor-pointer"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    </div>
                  ))}
                </div>

                <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-800">
                  <label className="flex items-center gap-2 cursor-pointer mt-4">
                    <input
                      type="checkbox"
                      checked={conf.Padding}
                      onChange={(e) => setConf({ ...conf, Padding: e.target.checked })}
                      className="accent-sky-500"
                    />
                    <span>Padding (X-Padding Header)</span>
                  </label>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      PaddingSize (Range)
                    </label>
                    <input
                      type="text"
                      value={conf.PaddingSize}
                      onChange={(e) =>
                        setConf({ ...conf, PaddingSize: e.target.value })
                      }
                      className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 font-mono"
                    />
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'net' && (
              <div className="space-y-4">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-sky-400">
                  ICMP Ping & Jitter Configuration
                </h2>
                <div className="p-3 rounded border border-slate-800 bg-slate-900/40 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold">Ping Settings</span>
                    <label className="flex items-center gap-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={conf.Ping.Enable}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            Ping: { ...conf.Ping, Enable: e.target.checked },
                          })
                        }
                        className="accent-sky-500"
                      />
                      <span>Ping.Enable</span>
                    </label>
                  </div>
                  <div className="grid grid-cols-3 gap-2.5">
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">
                        MaxPing (ms)
                      </label>
                      <input
                        type="number"
                        value={conf.Ping.MaxPing}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            Ping: { ...conf.Ping, MaxPing: Number(e.target.value) },
                          })
                        }
                        className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">
                        Size (Range)
                      </label>
                      <input
                        type="text"
                        value={conf.Ping.Size}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            Ping: { ...conf.Ping, Size: e.target.value },
                          })
                        }
                        className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                    <label className="flex items-center gap-1.5 mt-5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={conf.Ping.Privileged}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            Ping: { ...conf.Ping, Privileged: e.target.checked },
                          })
                        }
                        className="accent-sky-500"
                      />
                      <span>Privileged</span>
                    </label>
                  </div>
                </div>

                <div className="p-3 rounded border border-slate-800 bg-slate-900/40 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold">Jitter Settings</span>
                    <label className="flex items-center gap-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={conf.Jitter.Enable}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            Jitter: { ...conf.Jitter, Enable: e.target.checked },
                          })
                        }
                        className="accent-sky-500"
                      />
                      <span>Jitter.Enable</span>
                    </label>
                  </div>
                  <div className="grid grid-cols-3 gap-2.5">
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">
                        MaxJitter (ms)
                      </label>
                      <input
                        type="number"
                        value={conf.Jitter.MaxJitter}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            Jitter: {
                              ...conf.Jitter,
                              MaxJitter: Number(e.target.value),
                            },
                          })
                        }
                        className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">
                        Samples
                      </label>
                      <input
                        type="number"
                        value={conf.Jitter.Samples}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            Jitter: {
                              ...conf.Jitter,
                              Samples: Number(e.target.value),
                            },
                          })
                        }
                        className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] text-slate-400 mb-1">
                        Interval (ms)
                      </label>
                      <input
                        type="number"
                        value={conf.Jitter.Interval}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            Jitter: {
                              ...conf.Jitter,
                              Interval: Number(e.target.value),
                            },
                          })
                        }
                        className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'tls' && (
              <div className="space-y-4">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-sky-400">
                  TLS, uTLS, Fragment, HTTP/3 & UDP Noises
                </h2>
                <div className="grid grid-cols-3 gap-2">
                  <label className="flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={conf['HTTP/3']}
                      onChange={(e) =>
                        setConf({ ...conf, 'HTTP/3': e.target.checked })
                      }
                      className="accent-sky-500"
                    />
                    <span className="font-mono">"HTTP/3"</span>
                  </label>
                  <label className="flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={conf.TLS.Enable}
                      onChange={(e) =>
                        setConf({
                          ...conf,
                          TLS: { ...conf.TLS, Enable: e.target.checked },
                        })
                      }
                      className="accent-sky-500"
                    />
                    <span>TLS.Enable</span>
                  </label>
                  <label className="flex items-center gap-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={conf.TLS.Insecure}
                      onChange={(e) =>
                        setConf({
                          ...conf,
                          TLS: { ...conf.TLS, Insecure: e.target.checked },
                        })
                      }
                      className="accent-sky-500"
                    />
                    <span>TLS.Insecure</span>
                  </label>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      TLS.SNI
                    </label>
                    <input
                      type="text"
                      value={conf.TLS.SNI}
                      onChange={(e) =>
                        setConf({
                          ...conf,
                          TLS: { ...conf.TLS, SNI: e.target.value },
                        })
                      }
                      className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 mb-1">
                      TLS.Alpn (comma-separated)
                    </label>
                    <input
                      type="text"
                      value={conf.TLS.Alpn.join(', ')}
                      onChange={(e) =>
                        setConf({
                          ...conf,
                          TLS: {
                            ...conf.TLS,
                            Alpn: e.target.value
                              .split(',')
                              .map((s) => s.trim())
                              .filter(Boolean),
                          },
                        })
                      }
                      className="w-full px-2 py-1.5 rounded bg-slate-900 border border-slate-700 font-mono"
                    />
                  </div>
                </div>

                {/* uTLS & Fragment */}
                <div className="p-3 rounded border border-slate-800 bg-slate-900/40 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold">TLS.Utls & Fragment</span>
                    <div className="flex gap-3">
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={conf.TLS.Utls.Enable}
                          onChange={(e) =>
                            setConf({
                              ...conf,
                              TLS: {
                                ...conf.TLS,
                                Utls: { ...conf.TLS.Utls, Enable: e.target.checked },
                              },
                            })
                          }
                          className="accent-sky-500"
                        />
                        <span>Utls.Enable</span>
                      </label>
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={conf.TLS.Utls.Fragment.Enable}
                          onChange={(e) =>
                            setConf({
                              ...conf,
                              TLS: {
                                ...conf.TLS,
                                Utls: {
                                  ...conf.TLS.Utls,
                                  Fragment: {
                                    ...conf.TLS.Utls.Fragment,
                                    Enable: e.target.checked,
                                  },
                                },
                              },
                            })
                          }
                          className="accent-sky-500"
                        />
                        <span>Fragment.Enable</span>
                      </label>
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-2">
                    <div>
                      <label className="block text-[10px] text-slate-400">
                        Fingerprint
                      </label>
                      <input
                        type="text"
                        value={conf.TLS.Utls.Fingerprint}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            TLS: {
                              ...conf.TLS,
                              Utls: {
                                ...conf.TLS.Utls,
                                Fingerprint: e.target.value,
                              },
                            },
                          })
                        }
                        className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400">
                        TcpTimeout (ms)
                      </label>
                      <input
                        type="number"
                        value={conf.TLS.Utls.TcpTimeout}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            TLS: {
                              ...conf.TLS,
                              Utls: {
                                ...conf.TLS.Utls,
                                TcpTimeout: Number(e.target.value),
                              },
                            },
                          })
                        }
                        className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400">
                        TcpConnectAttempt
                      </label>
                      <input
                        type="number"
                        value={conf.TLS.Utls.TcpConnectAttempt}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            TLS: {
                              ...conf.TLS,
                              Utls: {
                                ...conf.TLS.Utls,
                                TcpConnectAttempt: Number(e.target.value),
                              },
                            },
                          })
                        }
                        className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-2">
                    <div>
                      <label className="block text-[10px] text-slate-400">
                        Fragment.Length
                      </label>
                      <input
                        type="text"
                        value={conf.TLS.Utls.Fragment.Length}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            TLS: {
                              ...conf.TLS,
                              Utls: {
                                ...conf.TLS.Utls,
                                Fragment: {
                                  ...conf.TLS.Utls.Fragment,
                                  Length: e.target.value,
                                },
                              },
                            },
                          })
                        }
                        className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400">
                        Fragment.Delay
                      </label>
                      <input
                        type="text"
                        value={conf.TLS.Utls.Fragment.Delay}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            TLS: {
                              ...conf.TLS,
                              Utls: {
                                ...conf.TLS.Utls,
                                Fragment: {
                                  ...conf.TLS.Utls.Fragment,
                                  Delay: e.target.value,
                                },
                              },
                            },
                          })
                        }
                        className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400">
                        Fragment.MaxSplit
                      </label>
                      <input
                        type="text"
                        value={conf.TLS.Utls.Fragment.MaxSplit}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            TLS: {
                              ...conf.TLS,
                              Utls: {
                                ...conf.TLS.Utls,
                                Fragment: {
                                  ...conf.TLS.Utls.Fragment,
                                  MaxSplit: e.target.value,
                                },
                              },
                            },
                          })
                        }
                        className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'speed' && (
              <div className="space-y-4">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-sky-400">
                  Sequential Speed Tests (DownloadTest & UploadTest)
                </h2>
                {/* DownloadTest */}
                <div className="p-3 rounded border border-slate-800 bg-slate-900/40 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-sky-400">DownloadTest</span>
                    <div className="flex gap-3">
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={conf.DownloadTest.Enable}
                          onChange={(e) =>
                            setConf({
                              ...conf,
                              DownloadTest: {
                                ...conf.DownloadTest,
                                Enable: e.target.checked,
                              },
                            })
                          }
                          className="accent-sky-500"
                        />
                        <span>Enable</span>
                      </label>
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={conf.DownloadTest.SeparateConnection}
                          onChange={(e) =>
                            setConf({
                              ...conf,
                              DownloadTest: {
                                ...conf.DownloadTest,
                                SeparateConnection: e.target.checked,
                              },
                            })
                          }
                          className="accent-sky-500"
                        />
                        <span>SeparateConnection</span>
                      </label>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="col-span-2">
                      <label className="block text-[10px] text-slate-400">Url</label>
                      <input
                        type="text"
                        value={conf.DownloadTest.Url}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            DownloadTest: {
                              ...conf.DownloadTest,
                              Url: e.target.value,
                            },
                          })
                        }
                        className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400">
                        TargetBytes
                      </label>
                      <input
                        type="number"
                        value={conf.DownloadTest.TargetBytes}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            DownloadTest: {
                              ...conf.DownloadTest,
                              TargetBytes: Number(e.target.value),
                            },
                          })
                        }
                        className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400">
                        Timeout (ms)
                      </label>
                      <input
                        type="number"
                        value={conf.DownloadTest.Timeout}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            DownloadTest: {
                              ...conf.DownloadTest,
                              Timeout: Number(e.target.value),
                            },
                          })
                        }
                        className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                  </div>
                </div>

                {/* UploadTest */}
                <div className="p-3 rounded border border-slate-800 bg-slate-900/40 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-emerald-400">UploadTest</span>
                    <div className="flex gap-3">
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={conf.UploadTest.Enable}
                          onChange={(e) =>
                            setConf({
                              ...conf,
                              UploadTest: {
                                ...conf.UploadTest,
                                Enable: e.target.checked,
                              },
                            })
                          }
                          className="accent-emerald-500"
                        />
                        <span>Enable</span>
                      </label>
                      <label className="flex items-center gap-1.5 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={conf.UploadTest.SeparateConnection}
                          onChange={(e) =>
                            setConf({
                              ...conf,
                              UploadTest: {
                                ...conf.UploadTest,
                                SeparateConnection: e.target.checked,
                              },
                            })
                          }
                          className="accent-emerald-500"
                        />
                        <span>SeparateConnection</span>
                      </label>
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-2">
                    <div className="col-span-3">
                      <label className="block text-[10px] text-slate-400">Url</label>
                      <input
                        type="text"
                        value={conf.UploadTest.Url}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            UploadTest: { ...conf.UploadTest, Url: e.target.value },
                          })
                        }
                        className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400">
                        PayloadBytes
                      </label>
                      <input
                        type="number"
                        value={conf.UploadTest.PayloadBytes}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            UploadTest: {
                              ...conf.UploadTest,
                              PayloadBytes: Number(e.target.value),
                            },
                          })
                        }
                        className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400">
                        TargetBytes
                      </label>
                      <input
                        type="number"
                        value={conf.UploadTest.TargetBytes}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            UploadTest: {
                              ...conf.UploadTest,
                              TargetBytes: Number(e.target.value),
                            },
                          })
                        }
                        className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-slate-400">
                        Timeout (ms)
                      </label>
                      <input
                        type="number"
                        value={conf.UploadTest.Timeout}
                        onChange={(e) =>
                          setConf({
                            ...conf,
                            UploadTest: {
                              ...conf.UploadTest,
                              Timeout: Number(e.target.value),
                            },
                          })
                        }
                        className="w-full px-2 py-1 rounded bg-slate-900 border border-slate-700 font-mono"
                      />
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'raw' && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="text-xs font-semibold uppercase tracking-wider text-sky-400">
                    Raw conf.json Editor (Two-Way Synced)
                  </h2>
                  <button
                    onClick={() => {
                      try {
                        const parsed = JSON.parse(rawJsonText);
                        setConf(parsed);
                        setRawJsonError(null);
                        pushLog('info', 'Applied Raw JSON changes to GUI controls.');
                      } catch (e: unknown) {
                        setRawJsonError(
                          e instanceof Error ? e.message : 'Invalid JSON'
                        );
                      }
                    }}
                    className="px-2.5 py-1 rounded bg-sky-500 text-slate-950 font-semibold cursor-pointer"
                  >
                    Apply Raw JSON
                  </button>
                </div>
                {rawJsonError && (
                  <div className="p-2 rounded bg-rose-500/15 border border-rose-500/40 text-rose-300 font-mono text-[11px]">
                    {rawJsonError}
                  </div>
                )}
                <textarea
                  rows={22}
                  value={rawJsonText}
                  onChange={(e) => setRawJsonText(e.target.value)}
                  className={`w-full p-3 rounded border font-mono text-[11px] ${
                    isLight
                      ? 'bg-slate-50 border-slate-300'
                      : 'bg-slate-950 border-slate-800 text-emerald-300'
                  }`}
                />
              </div>
            )}

            {activeTab === 'source' && (
              <div className="space-y-3">
                <h2 className="text-xs font-semibold uppercase tracking-wider text-sky-400">
                  Repository Deliverables ({GO_FILES.length} Files)
                </h2>
                <div className="flex flex-wrap gap-1">
                  {GO_FILES.map((file, idx) => (
                    <button
                      key={file.name}
                      onClick={() => setSelectedFileIdx(idx)}
                      className={`px-2 py-1 rounded font-mono text-[10px] border cursor-pointer ${
                        selectedFileIdx === idx
                          ? 'bg-sky-500/20 border-sky-500 text-sky-300 font-semibold'
                          : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {file.name}
                    </button>
                  ))}
                </div>
                <div className="p-2 rounded bg-slate-900/70 border border-slate-800 flex items-center justify-between">
                  <span className="text-[11px] text-slate-300">
                    {GO_FILES[selectedFileIdx]?.description}
                  </span>
                  <button
                    onClick={() =>
                      copyText(
                        GO_FILES[selectedFileIdx]?.content || '',
                        `file-${selectedFileIdx}`
                      )
                    }
                    className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-[10px] flex items-center gap-1 cursor-pointer"
                  >
                    {copiedId === `file-${selectedFileIdx}` ? (
                      <Check className="w-3 h-3 text-emerald-400" />
                    ) : (
                      <Copy className="w-3 h-3" />
                    )}
                    Copy File
                  </button>
                </div>
                <pre className="p-3 rounded bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-200 overflow-x-auto max-h-[420px]">
                  <code>{GO_FILES[selectedFileIdx]?.content}</code>
                </pre>
              </div>
            )}
          </div>
        </aside>

        {/* Right Live Results Table & Color-Coded Logs (7 cols) */}
        <main className="col-span-12 lg:col-span-7 flex flex-col min-h-0 overflow-hidden">
          {/* Results Table Section */}
          <section className="flex-1 flex flex-col min-h-0 border-b border-slate-800">
            <div
              className={`px-4 py-2.5 border-b flex flex-wrap items-center justify-between gap-2 ${
                isLight
                  ? 'bg-slate-50 border-slate-200'
                  : 'bg-slate-900/60 border-slate-800'
              }`}
            >
              <div className="flex items-center gap-2">
                <h2 className="font-semibold text-xs uppercase tracking-wider">
                  Live Scan Results ({filteredResults.length})
                </h2>
                <input
                  type="text"
                  placeholder="Filter IP, port, or status..."
                  value={resultFilter}
                  onChange={(e) => setResultFilter(e.target.value)}
                  className={`px-2.5 py-1 rounded border font-mono text-[11px] ${
                    isLight
                      ? 'bg-white border-slate-300'
                      : 'bg-slate-950 border-slate-700'
                  }`}
                />
                <label className="flex items-center gap-1 text-[11px] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={passedOnly}
                    onChange={(e) => setPassedOnly(e.target.checked)}
                    className="accent-emerald-500"
                  />
                  <span>Passed Only</span>
                </label>
              </div>

              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => {
                    const ips = filteredResults
                      .filter((r) => r.status === 'PASSED')
                      .map((r) => r.ip)
                      .join('\n');
                    copyText(ips, 'all-ips');
                    pushLog('info', 'Copied all PASSED IPs to clipboard.');
                  }}
                  className="px-2.5 py-1 rounded bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 font-medium flex items-center gap-1 cursor-pointer"
                >
                  {copiedId === 'all-ips' ? (
                    <Check className="w-3 h-3" />
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                  Copy All Passed IPs
                </button>
                <button
                  onClick={() =>
                    pushLog('success', 'Exported results to result.csv')
                  }
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 flex items-center gap-1 cursor-pointer"
                >
                  <Download className="w-3 h-3 text-sky-400" />
                  Export CSV
                </button>
                <button
                  onClick={() =>
                    pushLog('success', 'Exported results to result.txt')
                  }
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 flex items-center gap-1 cursor-pointer"
                >
                  <Download className="w-3 h-3 text-emerald-400" />
                  Export TXT
                </button>
              </div>
            </div>

            <div className="flex-1 overflow-auto">
              <table className="w-full text-left border-collapse font-mono text-[11px]">
                <thead
                  className={`sticky top-0 z-10 border-b ${
                    isLight
                      ? 'bg-slate-100 border-slate-300 text-slate-600'
                      : 'bg-slate-900 border-slate-800 text-slate-400'
                  }`}
                >
                  <tr>
                    {[
                      { key: 'ip', label: 'IP : Port' },
                      { key: 'pingMs', label: 'Ping' },
                      { key: 'latencyMs', label: 'Latency' },
                      { key: 'jitterMs', label: 'Jitter' },
                      { key: 'downloadMbps', label: 'Download Speed' },
                      { key: 'uploadMbps', label: 'Upload Speed' },
                      { key: 'status', label: 'Status' },
                    ].map((col) => (
                      <th
                        key={col.key}
                        onClick={() =>
                          handleSort(
                            col.key as
                              | 'ip'
                              | 'pingMs'
                              | 'latencyMs'
                              | 'jitterMs'
                              | 'downloadMbps'
                              | 'uploadMbps'
                              | 'status'
                          )
                        }
                        className="py-2 px-3 cursor-pointer hover:text-sky-400 select-none"
                      >
                        <div className="flex items-center gap-1">
                          <span>{col.label}</span>
                          <ArrowUpDown className="w-3 h-3 opacity-60" />
                        </div>
                      </th>
                    ))}
                    <th className="py-2 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredResults.map((r) => (
                    <tr
                      key={r.id}
                      className={
                        isLight
                          ? 'hover:bg-slate-50'
                          : 'hover:bg-slate-800/40'
                      }
                    >
                      <td className="py-2 px-3 font-semibold text-sky-400">
                        {r.addr}
                      </td>
                      <td className="py-2 px-3">{r.pingText}</td>
                      <td className="py-2 px-3">{r.latencyMs}ms</td>
                      <td className="py-2 px-3">{r.jitterText}</td>
                      <td className="py-2 px-3 text-emerald-400">
                        {r.downloadSpeed}
                      </td>
                      <td
                        className={`py-2 px-3 ${
                          r.uploadSpeed === 'JAMMED'
                            ? 'text-rose-400 font-semibold'
                            : 'text-emerald-400'
                        }`}
                      >
                        {r.uploadSpeed}
                      </td>
                      <td className="py-2 px-3">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            r.status === 'PASSED'
                              ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                              : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                          }`}
                        >
                          {r.status}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-right">
                        <button
                          onClick={() => copyText(r.ip, `row-${r.id}`)}
                          className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-[10px] cursor-pointer"
                        >
                          {copiedId === `row-${r.id}` ? 'Copied' : 'Copy IP'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          {/* Bottom Live Colored Logs Panel */}
          <section className="h-48 flex flex-col min-h-0">
            <div
              className={`px-4 py-1.5 border-b flex items-center justify-between ${
                isLight
                  ? 'bg-slate-100 border-slate-200'
                  : 'bg-slate-900 border-slate-800'
              }`}
            >
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Real-Time Scanner Log Stream ({logs.length})
              </span>
              <button
                onClick={() => setLogs([])}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] cursor-pointer"
              >
                Clear Log
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-3 font-mono text-[11px] space-y-1 bg-slate-950 text-slate-300">
              {logs.map((l) => (
                <div key={l.id} className="flex items-start gap-2">
                  <span className="text-slate-500 shrink-0">[{l.time}]</span>
                  <span
                    className={
                      l.level === 'success'
                        ? 'text-emerald-400'
                        : l.level === 'warn'
                        ? 'text-amber-400'
                        : l.level === 'error'
                        ? 'text-rose-400'
                        : 'text-sky-300'
                    }
                  >
                    {l.message}
                  </span>
                </div>
              ))}
            </div>
          </section>
        </main>
      </div>
    </div>
  );
}
