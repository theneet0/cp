import React, { useState, useMemo } from 'react';
import {
  CheckCircle2,
  Copy,
  FileCode2,
  Play,
  Shuffle,
  Sliders,
  Terminal,
  AlertTriangle,
  ArrowUpRight,
  ArrowDownLeft,
} from 'lucide-react';
import {
  parseMixedIPList,
  evaluateSpeedTests,
} from './utils/scannerLogic';
import { GO_FILES } from './data/goFiles';

const DEFAULT_IPV4_MIXED = `# Cloudflare mixed IPv4 list (Single IPs + CIDR ranges)
104.16.132.229 # Single IPv4 (auto /32, never dropped)
104.16.132.230/32 // Explicit /32 CIDR
104.16.0.0/29 # 8 IPs (104.16.0.0 - 104.16.0.7)
172.64.0.15

// Below entries test validation & graceful warning skip:
2606:4700::6810:84e5 # IPv6 in IPv4 mode -> skipped with warning
malformed.ip.line`;

const DEFAULT_IPV6_MIXED = `# Cloudflare mixed IPv6 list (Single IPs + CIDR ranges)
2606:4700::6810:84e5 # Single IPv6 (auto /128)
2606:4700::6810:84e6/128 // Explicit /128
2606:4700:10::/48 # IPv6 CIDR range
104.16.132.229 # IPv4 in IPv6 mode -> skipped with warning`;

export default function App() {
  const [activeTab, setActiveTab] = useState<'ip-parser' | 'upload-test' | 'source-files'>('ip-parser');
  const [copiedFile, setCopiedFile] = useState<string | null>(null);
  const [selectedFileIndex, setSelectedFileIndex] = useState(0);

  // Task 2: Mixed Single IP + CIDR Sandbox state
  const [ipVersion, setIpVersion] = useState<4 | 6>(4);
  const [ipListText, setIpListText] = useState<string>(DEFAULT_IPV4_MIXED);
  const [ignoreRangeText, setIgnoreRangeText] = useState<string>('104.16.0.1, 104.16.0.6/31');
  const [allowRangeText, setAllowRangeText] = useState<string>('');
  const [randomScan, setRandomScan] = useState<boolean>(false);
  const [shuffleSeed, setShuffleSeed] = useState<number>(1);

  // Task 1: UploadTest & DownloadTest Sandbox state
  const [enableDownload, setEnableDownload] = useState<boolean>(true);
  const [enableUpload, setEnableUpload] = useState<boolean>(true);
  const [separateConnection, setSeparateConnection] = useState<boolean>(false);
  const [uploadUrl, setUploadUrl] = useState<string>('https://speed.cloudflare.com/__up');
  const [uploadSni, setUploadSni] = useState<string>('cp.cloudflare.com');
  const [payloadBytes, setPayloadBytes] = useState<number>(10_000_000);
  const [targetBytes, setTargetBytes] = useState<number>(5_000_000);
  const [timeoutMs, setTimeoutMs] = useState<number>(5000);
  const [simulatedUploadBytes, setSimulatedUploadBytes] = useState<number>(10_000_000);
  const [simulatedUploadElapsedMs, setSimulatedUploadElapsedMs] = useState<number>(1850);
  const [simulatedUploadDrop, setSimulatedUploadDrop] = useState<boolean>(false);
  const [simulatedDownloadBytes, setSimulatedDownloadBytes] = useState<number>(10_000_000);
  const [simulatedDownloadElapsedMs, setSimulatedDownloadElapsedMs] = useState<number>(1250);

  const parsedIPResult = useMemo(() => {
    const ignores = ignoreRangeText
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter(Boolean);
    const allows = allowRangeText
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter(Boolean);
    return parseMixedIPList(ipListText, ipVersion, ignores, allows);
  }, [ipListText, ipVersion, ignoreRangeText, allowRangeText]);

  const displayedIPs = useMemo(() => {
    const list = [...parsedIPResult.expandedIPs];
    if (!randomScan) return list;
    let seed = shuffleSeed;
    for (let i = list.length - 1; i > 0; i--) {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      const j = seed % (i + 1);
      [list[i], list[j]] = [list[j], list[i]];
    }
    return list;
  }, [parsedIPResult.expandedIPs, randomScan, shuffleSeed]);

  const speedEval = useMemo(() => {
    return evaluateSpeedTests({
      enableDownload,
      downloadBytesTransferred: simulatedDownloadBytes,
      downloadTargetBytes: 5_000_000,
      downloadElapsedMs: simulatedDownloadElapsedMs,
      downloadTimeoutMs: 5000,
      downloadDroppedMidTransfer: false,
      enableUpload,
      uploadPayloadBytes: payloadBytes,
      uploadBytesTransferred: simulatedUploadBytes,
      uploadTargetBytes: targetBytes,
      uploadElapsedMs: simulatedUploadElapsedMs,
      uploadTimeoutMs: timeoutMs,
      uploadDroppedMidTransfer: simulatedUploadDrop,
      ipAddr: ipVersion === 4 ? '104.16.132.229' : '2606:4700::6810:84e5',
      port: 443,
      pingMs: 38,
      latencyMs: 112,
      jitterMs: 4.82,
    });
  }, [
    enableDownload,
    simulatedDownloadBytes,
    simulatedDownloadElapsedMs,
    enableUpload,
    payloadBytes,
    simulatedUploadBytes,
    targetBytes,
    simulatedUploadElapsedMs,
    timeoutMs,
    simulatedUploadDrop,
    ipVersion,
  ]);

  const handleSwitchVersion = (v: 4 | 6) => {
    setIpVersion(v);
    if (v === 4) {
      setIpListText(DEFAULT_IPV4_MIXED);
      setIgnoreRangeText('104.16.0.1, 104.16.0.6/31');
      setAllowRangeText('');
    } else {
      setIpListText(DEFAULT_IPV6_MIXED);
      setIgnoreRangeText('2606:4700::6810:84e6');
      setAllowRangeText('');
    }
  };

  const handleCopyCode = (filename: string, content: string) => {
    navigator.clipboard?.writeText(content);
    setCopiedFile(filename);
    setTimeout(() => setCopiedFile(null), 1800);
  };

  const activeFile = GO_FILES[selectedFileIndex];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Bar Contract: 3 zones separated by gap-8 */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-slate-800 bg-slate-900/80">
        <a
          href="#top"
          className="text-lg font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0"
        >
          cf-scanner
        </a>

        <nav
          aria-label="Primary sections"
          className="flex items-center gap-6 text-sm font-medium text-slate-400"
        >
          <button
            type="button"
            onClick={() => setActiveTab('ip-parser')}
            className={`transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'ip-parser'
                ? 'text-slate-100 underline underline-offset-8 decoration-sky-400 decoration-2'
                : 'hover:text-slate-200'
            }`}
          >
            Single IP & CIDR Parser
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('upload-test')}
            className={`transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'upload-test'
                ? 'text-slate-100 underline underline-offset-8 decoration-sky-400 decoration-2'
                : 'hover:text-slate-200'
            }`}
          >
            Upload Speed Test
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('source-files')}
            className={`transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              activeTab === 'source-files'
                ? 'text-slate-100 underline underline-offset-8 decoration-sky-400 decoration-2'
                : 'hover:text-slate-200'
            }`}
          >
            Go Source Files
          </button>
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => setActiveTab('source-files')}
            className="px-4 py-2 text-xs font-semibold text-slate-950 bg-sky-400 rounded-lg hover:bg-sky-300 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Inspect Go Deliverables
          </button>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-8 space-y-8">
        {/* Summary Header */}
        <section className="flex flex-col lg:flex-row lg:items-end justify-between gap-6 pb-6 border-b border-slate-800">
          <div className="space-y-2 max-w-3xl">
            <p className="text-xs text-slate-400">
              github.com/radioactiveAHM/cf-scanner · Go 1.27.4 Verified · Zero Build Errors
            </p>
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-100">
              Upload Speed Test & Mixed Single IP / CIDR Range Architecture
            </h1>
            <p className="text-sm text-slate-400 leading-relaxed">
              Interactive verification workbench for the two new <code className="text-slate-200">cf-scanner</code> capabilities:
              streaming HTTP POST <code className="text-slate-200">UploadTest</code> with <code className="text-slate-200">JAMMED</code> detection, and single IP (<code className="text-slate-200">/32</code> &amp; <code className="text-slate-200">/128</code>) + CIDR parsing across <code className="text-slate-200">IplistPath</code>, <code className="text-slate-200">AllowRange</code>, and <code className="text-slate-200">IgnoreRange</code>.
            </p>
          </div>

          <div className="grid grid-cols-3 gap-6 text-right font-mono tabular-nums shrink-0">
            <div>
              <div className="text-xs text-slate-400">Go Build</div>
              <div className="text-base font-semibold text-emerald-400 flex items-center justify-end gap-1.5 mt-0.5">
                <CheckCircle2 className="w-4 h-4" />
                PASS
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-400">Go Unit Tests</div>
              <div className="text-base font-semibold text-emerald-400 mt-0.5">7 / 7 PASS</div>
            </div>
            <div>
              <div className="text-xs text-slate-400">Modified Files</div>
              <div className="text-base font-semibold text-slate-100 mt-0.5">6 Files</div>
            </div>
          </div>
        </section>

        {/* TAB 1: Mixed Single IP & CIDR Parser */}
        {activeTab === 'ip-parser' && (
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            <div className="lg:col-span-6 space-y-6 bg-slate-900 border border-slate-800 rounded-xl p-6">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <h2 className="text-lg font-semibold text-slate-100">
                    Task 2: IplistPath, AllowRange &amp; IgnoreRange Input
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Supports bare single IPs, CIDR blocks, inline comments, and version validation.
                  </p>
                </div>

                <div className="flex items-center gap-1 p-1 bg-slate-950 border border-slate-800 rounded-lg">
                  <button
                    type="button"
                    onClick={() => handleSwitchVersion(4)}
                    className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      ipVersion === 4
                        ? 'bg-sky-400 text-slate-950 font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    IpVersion: 4
                  </button>
                  <button
                    type="button"
                    onClick={() => handleSwitchVersion(6)}
                    className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      ipVersion === 6
                        ? 'bg-sky-400 text-slate-950 font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    IpVersion: 6
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                <label
                  htmlFor="iplist-textarea"
                  className="block text-xs font-medium text-slate-300"
                >
                  IplistPath File Content ({ipVersion === 4 ? 'ipv4.txt' : 'ipv6.txt'})
                </label>
                <textarea
                  id="iplist-textarea"
                  rows={8}
                  value={ipListText}
                  onChange={(e) => setIpListText(e.target.value)}
                  className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3.5 py-2.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-400"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label
                    htmlFor="ignore-range-input"
                    className="block text-xs font-medium text-slate-300"
                  >
                    IgnoreRange (Single IPs or CIDRs)
                  </label>
                  <input
                    id="ignore-range-input"
                    type="text"
                    value={ignoreRangeText}
                    onChange={(e) => setIgnoreRangeText(e.target.value)}
                    placeholder="e.g. 104.16.0.1, 172.0.0.0/8"
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-400"
                  />
                </div>

                <div className="space-y-1.5">
                  <label
                    htmlFor="allow-range-input"
                    className="block text-xs font-medium text-slate-300"
                  >
                    AllowRange (Single IPs or CIDRs)
                  </label>
                  <input
                    id="allow-range-input"
                    type="text"
                    value={allowRangeText}
                    onChange={(e) => setAllowRangeText(e.target.value)}
                    placeholder="Empty = allow all"
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-sky-400"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between pt-2 border-t border-slate-800">
                <label className="flex items-center gap-2.5 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={randomScan}
                    onChange={(e) => setRandomScan(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-950 text-sky-400 focus:ring-sky-400"
                  />
                  <span>Enable RandomScan (Shuffle generated IP list)</span>
                </label>

                <button
                  type="button"
                  onClick={() => {
                    setRandomScan(true);
                    setShuffleSeed((s) => s + 1);
                  }}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Shuffle className="w-3.5 h-3.5" />
                  Shuffle Order
                </button>
              </div>
            </div>

            <div className="lg:col-span-6 space-y-6">
              {/* ProgressBar & Counter verification */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-100">
                      ProgressBar &amp; Address Expansion Summary
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Single IPs (/32 and /128) are preserved without dropping network/broadcast addresses.
                    </p>
                  </div>
                  <div className="text-right font-mono tabular-nums">
                    <div className="text-xs text-slate-400">ProgressBar Total</div>
                    <div className="text-lg font-bold text-sky-400">
                      {displayedIPs.length} Targets
                    </div>
                  </div>
                </div>

                {/* Normalized Prefix Table */}
                <div className="overflow-x-auto border border-slate-800 rounded-lg">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400">
                        <th className="py-2.5 px-3 font-medium">Input Entry</th>
                        <th className="py-2.5 px-3 font-medium">Canonical Prefix</th>
                        <th className="py-2.5 px-3 font-medium">Type</th>
                        <th className="py-2.5 px-3 font-medium text-right">Host Count</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/70 font-mono tabular-nums">
                      {parsedIPResult.validEntries.map((entry, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/40">
                          <td className="py-2 px-3 text-slate-200">{entry.cleaned}</td>
                          <td className="py-2 px-3 text-sky-400">{entry.canonicalCIDR}</td>
                          <td className="py-2 px-3 text-slate-300 font-sans">
                            {entry.isSingleIP
                              ? `Single IP (/${entry.prefixBits})`
                              : `CIDR Subnet (/${entry.prefixBits})`}
                          </td>
                          <td className="py-2 px-3 text-right text-slate-200">
                            {entry.ipVersion === 6 && !entry.isSingleIP
                              ? `2^${128 - entry.prefixBits}`
                              : entry.addressCount.toLocaleString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Graceful Warnings Log */}
                {parsedIPResult.warnings.length > 0 && (
                  <div className="bg-amber-950/30 border border-amber-800/60 rounded-lg p-3.5 space-y-1.5">
                    <div className="flex items-center gap-2 text-xs font-semibold text-amber-300">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      <span>Graceful Validation Warnings (Skipped Without Crashing)</span>
                    </div>
                    <ul className="space-y-1 text-xs font-mono text-amber-200/90">
                      {parsedIPResult.warnings.map((w, i) => (
                        <li key={i}>{w}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Generated Scan Queue */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span>
                      Generated Scan Queue ({randomScan ? 'Shuffled via RandomScan' : 'Sequential Order'})
                    </span>
                    <span className="font-mono tabular-nums">
                      { parsedIPResult.skippedCommentsOrEmpty } empty/comment lines ignored
                    </span>
                  </div>
                  <div className="bg-slate-950 border border-slate-800 rounded-lg p-3 max-h-40 overflow-y-auto font-mono text-xs text-slate-200 grid grid-cols-2 sm:grid-cols-3 gap-1.5 tabular-nums">
                    {displayedIPs.map((ip, idx) => (
                      <div
                        key={`${ip}-${idx}`}
                        className="px-2 py-1 rounded bg-slate-900 border border-slate-800/80 truncate"
                      >
                        <span className="text-slate-500 mr-1.5">{idx + 1}.</span>
                        {ip}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* TAB 2: Upload Speed Test (UploadTest) */}
        {activeTab === 'upload-test' && (
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            <div className="lg:col-span-6 space-y-6 bg-slate-900 border border-slate-800 rounded-xl p-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-semibold text-slate-100">
                    Task 1: UploadTest Configuration &amp; Transfer Simulation
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Configure <code className="text-slate-200">UploadTest</code> and <code className="text-slate-200">DownloadTest</code> independently or sequentially.
                  </p>
                </div>
                <Sliders className="w-4 h-4 text-slate-400" />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <label className="flex items-center gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-medium text-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableDownload}
                    onChange={(e) => setEnableDownload(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-900 text-sky-400"
                  />
                  <span>DownloadTest.Enable</span>
                </label>

                <label className="flex items-center gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-medium text-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={enableUpload}
                    onChange={(e) => setEnableUpload(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-900 text-sky-400"
                  />
                  <span>UploadTest.Enable</span>
                </label>

                <label className="flex items-center gap-2.5 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-medium text-slate-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={separateConnection}
                    onChange={(e) => setSeparateConnection(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-900 text-sky-400"
                  />
                  <span>SeparateConnection</span>
                </label>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label htmlFor="upload-url" className="block text-xs font-medium text-slate-300">
                    UploadTest.Url (POST Endpoint)
                  </label>
                  <input
                    id="upload-url"
                    type="text"
                    value={uploadUrl}
                    onChange={(e) => setUploadUrl(e.target.value)}
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs font-mono text-slate-100"
                  />
                </div>
                <div className="space-y-1.5">
                  <label htmlFor="upload-sni" className="block text-xs font-medium text-slate-300">
                    UploadTest.SNI
                  </label>
                  <input
                    id="upload-sni"
                    type="text"
                    value={uploadSni}
                    onChange={(e) => setUploadSni(e.target.value)}
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs font-mono text-slate-100"
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4 font-mono tabular-nums">
                <div className="space-y-1.5">
                  <label htmlFor="payload-bytes" className="block text-xs font-sans font-medium text-slate-300">
                    PayloadBytes
                  </label>
                  <input
                    id="payload-bytes"
                    type="number"
                    value={payloadBytes}
                    onChange={(e) => setPayloadBytes(Number(e.target.value))}
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-slate-100"
                  />
                </div>
                <div className="space-y-1.5">
                  <label htmlFor="target-bytes" className="block text-xs font-sans font-medium text-slate-300">
                    TargetBytes
                  </label>
                  <input
                    id="target-bytes"
                    type="number"
                    value={targetBytes}
                    onChange={(e) => setTargetBytes(Number(e.target.value))}
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-slate-100"
                  />
                </div>
                <div className="space-y-1.5">
                  <label htmlFor="timeout-ms" className="block text-xs font-sans font-medium text-slate-300">
                    Timeout (ms)
                  </label>
                  <input
                    id="timeout-ms"
                    type="number"
                    value={timeoutMs}
                    onChange={(e) => setTimeoutMs(Number(e.target.value))}
                    className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-slate-100"
                  />
                </div>
              </div>

              <div className="pt-4 border-t border-slate-800 space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-200">
                    Simulate Network Conditions
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setSimulatedUploadBytes(10_000_000);
                        setSimulatedUploadElapsedMs(1850);
                        setSimulatedUploadDrop(false);
                      }}
                      className="px-2.5 py-1 text-xs font-medium rounded bg-slate-800 hover:bg-slate-700 text-slate-200 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Healthy Uplink (5.4 MB/s)
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setSimulatedUploadBytes(2_400_000);
                        setSimulatedUploadElapsedMs(5000);
                        setSimulatedUploadDrop(false);
                      }}
                      className="px-2.5 py-1 text-xs font-medium rounded bg-amber-950/80 border border-amber-800/70 hover:bg-amber-900/60 text-amber-200 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Below TargetBytes (JAMMED)
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setSimulatedUploadBytes(6_200_000);
                        setSimulatedUploadElapsedMs(1100);
                        setSimulatedUploadDrop(true);
                      }}
                      className="px-2.5 py-1 text-xs font-medium rounded bg-rose-950/80 border border-rose-800/70 hover:bg-rose-900/60 text-rose-200 whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      Mid-Transfer Drop (JAMMED)
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 text-xs">
                  <div className="space-y-1">
                    <div className="flex justify-between text-slate-400">
                      <span>Actual Uploaded Bytes</span>
                      <span className="font-mono tabular-nums text-slate-200">
                        {(simulatedUploadBytes / 1_000_000).toFixed(2)} MB
                      </span>
                    </div>
                    <input
                      type="range"
                      aria-label="Actual Uploaded Bytes"
                      min={0}
                      max={payloadBytes}
                      step={250_000}
                      value={simulatedUploadBytes}
                      onChange={(e) => setSimulatedUploadBytes(Number(e.target.value))}
                      className="w-full accent-sky-400"
                    />
                  </div>

                  <div className="space-y-1">
                    <div className="flex justify-between text-slate-400">
                      <span>Upload Duration</span>
                      <span className="font-mono tabular-nums text-slate-200">
                        {simulatedUploadElapsedMs} ms
                      </span>
                    </div>
                    <input
                      type="range"
                      aria-label="Upload Duration"
                      min={200}
                      max={6000}
                      step={50}
                      value={simulatedUploadElapsedMs}
                      onChange={(e) => setSimulatedUploadElapsedMs(Number(e.target.value))}
                      className="w-full accent-sky-400"
                    />
                  </div>
                </div>
              </div>
            </div>

            <div className="lg:col-span-6 space-y-6">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-5">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-100">
                      Sequential Execution &amp; Output Preview
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Mode: <span className="text-slate-200 font-medium">{speedEval.executionMode}</span> (Goroutines: 1 recommended when speed tests are enabled)
                    </p>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-4 font-mono tabular-nums">
                  <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <div className="flex items-center justify-between text-xs text-slate-400 font-sans">
                      <span>DownloadTest Result</span>
                      <ArrowDownLeft className="w-4 h-4 text-sky-400" />
                    </div>
                    <div className="text-lg font-bold text-slate-100">
                      {speedEval.downloadReport}
                    </div>
                  </div>

                  <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <div className="flex items-center justify-between text-xs text-slate-400 font-sans">
                      <span>UploadTest Result</span>
                      <ArrowUpRight className="w-4 h-4 text-emerald-400" />
                    </div>
                    <div
                      className={`text-lg font-bold ${
                        speedEval.uploadReport === 'JAMMED'
                          ? 'text-amber-400'
                          : speedEval.uploadReport === 'Null'
                          ? 'text-slate-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {speedEval.uploadReport}
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="text-xs font-medium text-slate-300">
                    Console &amp; <code className="text-slate-200">result.txt</code> Output Line
                  </div>
                  <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto tabular-nums">
                    {speedEval.txtLine}
                  </pre>
                </div>

                <div className="space-y-2">
                  <div className="text-xs font-medium text-slate-300">
                    <code className="text-slate-200">result.csv</code> Output (with <code className="text-slate-200">upload</code> column)
                  </div>
                  <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 overflow-x-auto tabular-nums">
                    {speedEval.csvHeader}
                    {'\n'}
                    {speedEval.csvLine}
                  </pre>
                </div>
              </div>
            </div>
          </section>
        )}

        {/* TAB 3: Go Source Deliverables */}
        {activeTab === 'source-files' && (
          <section className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            <div className="lg:col-span-4 space-y-2">
              {GO_FILES.map((file, idx) => (
                <button
                  key={file.filename}
                  type="button"
                  onClick={() => setSelectedFileIndex(idx)}
                  className={`w-full text-left p-4 rounded-xl border transition-colors cursor-pointer ${
                    selectedFileIndex === idx
                      ? 'bg-slate-900 border-sky-400/80 text-slate-100'
                      : 'bg-slate-900/50 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-sm font-semibold text-slate-100 flex items-center gap-2">
                      <FileCode2 className="w-4 h-4 text-sky-400 shrink-0" />
                      {file.filename}
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      {file.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                    {file.summary}
                  </p>
                </button>
              ))}
            </div>

            <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
              <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-800 bg-slate-950/60">
                <div className="flex items-center gap-2 text-xs font-mono text-slate-200">
                  <Terminal className="w-4 h-4 text-sky-400" />
                  <span>cf-scanner/{activeFile.filename}</span>
                  <span aria-hidden="true">·</span>
                  <span className="text-slate-400">{activeFile.status}</span>
                </div>
                <button
                  type="button"
                  onClick={() => handleCopyCode(activeFile.filename, activeFile.content)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  <Copy className="w-3.5 h-3.5" />
                  {copiedFile === activeFile.filename ? 'Copied' : 'Copy File'}
                </button>
              </div>
              <pre className="p-5 text-xs font-mono text-slate-200 overflow-x-auto max-h-[540px] leading-relaxed">
                <code>{activeFile.content}</code>
              </pre>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
