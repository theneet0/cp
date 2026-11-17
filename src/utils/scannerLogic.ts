export interface ParsedPrefix {
  raw: string;
  cleaned: string;
  ipVersion: 4 | 6;
  networkAddress: string;
  prefixBits: number;
  canonicalCIDR: string;
  isSingleIP: boolean;
  addressCount: number; // capped for IPv6 display
  firstIP: string;
  lastIP: string;
}

export interface ParseIPListResult {
  validEntries: ParsedPrefix[];
  expandedIPs: string[];
  skippedCommentsOrEmpty: number;
  warnings: string[];
  allSingleIPv6: boolean;
}

export interface UploadTestConfig {
  Enable: boolean;
  SeparateConnection: boolean;
  Url: string;
  SNI: string;
  PayloadBytes: number;
  TargetBytes: number;
  Timeout: number;
}

export interface DownloadTestConfig {
  Enable: boolean;
  SeparateConnection: boolean;
  Url: string;
  SNI: string;
  TargetBytes: number;
  Timeout: number;
}

export interface SpeedEvalInput {
  enableDownload: boolean;
  downloadBytesTransferred: number;
  downloadTargetBytes: number;
  downloadElapsedMs: number;
  downloadTimeoutMs: number;
  downloadDroppedMidTransfer: boolean;
  enableUpload: boolean;
  uploadPayloadBytes: number;
  uploadBytesTransferred: number;
  uploadTargetBytes: number;
  uploadElapsedMs: number;
  uploadTimeoutMs: number;
  uploadDroppedMidTransfer: boolean;
  ipAddr: string;
  port: number;
  pingMs: number;
  latencyMs: number;
  jitterMs: number | null;
}

export interface SpeedEvalResult {
  downloadReport: string;
  uploadReport: string;
  executionMode: 'sequential' | 'download-only' | 'upload-only' | 'none';
  txtLine: string;
  csvHeader: string;
  csvLine: string;
}

export function cleanIPListLine(raw: string): string {
  let line = raw.trim();
  if (!line || line.startsWith('#') || line.startsWith('//')) {
    return '';
  }
  const hashIdx = line.indexOf('#');
  if (hashIdx !== -1) {
    line = line.slice(0, hashIdx).trim();
  }
  const slashIdx = line.indexOf('//');
  if (slashIdx !== -1) {
    line = line.slice(0, slashIdx).trim();
  }
  return line;
}

function ipv4ToUint32(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    result = ((result << 8) | n) >>> 0;
  }
  return result >>> 0;
}

function uint32ToIPv4(n: number): string {
  return [
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ].join('.');
}

function isValidIPv6Addr(ip: string): boolean {
  if (!ip.includes(':')) return false;
  // Reject IPv4 octets or invalid characters
  if (!/^[0-9a-fA-F:]+$/.test(ip)) return false;
  const doubleColonParts = ip.split('::');
  if (doubleColonParts.length > 2) return false;
  const groups = ip.split(':').filter((g) => g.length > 0);
  if (doubleColonParts.length === 1 && groups.length !== 8) return false;
  if (doubleColonParts.length === 2 && groups.length > 7) return false;
  return groups.every((g) => g.length <= 4);
}

export function parseIPOrPrefix(
  raw: string,
  expectedVersion: 4 | 6
): { prefix?: ParsedPrefix; error?: string } {
  const cleaned = cleanIPListLine(raw);
  if (!cleaned) {
    return { error: 'empty input' };
  }

  const hasSlash = cleaned.includes('/');
  let addrPart = cleaned;
  let bits: number | null = null;

  if (hasSlash) {
    const parts = cleaned.split('/');
    if (parts.length !== 2 || !/^\d+$/.test(parts[1])) {
      return { error: `invalid CIDR "${cleaned}"` };
    }
    addrPart = parts[0];
    bits = Number(parts[1]);
  }

  const v4Int = ipv4ToUint32(addrPart);
  if (v4Int !== null) {
    const prefixBits = bits === null ? 32 : bits;
    if (prefixBits < 0 || prefixBits > 32) {
      return { error: `invalid IPv4 prefix length /${prefixBits} in "${cleaned}"` };
    }
    if (expectedVersion !== 4) {
      return { error: `entry "${cleaned}" is not IPv6 (IpVersion=6)` };
    }
    const mask = prefixBits === 0 ? 0 : (0xffffffff << (32 - prefixBits)) >>> 0;
    const networkInt = (v4Int & mask) >>> 0;
    const count = prefixBits === 32 ? 1 : Math.pow(2, 32 - prefixBits);
    const lastInt = (networkInt + count - 1) >>> 0;
    const netStr = uint32ToIPv4(networkInt);

    return {
      prefix: {
        raw,
        cleaned,
        ipVersion: 4,
        networkAddress: netStr,
        prefixBits,
        canonicalCIDR: `${netStr}/${prefixBits}`,
        isSingleIP: prefixBits === 32,
        addressCount: count,
        firstIP: netStr,
        lastIP: uint32ToIPv4(lastInt),
      },
    };
  }

  if (isValidIPv6Addr(addrPart)) {
    const prefixBits = bits === null ? 128 : bits;
    if (prefixBits < 0 || prefixBits > 128) {
      return { error: `invalid IPv6 prefix length /${prefixBits} in "${cleaned}"` };
    }
    if (expectedVersion !== 6) {
      return { error: `entry "${cleaned}" is not IPv4 (IpVersion=4)` };
    }
    const normalized = addrPart.toLowerCase();
    return {
      prefix: {
        raw,
        cleaned,
        ipVersion: 6,
        networkAddress: normalized,
        prefixBits,
        canonicalCIDR: `${normalized}/${prefixBits}`,
        isSingleIP: prefixBits === 128,
        addressCount: prefixBits === 128 ? 1 : Math.pow(2, Math.min(20, 128 - prefixBits)),
        firstIP: normalized,
        lastIP: prefixBits === 128 ? normalized : `${normalized} (random /${prefixBits})`,
      },
    };
  }

  return { error: `invalid IP address or CIDR "${cleaned}"` };
}

function ipv4InPrefix(ipInt: number, prefix: ParsedPrefix): boolean {
  const netInt = ipv4ToUint32(prefix.networkAddress);
  if (netInt === null) return false;
  const mask = prefix.prefixBits === 0 ? 0 : (0xffffffff << (32 - prefix.prefixBits)) >>> 0;
  return ((ipInt & mask) >>> 0) === netInt;
}

export function parseMixedIPList(
  fileContent: string,
  ipVersion: 4 | 6,
  ignoreRange: string[] = [],
  allowRange: string[] = [],
  maxExpand = 4096
): ParseIPListResult {
  const lines = fileContent.split(/\r?\n/);
  const validEntries: ParsedPrefix[] = [];
  const expandedIPs: string[] = [];
  const warnings: string[] = [];
  let skippedCommentsOrEmpty = 0;

  const ignorePrefixes: ParsedPrefix[] = [];
  for (const r of ignoreRange) {
    const c = cleanIPListLine(r);
    if (!c) continue;
    const res = parseIPOrPrefix(c, ipVersion);
    if (res.prefix) ignorePrefixes.push(res.prefix);
    else if (res.error) warnings.push(`IgnoreRange warning: ${res.error}`);
  }

  const allowPrefixes: ParsedPrefix[] = [];
  for (const r of allowRange) {
    const c = cleanIPListLine(r);
    if (!c) continue;
    const res = parseIPOrPrefix(c, ipVersion);
    if (res.prefix) allowPrefixes.push(res.prefix);
    else if (res.error) warnings.push(`AllowRange warning: ${res.error}`);
  }

  for (const rawLine of lines) {
    const cleaned = cleanIPListLine(rawLine);
    if (!cleaned) {
      skippedCommentsOrEmpty++;
      continue;
    }
    const res = parseIPOrPrefix(cleaned, ipVersion);
    if (res.error || !res.prefix) {
      warnings.push(`Warning: skipping invalid IP${ipVersion === 4 ? 'v4' : 'v6'}/CIDR line "${rawLine.trim()}": ${res.error}`);
      continue;
    }

    const p = res.prefix;
    validEntries.push(p);

    if (ipVersion === 4) {
      const startInt = ipv4ToUint32(p.networkAddress)!;
      const count = Math.min(p.addressCount, maxExpand);
      for (let offset = 0; offset < count; offset++) {
        if (expandedIPs.length >= maxExpand) break;
        const ipInt = (startInt + offset) >>> 0;
        const isIgnored = ignorePrefixes.some((ig) => ipv4InPrefix(ipInt, ig));
        if (isIgnored) continue;
        if (allowPrefixes.length > 0) {
          const isAllowed = allowPrefixes.some((al) => ipv4InPrefix(ipInt, al));
          if (!isAllowed) continue;
        }
        expandedIPs.push(uint32ToIPv4(ipInt));
      }
    } else {
      const isIgnored = ignorePrefixes.some(
        (ig) => ig.networkAddress === p.networkAddress && ig.prefixBits <= p.prefixBits
      );
      if (isIgnored) continue;
      if (allowPrefixes.length > 0) {
        const isAllowed = allowPrefixes.some(
          (al) =>
            p.networkAddress.startsWith(al.networkAddress.replace(/::$/, '')) ||
            al.networkAddress === p.networkAddress
        );
        if (!isAllowed) continue;
      }
      expandedIPs.push(p.isSingleIP ? p.networkAddress : p.canonicalCIDR);
    }
  }

  const allSingleIPv6 =
    ipVersion === 6 &&
    validEntries.length > 0 &&
    validEntries.every((e) => e.isSingleIP);

  return {
    validEntries,
    expandedIPs,
    skippedCommentsOrEmpty,
    warnings,
    allSingleIPv6,
  };
}

export function evaluateSpeedTests(input: SpeedEvalInput): SpeedEvalResult {
  let downloadReport = 'Null';
  let uploadReport = 'Null';

  if (input.enableDownload) {
    if (input.downloadDroppedMidTransfer) {
      downloadReport = 'JAMMED';
    } else if (input.downloadElapsedMs > input.downloadTimeoutMs) {
      downloadReport = 'Timeout';
    } else if (input.downloadBytesTransferred < input.downloadTargetBytes) {
      downloadReport = 'JAMMED';
    } else {
      const sec = Math.max(0.001, input.downloadElapsedMs / 1000);
      const mbps = input.downloadBytesTransferred / sec / 1_000_000;
      downloadReport = `${mbps.toFixed(6)}MB/S`;
    }
  }

  if (input.enableUpload) {
    if (input.uploadDroppedMidTransfer) {
      uploadReport = 'JAMMED';
    } else if (input.uploadBytesTransferred < input.uploadTargetBytes) {
      uploadReport = 'JAMMED';
    } else {
      const effectiveMs = Math.min(input.uploadElapsedMs, input.uploadTimeoutMs);
      const sec = Math.max(0.001, effectiveMs / 1000);
      const mbps = input.uploadBytesTransferred / sec / 1_000_000;
      uploadReport = `${mbps.toFixed(6)}MB/S`;
    }
  }

  let executionMode: SpeedEvalResult['executionMode'] = 'none';
  if (input.enableDownload && input.enableUpload) executionMode = 'sequential';
  else if (input.enableDownload) executionMode = 'download-only';
  else if (input.enableUpload) executionMode = 'upload-only';

  const addrStr = input.ipAddr.includes(':')
    ? `[${input.ipAddr}]:${input.port}`
    : `${input.ipAddr}:${input.port}`;
  const pingStr = `${input.pingMs}ms`;
  const jitterStr = input.jitterMs !== null ? input.jitterMs.toFixed(6) : 'Null';

  const txtLine = `${addrStr.padEnd(21, ' ')} ${pingStr.padEnd(12, ' ')} ${input.latencyMs}\t${jitterStr}\t${downloadReport}\t${uploadReport}`;
  const csvHeader = 'ip:port,ping,latency,jitter,download,upload';
  const csvLine = `${addrStr},${pingStr},${input.latencyMs},${jitterStr},${downloadReport},${uploadReport}`;

  return {
    downloadReport,
    uploadReport,
    executionMode,
    txtLine,
    csvHeader,
    csvLine,
  };
}
