import test from 'node:test';
import assert from 'node:assert/strict';
import {
  cleanIPListLine,
  parseIPOrPrefix,
  parseMixedIPList,
  evaluateSpeedTests,
} from './scannerLogic';

test('cleanIPListLine strips # and // comments and whitespace', () => {
  assert.equal(cleanIPListLine('  # full comment '), '');
  assert.equal(cleanIPListLine('// another comment'), '');
  assert.equal(cleanIPListLine('104.16.132.229 # inline comment'), '104.16.132.229');
  assert.equal(cleanIPListLine('104.16.0.0/24 // cidr comment'), '104.16.0.0/24');
});

test('parseIPOrPrefix converts single IPv4 to /32 and single IPv6 to /128', () => {
  const v4 = parseIPOrPrefix('104.16.132.229', 4);
  assert.ok(v4.prefix);
  assert.equal(v4.prefix.canonicalCIDR, '104.16.132.229/32');
  assert.equal(v4.prefix.isSingleIP, true);
  assert.equal(v4.prefix.addressCount, 1);

  const v6 = parseIPOrPrefix('2606:4700::6810:84e5', 6);
  assert.ok(v6.prefix);
  assert.equal(v6.prefix.canonicalCIDR, '2606:4700::6810:84e5/128');
  assert.equal(v6.prefix.isSingleIP, true);
  assert.equal(v6.prefix.addressCount, 1);

  const mismatch = parseIPOrPrefix('2606:4700::6810:84e5', 4);
  assert.ok(mismatch.error);
});

test('parseMixedIPList preserves single IPs (/32) and applies single-IP IgnoreRange/AllowRange', () => {
  const input = [
    '# Cloudflare mixed list',
    '104.16.132.229',
    '104.16.132.230/32',
    '104.16.0.0/30',
    '2606:4700::6810:84e5',
    'malformed_entry',
  ].join('\n');

  const res = parseMixedIPList(
    input,
    4,
    ['104.16.0.1'], // Ignore single IP inside /30
    ['104.16.132.229', '104.16.132.230/32', '104.16.0.0/30']
  );

  assert.deepEqual(res.expandedIPs, [
    '104.16.132.229',
    '104.16.132.230',
    '104.16.0.0',
    '104.16.0.2',
    '104.16.0.3',
  ]);
  assert.equal(res.warnings.length, 2);
});

test('evaluateSpeedTests formats UploadTest and DownloadTest results and detects JAMMED', () => {
  const normal = evaluateSpeedTests({
    enableDownload: true,
    downloadBytesTransferred: 10_000_000,
    downloadTargetBytes: 5_000_000,
    downloadElapsedMs: 2000,
    downloadTimeoutMs: 5000,
    downloadDroppedMidTransfer: false,
    enableUpload: true,
    uploadPayloadBytes: 10_000_000,
    uploadBytesTransferred: 8_000_000,
    uploadTargetBytes: 5_000_000,
    uploadElapsedMs: 2000,
    uploadTimeoutMs: 5000,
    uploadDroppedMidTransfer: false,
    ipAddr: '104.16.132.229',
    port: 443,
    pingMs: 42,
    latencyMs: 118,
    jitterMs: 6.25,
  });

  assert.equal(normal.downloadReport, '5.000000MB/S');
  assert.equal(normal.uploadReport, '4.000000MB/S');
  assert.equal(normal.executionMode, 'sequential');
  assert.equal(
    normal.csvLine,
    '104.16.132.229:443,42ms,118,6.250000,5.000000MB/S,4.000000MB/S'
  );

  const jammedUpload = evaluateSpeedTests({
    enableDownload: false,
    downloadBytesTransferred: 0,
    downloadTargetBytes: 5_000_000,
    downloadElapsedMs: 0,
    downloadTimeoutMs: 5000,
    downloadDroppedMidTransfer: false,
    enableUpload: true,
    uploadPayloadBytes: 10_000_000,
    uploadBytesTransferred: 2_000_000, // below 5,000,000 TargetBytes
    uploadTargetBytes: 5_000_000,
    uploadElapsedMs: 5000,
    uploadTimeoutMs: 5000,
    uploadDroppedMidTransfer: false,
    ipAddr: '104.16.132.229',
    port: 443,
    pingMs: 42,
    latencyMs: 118,
    jitterMs: null,
  });

  assert.equal(jammedUpload.downloadReport, 'Null');
  assert.equal(jammedUpload.uploadReport, 'JAMMED');
  assert.equal(jammedUpload.executionMode, 'upload-only');
});
