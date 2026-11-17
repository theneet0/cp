(function () {
  'use strict';

  const DEFAULT_CONFIG = {
    ProgressBar: true,
    Log: true,
    CSV: false,
    RandomScan: true,
    Hostname: 'cp.cloudflare.com',
    Ports: [],
    Path: '/',
    Headers: {
      'User-Agent': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0',
      ],
    },
    ResponseHeader: {
      Server: 'cloudflare',
    },
    ResponseStatusCode: [200, 204],
    Padding: true,
    PaddingSize: '100-1000',
    Ping: {
      Enable: true,
      MaxPing: 300,
      Privileged: true,
      Size: '24-65',
    },
    Goroutines: 16,
    Maxlatency: 2000,
    Jitter: {
      Enable: true,
      MaxJitter: 50.0,
      Samples: 5,
      Interval: 200,
    },
    IpVersion: 4,
    IplistPath: 'ipv4.txt',
    IgnoreRange: [],
    AllowRange: [],
    TLS: {
      Enable: true,
      SNI: 'cp.cloudflare.com',
      Insecure: false,
      Alpn: ['h2', 'http/1.1'],
      Utls: {
        Enable: true,
        Fingerprint: 'chrome',
        TcpTimeout: 1000,
        TcpConnectAttempt: 1,
        Fragment: {
          Enable: false,
          Length: '50-100',
          Delay: '10-15',
          MaxSplit: null,
        },
      },
    },
    'HTTP/3': false,
    Noises: {
      Enable: false,
      Packets: [
        { Type: 'rand', Payload: '1-10', Sleep: '20-50' },
        { Type: 'rand', Payload: '1-20', Sleep: '20-50' },
      ],
    },
    DomainScan: {
      Enable: false,
      DomainAsSNI: false,
      DomainAsHost: false,
      Shuffle: true,
      SkipIPV6: true,
      DomainListPath: 'cloudfalare-domains.txt',
    },
    DownloadTest: {
      Enable: false,
      SeparateConnection: false,
      Url: 'https://speed.cloudflare.com/__down?bytes=10000000',
      SNI: 'cp.cloudflare.com',
      TargetBytes: 5000000,
      Timeout: 5000,
    },
    UploadTest: {
      Enable: false,
      SeparateConnection: false,
      Url: 'https://speed.cloudflare.com/__up',
      SNI: 'cp.cloudflare.com',
      PayloadBytes: 10000000,
      TargetBytes: 5000000,
      Timeout: 5000,
    },
  };

  let currentConfig = structuredClone(DEFAULT_CONFIG);
  let scanResults = [];
  let scanLogs = [];
  let sortKey = 'latencyMs';
  let sortAsc = true;
  let isScanning = false;

  const hasWails = () => Boolean(window.go && window.go.main && window.go.main.App);

  const $ = (id) => document.getElementById(id);

  function appendLog(level, message, timestamp) {
    const ts = timestamp || new Date().toTimeString().slice(0, 8);
    scanLogs.push({ level, message, timestamp: ts });
    if (scanLogs.length > 1000) {
      scanLogs.shift();
    }
    renderLogs();
  }

  function renderLogs() {
    const container = $('logs-container');
    const filter = $('log-level-filter').value;
    const autoScroll = $('log-autoscroll').checked;
    container.innerHTML = '';

    const filtered = scanLogs.filter((l) => filter === 'all' || l.level === filter);
    for (const item of filtered) {
      const div = document.createElement('div');
      div.className = `log-line log-${item.level || 'info'}`;
      div.textContent = `[${item.timestamp}] ${item.message}`;
      container.appendChild(div);
    }
    if (autoScroll) {
      container.scrollTop = container.scrollHeight;
    }
  }

  function renderResultsTable() {
    const tbody = $('results-tbody');
    const query = ($('results-filter').value || '').trim().toLowerCase();

    const filtered = scanResults.filter((r) => {
      if (!query) return true;
      return (
        (r.addr && r.addr.toLowerCase().includes(query)) ||
        (r.ip && r.ip.toLowerCase().includes(query)) ||
        (r.domain && r.domain.toLowerCase().includes(query)) ||
        (r.status && r.status.toLowerCase().includes(query))
      );
    });

    filtered.sort((a, b) => {
      const va = a[sortKey] ?? '';
      const vb = b[sortKey] ?? '';
      if (typeof va === 'number' && typeof vb === 'number') {
        return sortAsc ? va - vb : vb - va;
      }
      return sortAsc
        ? String(va).localeCompare(String(vb))
        : String(vb).localeCompare(String(va));
    });

    tbody.innerHTML = '';
    if (filtered.length === 0) {
      const tr = document.createElement('tr');
      tr.className = 'empty-row';
      tr.innerHTML = '<td colspan="8">No matching scan results.</td>';
      tbody.appendChild(tr);
      return;
    }

    for (const r of filtered) {
      const tr = document.createElement('tr');
      const label = r.domain ? `${r.domain} (${r.addr})` : r.addr;
      const statusClass = r.status === 'PASSED' ? 'status-passed' : 'status-jammed';
      tr.innerHTML = `
        <td class="mono">${label}</td>
        <td class="num">${r.pingText || '0ms'}</td>
        <td class="num">${r.latencyMs} ms</td>
        <td class="num">${r.jitterText || 'Null'}</td>
        <td class="num">${r.downloadSpeed || 'Null'}</td>
        <td class="num">${r.uploadSpeed || 'Null'}</td>
        <td class="${statusClass}">${r.status}</td>
        <td><button type="button" class="btn btn-secondary btn-sm btn-copy-ip" data-ip="${r.ip}">Copy IP</button></td>
      `;
      tbody.appendChild(tr);
    }

    tbody.querySelectorAll('.btn-copy-ip').forEach((btn) => {
      btn.addEventListener('click', () => {
        const ip = btn.getAttribute('data-ip');
        navigator.clipboard?.writeText(ip);
        btn.textContent = 'Copied';
        setTimeout(() => {
          btn.textContent = 'Copy IP';
        }, 1200);
      });
    });
  }

  function renderKeyValueLists() {
    // Request Headers (map[string][]string)
    const reqContainer = $('req-headers-list');
    reqContainer.innerHTML = '';
    const headersObj = currentConfig.Headers || {};
    Object.keys(headersObj).forEach((key) => {
      const vals = Array.isArray(headersObj[key]) ? headersObj[key].join(', ') : String(headersObj[key]);
      const row = document.createElement('div');
      row.className = 'kv-row';
      row.innerHTML = `
        <input type="text" class="mono req-hdr-key" value="${key.replace(/"/g, '&quot;')}" placeholder="Header Name" />
        <input type="text" class="mono req-hdr-val" value="${vals.replace(/"/g, '&quot;')}" placeholder="Header Value" />
        <button type="button" class="btn btn-ghost btn-sm">Remove</button>
      `;
      row.querySelector('button').addEventListener('click', () => {
        row.remove();
        readFormIntoConfig();
      });
      row.querySelectorAll('input').forEach((inp) => inp.addEventListener('input', readFormIntoConfig));
      reqContainer.appendChild(row);
    });

    // ResponseHeader (map[string]string)
    const respContainer = $('resp-headers-list');
    respContainer.innerHTML = '';
    const respObj = currentConfig.ResponseHeader || {};
    Object.keys(respObj).forEach((key) => {
      const val = String(respObj[key] ?? '');
      const row = document.createElement('div');
      row.className = 'kv-row';
      row.innerHTML = `
        <input type="text" class="mono resp-hdr-key" value="${key.replace(/"/g, '&quot;')}" placeholder="Response Header" />
        <input type="text" class="mono resp-hdr-val" value="${val.replace(/"/g, '&quot;')}" placeholder="Expected Value" />
        <button type="button" class="btn btn-ghost btn-sm">Remove</button>
      `;
      row.querySelector('button').addEventListener('click', () => {
        row.remove();
        readFormIntoConfig();
      });
      row.querySelectorAll('input').forEach((inp) => inp.addEventListener('input', readFormIntoConfig));
      respContainer.appendChild(row);
    });

    // Noise Packets ([]NoisePacket)
    const noiseContainer = $('noise-packets-list');
    noiseContainer.innerHTML = '';
    const packets = (currentConfig.Noises && currentConfig.Noises.Packets) || [];
    packets.forEach((pkt) => {
      const row = document.createElement('div');
      row.className = 'noise-row';
      row.innerHTML = `
        <select class="mono noise-type">
          <option value="rand" ${pkt.Type === 'rand' ? 'selected' : ''}>rand</option>
          <option value="str" ${pkt.Type === 'str' ? 'selected' : ''}>str</option>
          <option value="base64" ${pkt.Type === 'base64' ? 'selected' : ''}>base64</option>
          <option value="hex" ${pkt.Type === 'hex' ? 'selected' : ''}>hex</option>
        </select>
        <input type="text" class="mono noise-payload" value="${(pkt.Payload || '').replace(/"/g, '&quot;')}" placeholder="Payload (e.g. 1-10)" />
        <input type="text" class="mono noise-sleep" value="${(pkt.Sleep || '').replace(/"/g, '&quot;')}" placeholder="Sleep ms (20-50)" />
        <button type="button" class="btn btn-ghost btn-sm">Remove</button>
      `;
      row.querySelector('button').addEventListener('click', () => {
        row.remove();
        readFormIntoConfig();
      });
      row.querySelectorAll('input, select').forEach((el) => el.addEventListener('input', readFormIntoConfig));
      noiseContainer.appendChild(row);
    });
  }

  function populateFormFromConfig(cfg) {
    currentConfig = structuredClone(cfg);

    $('cfg-ProgressBar').checked = Boolean(cfg.ProgressBar);
    $('cfg-Log').checked = Boolean(cfg.Log);
    $('cfg-CSV').checked = Boolean(cfg.CSV);
    $('cfg-RandomScan').checked = Boolean(cfg.RandomScan);
    $('cfg-Goroutines').value = cfg.Goroutines ?? 16;
    $('cfg-Maxlatency').value = cfg.Maxlatency ?? 2000;

    $('cfg-IpVersion').value = String(cfg.IpVersion || 4);
    $('cfg-IplistPath').value = cfg.IplistPath || '';
    $('cfg-IgnoreRange').value = (cfg.IgnoreRange || []).join('\n');
    $('cfg-AllowRange').value = (cfg.AllowRange || []).join('\n');

    const ds = cfg.DomainScan || {};
    $('cfg-DomainScan-Enable').checked = Boolean(ds.Enable);
    $('cfg-DomainScan-DomainAsSNI').checked = Boolean(ds.DomainAsSNI);
    $('cfg-DomainScan-DomainAsHost').checked = Boolean(ds.DomainAsHost);
    $('cfg-DomainScan-Shuffle').checked = Boolean(ds.Shuffle);
    $('cfg-DomainScan-SkipIPV6').checked = Boolean(ds.SkipIPV6);
    $('cfg-DomainScan-DomainListPath').value = ds.DomainListPath || '';

    $('cfg-Hostname').value = cfg.Hostname || '';
    $('cfg-Path').value = cfg.Path || '/';
    $('cfg-Ports').value = (cfg.Ports || []).join(', ');
    $('cfg-ResponseStatusCode').value = (cfg.ResponseStatusCode || [200, 204]).join(', ');
    $('cfg-Padding').checked = Boolean(cfg.Padding);
    $('cfg-PaddingSize').value = cfg.PaddingSize || '100-1000';

    const ping = cfg.Ping || {};
    $('cfg-Ping-Enable').checked = Boolean(ping.Enable);
    $('cfg-Ping-MaxPing').value = ping.MaxPing ?? 300;
    $('cfg-Ping-Privileged').checked = Boolean(ping.Privileged);
    $('cfg-Ping-Size').value = ping.Size || '24-65';

    const jit = cfg.Jitter || {};
    $('cfg-Jitter-Enable').checked = Boolean(jit.Enable);
    $('cfg-Jitter-MaxJitter').value = jit.MaxJitter ?? 50.0;
    $('cfg-Jitter-Samples').value = jit.Samples ?? 5;
    $('cfg-Jitter-Interval').value = jit.Interval ?? 200;

    const tls = cfg.TLS || {};
    $('cfg-TLS-Enable').checked = Boolean(tls.Enable);
    $('cfg-TLS-SNI').value = tls.SNI || '';
    $('cfg-TLS-Insecure').checked = Boolean(tls.Insecure);
    $('cfg-TLS-Alpn').value = (tls.Alpn || ['h2', 'http/1.1']).join(', ');
    $('cfg-HTTP3').checked = Boolean(cfg['HTTP/3']);

    const utls = tls.Utls || {};
    $('cfg-TLS-Utls-Enable').checked = Boolean(utls.Enable);
    $('cfg-TLS-Utls-Fingerprint').value = utls.Fingerprint || 'chrome';
    $('cfg-TLS-Utls-TcpTimeout').value = utls.TcpTimeout ?? 1000;
    $('cfg-TLS-Utls-TcpConnectAttempt').value = utls.TcpConnectAttempt ?? 1;

    const frag = utls.Fragment || {};
    $('cfg-Fragment-Enable').checked = Boolean(frag.Enable);
    $('cfg-Fragment-Length').value = frag.Length || '50-100';
    $('cfg-Fragment-Delay').value = frag.Delay || '10-15';
    $('cfg-Fragment-MaxSplit').value = frag.MaxSplit || '';

    const noises = cfg.Noises || {};
    $('cfg-Noises-Enable').checked = Boolean(noises.Enable);

    const dl = cfg.DownloadTest || {};
    $('cfg-DownloadTest-Enable').checked = Boolean(dl.Enable);
    $('cfg-DownloadTest-SeparateConnection').checked = Boolean(dl.SeparateConnection);
    $('cfg-DownloadTest-Url').value = dl.Url || '';
    $('cfg-DownloadTest-SNI').value = dl.SNI || '';
    $('cfg-DownloadTest-TargetBytes').value = dl.TargetBytes ?? 5000000;
    $('cfg-DownloadTest-Timeout').value = dl.Timeout ?? 5000;

    const ul = cfg.UploadTest || {};
    $('cfg-UploadTest-Enable').checked = Boolean(ul.Enable);
    $('cfg-UploadTest-SeparateConnection').checked = Boolean(ul.SeparateConnection);
    $('cfg-UploadTest-Url').value = ul.Url || '';
    $('cfg-UploadTest-SNI').value = ul.SNI || '';
    $('cfg-UploadTest-PayloadBytes').value = ul.PayloadBytes ?? 10000000;
    $('cfg-UploadTest-TargetBytes').value = ul.TargetBytes ?? 5000000;
    $('cfg-UploadTest-Timeout').value = ul.Timeout ?? 5000;

    renderKeyValueLists();
    syncRawJSONEditor();
    updateValidationBanner();
  }

  function parseIntList(str) {
    return String(str || '')
      .split(',')
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => !Number.isNaN(n) && n > 0);
  }

  function parseLinesList(str) {
    return String(str || '')
      .split(/\r?\n|,/)
      .map((s) => s.trim())
      .filter(Boolean);
  }

  function readFormIntoConfig() {
    const reqHeaders = {};
    document.querySelectorAll('#req-headers-list .kv-row').forEach((row) => {
      const k = row.querySelector('.req-hdr-key').value.trim();
      const v = row.querySelector('.req-hdr-val').value.trim();
      if (k) {
        reqHeaders[k] = [v];
      }
    });

    const respHeaders = {};
    document.querySelectorAll('#resp-headers-list .kv-row').forEach((row) => {
      const k = row.querySelector('.resp-hdr-key').value.trim();
      const v = row.querySelector('.resp-hdr-val').value.trim();
      if (k) {
        respHeaders[k] = v;
      }
    });

    const noisePackets = [];
    document.querySelectorAll('#noise-packets-list .noise-row').forEach((row) => {
      noisePackets.push({
        Type: row.querySelector('.noise-type').value,
        Payload: row.querySelector('.noise-payload').value.trim(),
        Sleep: row.querySelector('.noise-sleep').value.trim(),
      });
    });

    const maxSplitRaw = $('cfg-Fragment-MaxSplit').value.trim();

    currentConfig = {
      ProgressBar: $('cfg-ProgressBar').checked,
      Log: $('cfg-Log').checked,
      CSV: $('cfg-CSV').checked,
      RandomScan: $('cfg-RandomScan').checked,
      Hostname: $('cfg-Hostname').value.trim(),
      Ports: parseIntList($('cfg-Ports').value),
      Path: $('cfg-Path').value.trim() || '/',
      Headers: reqHeaders,
      ResponseHeader: respHeaders,
      ResponseStatusCode: parseIntList($('cfg-ResponseStatusCode').value),
      Padding: $('cfg-Padding').checked,
      PaddingSize: $('cfg-PaddingSize').value.trim(),
      Ping: {
        Enable: $('cfg-Ping-Enable').checked,
        MaxPing: parseFloat($('cfg-Ping-MaxPing').value) || 300,
        Privileged: $('cfg-Ping-Privileged').checked,
        Size: $('cfg-Ping-Size').value.trim(),
      },
      Goroutines: parseInt($('cfg-Goroutines').value, 10) || 1,
      Maxlatency: parseInt($('cfg-Maxlatency').value, 10) || 2000,
      Jitter: {
        Enable: $('cfg-Jitter-Enable').checked,
        MaxJitter: parseFloat($('cfg-Jitter-MaxJitter').value) || 50.0,
        Samples: parseInt($('cfg-Jitter-Samples').value, 10) || 5,
        Interval: parseInt($('cfg-Jitter-Interval').value, 10) || 200,
      },
      IpVersion: parseInt($('cfg-IpVersion').value, 10) || 4,
      IplistPath: $('cfg-IplistPath').value.trim(),
      IgnoreRange: parseLinesList($('cfg-IgnoreRange').value),
      AllowRange: parseLinesList($('cfg-AllowRange').value),
      TLS: {
        Enable: $('cfg-TLS-Enable').checked,
        SNI: $('cfg-TLS-SNI').value.trim(),
        Insecure: $('cfg-TLS-Insecure').checked,
        Alpn: $('cfg-TLS-Alpn')
          .value.split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        Utls: {
          Enable: $('cfg-TLS-Utls-Enable').checked,
          Fingerprint: $('cfg-TLS-Utls-Fingerprint').value,
          TcpTimeout: parseInt($('cfg-TLS-Utls-TcpTimeout').value, 10) || 1000,
          TcpConnectAttempt: parseInt($('cfg-TLS-Utls-TcpConnectAttempt').value, 10) || 1,
          Fragment: {
            Enable: $('cfg-Fragment-Enable').checked,
            Length: $('cfg-Fragment-Length').value.trim(),
            Delay: $('cfg-Fragment-Delay').value.trim(),
            MaxSplit: maxSplitRaw === '' || maxSplitRaw === 'null' ? null : maxSplitRaw,
          },
        },
      },
      'HTTP/3': $('cfg-HTTP3').checked,
      Noises: {
        Enable: $('cfg-Noises-Enable').checked,
        Packets: noisePackets,
      },
      DomainScan: {
        Enable: $('cfg-DomainScan-Enable').checked,
        DomainAsSNI: $('cfg-DomainScan-DomainAsSNI').checked,
        DomainAsHost: $('cfg-DomainScan-DomainAsHost').checked,
        Shuffle: $('cfg-DomainScan-Shuffle').checked,
        SkipIPV6: $('cfg-DomainScan-SkipIPV6').checked,
        DomainListPath: $('cfg-DomainScan-DomainListPath').value.trim(),
      },
      DownloadTest: {
        Enable: $('cfg-DownloadTest-Enable').checked,
        SeparateConnection: $('cfg-DownloadTest-SeparateConnection').checked,
        Url: $('cfg-DownloadTest-Url').value.trim(),
        SNI: $('cfg-DownloadTest-SNI').value.trim(),
        TargetBytes: parseInt($('cfg-DownloadTest-TargetBytes').value, 10) || 5000000,
        Timeout: parseInt($('cfg-DownloadTest-Timeout').value, 10) || 5000,
      },
      UploadTest: {
        Enable: $('cfg-UploadTest-Enable').checked,
        SeparateConnection: $('cfg-UploadTest-SeparateConnection').checked,
        Url: $('cfg-UploadTest-Url').value.trim(),
        SNI: $('cfg-UploadTest-SNI').value.trim(),
        PayloadBytes: parseInt($('cfg-UploadTest-PayloadBytes').value, 10) || 10000000,
        TargetBytes: parseInt($('cfg-UploadTest-TargetBytes').value, 10) || 5000000,
        Timeout: parseInt($('cfg-UploadTest-Timeout').value, 10) || 5000,
      },
    };

    syncRawJSONEditor();
    updateValidationBanner();
  }

  function syncRawJSONEditor() {
    $('raw-json-editor').value = JSON.stringify(currentConfig, null, '\t');
    $('raw-json-error').classList.add('hidden');
  }

  function updateValidationBanner() {
    const speedEnabled = currentConfig.DownloadTest.Enable || currentConfig.UploadTest.Enable;
    const g = currentConfig.Goroutines;
    const banner = $('goroutine-warning');
    if (speedEnabled && g > 1) {
      $('warn-goroutine-val').textContent = String(g);
      banner.classList.remove('hidden');
    } else {
      banner.classList.add('hidden');
    }
  }

  function updateProgressUI(p) {
    $('stat-scanned').textContent = `${p.scanned} / ${p.total}`;
    $('stat-passed').textContent = String(p.passed);
    $('stat-elapsed').textContent = p.elapsedText || '0.0s';
    const pct = Math.min(100, Math.max(0, p.percent || 0));
    $('progress-fill').style.width = `${pct}%`;
    $('progress-bar-container').setAttribute('aria-valuenow', String(Math.round(pct)));
  }

  function updateStateUI(state) {
    const badge = $('status-badge');
    const btn = $('btn-start-stop');
    badge.setAttribute('data-state', state);
    const labelMap = {
      idle: 'Idle',
      running: 'Running',
      stopping: 'Stopping...',
      completed: 'Completed',
      stopped: 'Stopped',
      error: 'Error',
    };
    badge.textContent = labelMap[state] || state;
    isScanning = state === 'running' || state === 'stopping';
    btn.setAttribute('data-running', String(isScanning));
    btn.textContent = isScanning ? 'Stop Scan' : 'Start Scan';
  }

  function initEvents() {
    // Sidebar tab navigation
    document.querySelectorAll('.nav-item').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-item').forEach((b) => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
        btn.classList.add('active');
        const target = $(btn.getAttribute('data-tab'));
        if (target) target.classList.add('active');
      });
    });

    // Bind all config inputs
    document.querySelectorAll('.config-pane input, .config-pane select, .config-pane textarea').forEach((el) => {
      if (el.id === 'raw-json-editor' || el.id === 'iplist-inline-editor') return;
      el.addEventListener('input', readFormIntoConfig);
      el.addEventListener('change', readFormIntoConfig);
    });

    $('btn-fix-goroutines').addEventListener('click', () => {
      $('cfg-Goroutines').value = '1';
      readFormIntoConfig();
      appendLog('info', 'Updated Goroutines to 1 for accurate speed test measurements.');
    });

    // Dynamic Key-Value & Noise Packet Adders
    $('btn-add-req-header').addEventListener('click', () => {
      currentConfig.Headers = currentConfig.Headers || {};
      currentConfig.Headers[`X-Custom-${Object.keys(currentConfig.Headers).length + 1}`] = ['value'];
      renderKeyValueLists();
      readFormIntoConfig();
    });

    $('btn-add-resp-header').addEventListener('click', () => {
      currentConfig.ResponseHeader = currentConfig.ResponseHeader || {};
      currentConfig.ResponseHeader['cf-ray'] = '';
      renderKeyValueLists();
      readFormIntoConfig();
    });

    $('btn-add-noise-packet').addEventListener('click', () => {
      currentConfig.Noises = currentConfig.Noises || { Enable: false, Packets: [] };
      currentConfig.Noises.Packets.push({ Type: 'rand', Payload: '1-15', Sleep: '20-50' });
      renderKeyValueLists();
      readFormIntoConfig();
    });

    // Raw JSON Sync
    $('btn-apply-raw-json').addEventListener('click', async () => {
      const raw = $('raw-json-editor').value;
      try {
        const parsed = hasWails()
          ? await window.go.main.App.ParseRawConfig(raw)
          : JSON.parse(raw);
        populateFormFromConfig(parsed);
        appendLog('success', 'Applied Raw JSON configuration to all form controls.');
      } catch (err) {
        const errBox = $('raw-json-error');
        errBox.textContent = `JSON Parse Error: ${err.message || err}`;
        errBox.classList.remove('hidden');
      }
    });

    $('btn-copy-raw-json').addEventListener('click', () => {
      navigator.clipboard?.writeText($('raw-json-editor').value);
      appendLog('info', 'Copied conf.json content to clipboard.');
    });

    // Theme toggle
    $('btn-theme-toggle').addEventListener('click', () => {
      const html = document.documentElement;
      const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      html.setAttribute('data-theme', next);
      $('btn-theme-toggle').textContent = next === 'dark' ? 'Light Mode' : 'Dark Mode';
    });

    // File actions
    $('btn-load-conf').addEventListener('click', async () => {
      if (hasWails()) {
        try {
          const cfg = await window.go.main.App.GetConfig();
          populateFormFromConfig(cfg);
          appendLog('success', 'Loaded configuration from conf.json.');
        } catch (e) {
          appendLog('error', `Failed to load conf.json: ${e}`);
        }
      } else {
        populateFormFromConfig(DEFAULT_CONFIG);
        appendLog('info', 'Loaded conf.json configuration.');
      }
    });

    $('btn-save-conf').addEventListener('click', async () => {
      readFormIntoConfig();
      if (hasWails()) {
        try {
          await window.go.main.App.SaveConfig(currentConfig);
          appendLog('success', 'Saved configuration to conf.json.');
        } catch (e) {
          appendLog('error', `Failed to save conf.json: ${e}`);
        }
      } else {
        appendLog('success', 'Configuration saved to conf.json.');
      }
    });

    $('btn-import-conf').addEventListener('click', async () => {
      if (hasWails()) {
        try {
          const cfg = await window.go.main.App.ImportConfigDialog();
          populateFormFromConfig(cfg);
          appendLog('success', 'Imported configuration JSON.');
        } catch (e) {
          appendLog('error', `Import failed: ${e}`);
        }
      }
    });

    $('btn-save-as-conf').addEventListener('click', async () => {
      readFormIntoConfig();
      if (hasWails()) {
        try {
          const dest = await window.go.main.App.SaveConfigAs(currentConfig);
          if (dest) appendLog('success', `Saved configuration to ${dest}.`);
        } catch (e) {
          appendLog('error', `Save As failed: ${e}`);
        }
      }
    });

    $('btn-reset-conf').addEventListener('click', async () => {
      const cfg = hasWails() ? await window.go.main.App.ResetDefaultConfig() : DEFAULT_CONFIG;
      populateFormFromConfig(cfg);
      appendLog('info', 'Reset configuration to default values.');
    });

    // Browse file dialogs & inline IP list editor
    $('btn-browse-iplist').addEventListener('click', async () => {
      if (hasWails()) {
        const path = await window.go.main.App.BrowseFile('Select IP List File', currentConfig.IplistPath);
        if (path) {
          $('cfg-IplistPath').value = path;
          readFormIntoConfig();
        }
      }
    });

    $('btn-browse-domainlist').addEventListener('click', async () => {
      if (hasWails()) {
        const path = await window.go.main.App.BrowseFile('Select Domain List File', currentConfig.DomainScan.DomainListPath);
        if (path) {
          $('cfg-DomainScan-DomainListPath').value = path;
          readFormIntoConfig();
        }
      }
    });

    $('btn-load-iplist-editor').addEventListener('click', async () => {
      const path = $('cfg-IplistPath').value.trim();
      if (hasWails()) {
        try {
          const text = await window.go.main.App.ReadTextFile(path);
          $('iplist-inline-editor').value = text;
          appendLog('info', `Loaded ${path} into inline IP/CIDR editor.`);
        } catch (e) {
          appendLog('error', `Could not read ${path}: ${e}`);
        }
      }
    });

    $('btn-save-iplist-editor').addEventListener('click', async () => {
      const path = $('cfg-IplistPath').value.trim();
      const content = $('iplist-inline-editor').value;
      if (hasWails()) {
        try {
          await window.go.main.App.WriteTextFile(path, content);
          appendLog('success', `Saved inline IP/CIDR list to ${path}.`);
        } catch (e) {
          appendLog('error', `Could not write ${path}: ${e}`);
        }
      } else {
        appendLog('success', `Saved inline IP/CIDR list to ${path}.`);
      }
    });

    $('btn-preview-iplist').addEventListener('click', async () => {
      const content = $('iplist-inline-editor').value;
      if (hasWails()) {
        const res = await window.go.main.App.PreviewIPList(
          content,
          currentConfig.IpVersion,
          currentConfig.IgnoreRange,
          currentConfig.AllowRange
        );
        $('iplist-preview-summary').textContent = `Valid Entries: ${res.entries.length} · Total Scan Targets: ${res.totalTargets} · Skipped Comments/Blank: ${res.skippedLines}`;
        const warnBox = $('iplist-warnings');
        if (res.warnings && res.warnings.length > 0) {
          warnBox.textContent = res.warnings.join(' | ');
          warnBox.classList.remove('hidden');
        } else {
          warnBox.classList.add('hidden');
        }
      }
    });

    // Start / Stop Scan
    $('btn-start-stop').addEventListener('click', async () => {
      readFormIntoConfig();
      if (isScanning) {
        if (hasWails()) {
          await window.go.main.App.StopScan();
        }
        updateStateUI('stopped');
        return;
      }

      scanResults = [];
      renderResultsTable();
      updateStateUI('running');
      if (hasWails()) {
        try {
          await window.go.main.App.StartScan(currentConfig);
        } catch (e) {
          appendLog('error', `Failed to start scan: ${e}`);
          updateStateUI('error');
        }
      }
    });

    // Results table sorting, filtering, copy, export
    $('results-filter').addEventListener('input', renderResultsTable);
    document.querySelectorAll('#results-table th.sortable').forEach((th) => {
      th.addEventListener('click', () => {
        const key = th.getAttribute('data-sort');
        if (sortKey === key) sortAsc = !sortAsc;
        else {
          sortKey = key;
          sortAsc = true;
        }
        renderResultsTable();
      });
    });

    $('btn-copy-all-ips').addEventListener('click', () => {
      const ips = scanResults.filter((r) => r.status === 'PASSED').map((r) => r.ip);
      navigator.clipboard?.writeText(ips.join('\n'));
      appendLog('info', `Copied ${ips.length} passed IP(s) to clipboard.`);
    });

    $('btn-export-csv').addEventListener('click', async () => {
      if (hasWails()) {
        const dest = await window.go.main.App.ExportResults('csv', scanResults);
        if (dest) appendLog('success', `Exported CSV results to ${dest}.`);
      }
    });

    $('btn-export-txt').addEventListener('click', async () => {
      if (hasWails()) {
        const dest = await window.go.main.App.ExportResults('txt', scanResults);
        if (dest) appendLog('success', `Exported TXT results to ${dest}.`);
      }
    });

    $('log-level-filter').addEventListener('change', renderLogs);
    $('btn-clear-logs').addEventListener('click', () => {
      scanLogs = [];
      renderLogs();
    });

    // Subscribe to Wails runtime events
    if (window.runtime && window.runtime.EventsOn) {
      window.runtime.EventsOn('scan:state', (st) => updateStateUI(st));
      window.runtime.EventsOn('scan:progress', (p) => updateProgressUI(p));
      window.runtime.EventsOn('scan:log', (l) => appendLog(l.level, l.message, l.timestamp));
      window.runtime.EventsOn('scan:result', (r) => {
        scanResults.push(r);
        renderResultsTable();
      });
    }
  }

  async function init() {
    initEvents();
    if (hasWails()) {
      try {
        const cfg = await window.go.main.App.GetConfig();
        populateFormFromConfig(cfg);
      } catch (_) {
        populateFormFromConfig(DEFAULT_CONFIG);
      }
    } else {
      populateFormFromConfig(DEFAULT_CONFIG);
    }
  }

  document.addEventListener('DOMContentLoaded', init);
})();
