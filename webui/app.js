// AntiMal.VX web UI (P2 shell). Vanilla JS, no build step. Renders the 8-section
// console and talks to the C++ host over the WebView2 bridge. All values that
// could be host/sample derived are escaped via esc() before going into the DOM
// (Section 5). P2 uses realistic mock data; P3 swaps it for real bridge data.
(function () {
  'use strict';

  // ---------- helpers ----------
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

  // ---------- bridge ----------
  var nextReqId = 1, pending = new Map();
  function send(cmd, args) {
    var reqId = nextReqId++;
    return new Promise(function (resolve) {
      pending.set(reqId, resolve);
      try { window.chrome.webview.postMessage({ cmd: cmd, reqId: reqId, args: args || {} }); }
      catch (e) { resolve({ ok: false, error: 'bridge unavailable' }); }
    });
  }
  if (window.chrome && window.chrome.webview) {
    window.chrome.webview.addEventListener('message', function (e) {
      var m = e.data;
      if (!m || typeof m !== 'object') return;
      if (typeof m.reqId === 'number') {
        var r = pending.get(m.reqId); if (r) { pending.delete(m.reqId); r(m); } return;
      }
      if (m.evt === 'log' && m.data) appendLog(m.data.level || 'INFO', m.data.msg || '');
      if (m.evt === 'run.status' && m.data) { /* P4 */ }
      if (m.evt === 'telemetry' && m.data) { /* P4 */ }
    });
  }

  // ---------- status log ----------
  var logEl, logFilter = 'all', logQuery = '';
  function pad2(n) { return (n < 10 ? '0' : '') + n; }
  function appendLog(level, msg) {
    if (!logEl) return;
    var lv = String(level).toLowerCase();
    var d = new Date();
    var line = document.createElement('div');
    line.className = 'log-line log-' + lv;
    line.dataset.lvl = lv;
    var ts = document.createElement('span'); ts.className = 'ts';
    ts.textContent = pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
    var l = document.createElement('span'); l.className = 'lvl'; l.textContent = String(level).toUpperCase();
    var m = document.createElement('span'); m.className = 'msg'; m.textContent = String(msg); // injection-safe
    line.appendChild(ts); line.appendChild(l); line.appendChild(m);
    logEl.appendChild(line);
    applyLogFilter(line);
    logEl.scrollTop = logEl.scrollHeight;
  }
  function applyLogFilter(line) {
    var lv = line.dataset.lvl;
    var okLvl = logFilter === 'all' || lv === logFilter;
    var okQ = !logQuery || line.textContent.toLowerCase().indexOf(logQuery) !== -1;
    line.style.display = (okLvl && okQ) ? '' : 'none';
  }
  function refilterLog() { $all('.log-line', logEl).forEach(applyLogFilter); }

  // ---------- components ----------
  function riskChip(score) {
    var cls = score >= 70 ? 'high' : (score >= 40 ? 'susp' : 'low');
    return '<span class="chip ' + cls + '">' + esc(score) + '</span>';
  }
  function verdictBadge(v) {
    return '<span class="verdict ' + esc(String(v).toLowerCase()) + '">' + esc(v) + '</span>';
  }
  function tags(list) {
    return '<span class="tags">' + list.map(function (t) { return '<span class="tag">' + esc(t) + '</span>'; }).join('') + '</span>';
  }
  function kv(pairs) {
    return '<div class="kv">' + pairs.map(function (p) {
      return '<div class="k">' + esc(p[0]) + '</div><div class="v">' + esc(p[1]) + '</div>';
    }).join('') + '</div>';
  }

  // ---------- mock data (P3 replaces with bridge data) ----------
  var MOCK = {
    latestRun: {
      verdict: 'Booted to desktop', runId: 'bdf6c191-89d3-42a9-89a9-d65e597bd800',
      frame: 'screenshots/guest-000625.png', when: '2026-05-31 05:51', network: 'Disabled', timeout: 180
    },
    metrics: { vmsec: 184, frames: 994, events: 1317, overlay: '412 MB', hb: 'NO HB', net: 'Disabled' },
    results: [
      { score: 72, verdict: 'Suspicious', tags: ['Packed', 'Suspicious API', 'Network IOC'], path: 'C:/Samples/sample.exe', sha: 'a3f9c2e85a4b11d9e8f09c92e51b4f3c7a6e2d1c9f8b7a4d6e0c2a1f5b9d8e77' },
      { score: 18, verdict: 'Clean', tags: ['Signed'], path: 'C:/Samples/setup.exe', sha: '5dac656c21ad4a02ab49649917162e70aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
      { score: 95, verdict: 'Malicious', tags: ['Stealer', 'Loader', 'C2'], path: 'C:/Samples/invoice.bin.exe', sha: '0b0d247aa1f24c2f5867b3bf29f69450bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }
    ],
    reports: [
      { id: 'RPT-0042', file: 'sample.exe', score: 72, verdict: 'Suspicious', created: '2026-05-31 16:02', type: 'HTML+JSON' },
      { id: 'RPT-0041', file: 'invoice.bin.exe', score: 95, verdict: 'Malicious', created: '2026-05-31 14:39', type: 'HTML+JSON' },
      { id: 'RPT-0040', file: 'setup.exe', score: 18, verdict: 'Clean', created: '2026-05-30 22:10', type: 'JSON' }
    ]
  };

  // ---------- pages ----------
  var pages = {
    dashboard: function () {
      var r = MOCK.latestRun, m = MOCK.metrics;
      var rows = MOCK.results.map(function (x) {
        return '<tr><td>' + riskChip(x.score) + '</td><td>' + verdictBadge(x.verdict) + '</td><td>' + tags(x.tags) +
          '</td><td class="mono">' + esc(x.path) + '</td><td class="mono">' + esc(x.sha.slice(0, 16)) + '…' +
          '</td><td><button class="iconbtn" title="Copy hash">⧉</button><button class="iconbtn" title="Open report">▤</button></td></tr>';
      }).join('');
      var cards = [['VM Seconds', m.vmsec], ['Frames', m.frames], ['Events', m.events], ['Disk Overlay', m.overlay], ['GuestAgent', m.hb], ['Network', m.net]]
        .map(function (c) { return '<div class="metric"><div class="k">' + esc(c[0]) + '</div><div class="v">' + esc(c[1]) + '</div></div>'; }).join('');
      return '<h1 class="page-title">Dashboard</h1><p class="page-sub">Latest run, analysis results, and live VM telemetry.</p>' +
        '<div class="panel"><h2>Latest Run Preview</h2><div class="preview-wrap">' +
        '<div class="screenframe">VM framebuffer preview — ' + esc(r.frame) + '</div>' +
        '<div>' + kv([['Verdict', r.verdict], ['Run ID', r.runId], ['Frame', r.frame], ['When', r.when], ['Network', r.network], ['Timeout', r.timeout + ' sec']]) +
        '<div class="actions" style="margin-top:12px"><button class="btn">Open Run Folder</button><button class="btn">Screenshots</button><button class="btn primary">Export Report</button></div></div>' +
        '</div></div>' +
        '<div class="panel"><h2>Live Run Telemetry</h2><div class="grid-cards">' + cards + '</div></div>' +
        '<div class="panel"><h2>Analysis Results</h2><table class="grid"><thead><tr><th>Score</th><th>Verdict</th><th>Tags</th><th>Path</th><th>SHA-256</th><th>Actions</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
    },
    scan: function () {
      var opts = ['Include strings', 'Extract IOCs', 'Parse PE metadata', 'Run YARA if available', 'Run capa if available', 'Generate HTML report', 'Generate JSON report'];
      return '<h1 class="page-title">Scan</h1><p class="page-sub">Static enrichment: hash, entropy, PE, strings, IOCs, YARA/capa, intel.</p>' +
        '<div class="panel"><div class="dropzone"><div class="big">Drop a file or folder here</div>to scan it statically (no execution)' +
        '<div class="actions" style="justify-content:center;margin-top:14px"><button class="btn primary" data-cmd="scan.file">Select File</button><button class="btn" data-cmd="scan.folder">Select Folder</button><button class="btn" data-cmd="scan.computer">Scan Computer</button></div></div></div>' +
        '<div class="panel"><h2>Scan Configuration</h2><div class="checks">' +
        '<label><input type="checkbox" checked disabled> Flag threshold: <span class="mono" id="scan-flag">70</span></label>' +
        opts.map(function (o, i) { return '<label><input type="checkbox" ' + (i < 5 ? 'checked' : '') + '> ' + esc(o) + '</label>'; }).join('') +
        '</div></div>' +
        '<div class="panel"><h2>Result</h2><p class="page-sub" style="margin:0">No scan yet. Pick a file to see hashes, entropy, PE info, imports, strings, IOCs, tags, and report links.</p></div>';
    },
    vm: function () {
      var steps = [['OVMF firmware', 'done'], ['bootmgfw.efi', 'done'], ['winload.efi', 'done'], ['ntoskrnl', 'done'], ['AHCI storage mount', 'done'], ['win32k / GUI stack', 'done'], ['Getting Ready (OOBE)', 'done'], ['GuestAgent heartbeat', 'cur'], ['Artifact return', 'todo']];
      var gates = [['Network disabled or isolated', true], ['Disposable overlay active', true], ['Base image not mutated', true], ['GuestAgent heartbeat required', true], ['Sample execution blocked by default', true], ['Timeout configured', true], ['Artifact return enabled', true]];
      return '<h1 class="page-title">VM Analysis</h1><p class="page-sub">In-house WHP sandbox: state, controls, boot timeline, and safety gates.</p>' +
        '<div class="row"><div class="panel" style="flex:1;min-width:280px"><h2>VM State</h2>' +
        kv([['State', 'Idle'], ['Run dir', 'C:/AntiMalRuns/<run-id>'], ['Base VHDX', 'C:/AntiMalRuns/_base/AntiMalBase.vhdx'], ['Overlay', 'disk/overlay.cow (disposable)'], ['Firmware', 'OVMF-debug.fd'], ['Timeout', '180 sec'], ['Network', 'Disabled']]) +
        '<div class="actions" style="margin-top:12px"><button class="btn">Stage Sample</button><button class="btn primary">Boot VM</button><button class="btn">Stop VM</button><button class="btn danger" disabled title="Disabled until safety gates pass">Detonate Selected</button></div></div>' +
        '<div class="panel" style="flex:1;min-width:260px"><h2>Boot Timeline</h2><ul class="timeline">' +
        steps.map(function (s) { return '<li class="' + s[1] + '"><span class="mark"></span>' + esc(s[0]) + '</li>'; }).join('') + '</ul></div></div>' +
        '<div class="panel"><h2>Safety Gates</h2>' +
        gates.map(function (g) { return '<div class="gate"><span class="' + (g[1] ? 'g' : 'b') + '">' + (g[1] ? '✓' : '✕') + '</span>' + esc(g[0]) + '</div>'; }).join('') + '</div>';
    },
    reports: function () {
      var rows = MOCK.reports.map(function (x) {
        return '<tr><td class="mono">' + esc(x.id) + '</td><td>' + esc(x.file) + '</td><td>' + riskChip(x.score) + '</td><td>' + verdictBadge(x.verdict) +
          '</td><td class="mono">' + esc(x.created) + '</td><td>' + esc(x.type) + '</td><td><button class="iconbtn" title="Open HTML">▤</button><button class="iconbtn" title="View JSON">{}</button><button class="iconbtn" title="Export">⭳</button><button class="iconbtn" title="Delete">🗑</button></td></tr>';
      }).join('');
      return '<h1 class="page-title">Reports</h1><p class="page-sub">Static and dynamic analysis reports archived on disk.</p>' +
        '<div class="panel"><table class="grid"><thead><tr><th>Report</th><th>File</th><th>Risk</th><th>Verdict</th><th>Created</th><th>Type</th><th>Actions</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
    },
    base: function () {
      var steps = ['Select Windows ISO', 'Choose workspace path', 'Create or import base VHDX', 'Validate boot files', 'Install GuestAgent', 'Confirm ready state'];
      var reqs = ['Windows x64', 'Visual Studio 2022 C++ toolchain', 'Windows SDK', 'MSBuild', 'Windows Hypervisor Platform'];
      return '<h1 class="page-title">Base Setup</h1><p class="page-sub">Build or import the clean Windows base image the sandbox boots.</p>' +
        '<div class="panel"><h2>Setup Steps</h2><ul class="timeline">' +
        steps.map(function (s, i) { return '<li class="' + (i === 0 ? 'cur' : 'todo') + '"><span class="mark"></span>' + esc((i + 1) + '. ' + s) + '</li>'; }).join('') +
        '</ul><div class="actions" style="margin-top:12px"><button class="btn primary">Build Base</button><button class="btn">Import Base</button><button class="btn">Validate</button></div></div>' +
        '<div class="panel"><h2>Requirements</h2>' + reqs.map(function (r) { return '<div class="gate"><span class="g">✓</span>' + esc(r) + '</div>'; }).join('') + '</div>';
    },
    browser: function () {
      var rows = [['chrome-download.exe', 67, 'http://file-drop.cc/x'], ['invoice.pdf.exe', 95, 'mail attachment'], ['update.bin', 41, 'http://i-like-hokku.co.ua']]
        .map(function (x) { return '<tr><td>' + esc(x[0]) + '</td><td>' + riskChip(x[1]) + '</td><td class="mono">C:/Users/…/Downloads/' + esc(x[0]) + '</td><td class="mono">' + esc(x[2]) + '</td><td><button class="iconbtn" title="Scan">⌕</button><button class="iconbtn" title="Report">▤</button></td></tr>'; }).join('');
      return '<h1 class="page-title">Browser Risk</h1><p class="page-sub">Triage suspicious downloads and submitted files.</p>' +
        '<div class="panel"><table class="grid"><thead><tr><th>File</th><th>Risk</th><th>Path</th><th>Source</th><th>Actions</th></tr></thead><tbody>' + rows + '</tbody></table></div>';
    },
    config: function () {
      return '<h1 class="page-title">Config</h1><p class="page-sub">Live settings loaded from config/antimal.toml via the host bridge.</p>' +
        '<div id="cfg-body" class="row"><div class="panel"><h2>Loading&hellip;</h2></div></div>';
    },
    safety: function () {
      var cards = [['Network', 'Disabled', 'g'], ['Execution', 'Blocked', 'g'], ['Overlay', 'Required', 'g'], ['GuestAgent', 'Required', 'g'], ['Artifact Return', 'Required', 'g'], ['Timeout', 'Enabled', 'g']]
        .map(function (c) { return '<div class="metric"><div class="k">' + esc(c[0]) + '</div><div class="v" style="color:var(--green);font-size:15px">' + esc(c[1]) + '</div></div>'; }).join('');
      var dz = ['Enable dynamic execution', 'Enable live network', 'Disable overlay discard']
        .map(function (d) { return '<label class="toggle" style="display:flex;margin:6px 0;opacity:.5"><span class="track"></span>' + esc(d) + ' <span style="color:var(--muted)">— locked until all gates pass</span></label>'; }).join('');
      return '<h1 class="page-title">Safety</h1><p class="page-sub">AntiMal is safety-first. Dangerous actions are locked by default.</p>' +
        '<div class="banner">Dynamic execution is blocked by default.</div>' +
        '<div class="panel"><h2>Status</h2><div class="grid-cards">' + cards + '</div></div>' +
        '<div class="panel danger-zone"><h2>Danger Zone</h2>' + dz + '</div>';
    }
  };

  // ---------- mounts (per-page live data over the bridge) ----------
  function loadConfig() {
    send('config.get').then(function (r) {
      var c = (r && r.ok && r.result) ? r.result : {};
      function section(t, b) { return '<div class="panel" style="flex:1;min-width:300px"><h2>' + esc(t) + '</h2>' + b + '</div>'; }
      function yn(v) { return v ? 'on' : 'off'; }
      var html = section('VM / Sandbox', kv([['Base VHDX', c.baseVhdxPath || '—'], ['Workspace', c.workspaceRoot || '—'], ['Provider', c.vmProvider || '—'], ['Network default', c.networkMode || '—'], ['VM timeout', (c.defaultTimeoutSec != null ? c.defaultTimeoutSec : '—') + ' sec'], ['Screenshot interval', (c.screenshotIntervalMs != null ? c.screenshotIntervalMs : '—') + ' ms']])) +
        section('Scanner', kv([['YARA', yn(c.enrichYara)], ['capa', yn(c.enrichCapa)], ['Detect It Easy', yn(c.enrichDie)], ['Tagger', yn(c.enrichTagger)]])) +
        section('Threat Intel', '<p class="page-sub" style="margin:0 0 8px">Network lookups <b>' + (c.intelEnabled ? 'enabled' : 'disabled by default') + '</b>.</p>' + kv([['MalwareBazaar', yn(c.intelMalwareBazaar)], ['VirusTotal key', c.virusTotalKeySet ? 'set ••••••' : 'not set']])) +
        section('General', kv([['Theme', 'Dark (security)'], ['Base disk format', c.baseDiskFormat || '—'], ['Dynamic execution', c.dynamicExecutionEnabled ? 'ENABLED' : 'blocked']]));
      var body = $('#cfg-body'); if (body) { body.innerHTML = html; }
      appendLog(r && r.ok ? 'INFO' : 'ERROR', r && r.ok ? 'Config loaded from host.' : 'Config load failed.');
    });
  }
  var mounts = { config: loadConfig };

  // ---------- router ----------
  function route(page) {
    if (!pages[page]) page = 'dashboard';
    $('#content').innerHTML = pages[page]();
    $all('#nav a').forEach(function (a) { a.classList.toggle('active', a.dataset.page === page); });
    wireContentActions();
    if (mounts[page]) { mounts[page](); }
  }
  function wireContentActions() {
    $all('#content [data-cmd]').forEach(function (b) {
      b.onclick = function () { onAction(b.dataset.cmd); };
    });
  }
  function onAction(cmd) {
    var label = { 'scan.file': 'Scan File', 'scan.folder': 'Scan Folder', 'scan.computer': 'Scan Computer', 'detonate.selected': 'Detonate Selected' }[cmd] || cmd;
    appendLog(cmd === 'detonate.selected' ? 'WARN' : 'INFO', label + ' requested — backend wiring lands in P3.');
  }

  // ---------- init ----------
  function init() {
    logEl = $('#log');
    $all('#nav a').forEach(function (a) { a.onclick = function () { route(a.dataset.page); }; });
    $all('.topbar [data-cmd]').forEach(function (b) { b.onclick = function () { onAction(b.dataset.cmd); }; });
    $all('#network button').forEach(function (b) {
      b.onclick = function () {
        $all('#network button').forEach(function (x) { x.classList.remove('on', 'live'); });
        b.classList.add('on'); if (b.dataset.net === 'live') b.classList.add('live');
        appendLog(b.dataset.net === 'live' ? 'WARN' : 'SAFE', 'Network mode: ' + b.dataset.net + '.');
      };
    });
    var at = $('#autodet'); at.onclick = function () { at.classList.toggle('on'); appendLog('WARN', 'Auto-detonate flagged: ' + (at.classList.contains('on') ? 'ON' : 'OFF') + '.'); };
    $all('.logtools .f').forEach(function (f) {
      f.onclick = function () { $all('.logtools .f').forEach(function (x) { x.classList.remove('on'); }); f.classList.add('on'); logFilter = f.dataset.filter; refilterLog(); };
    });
    $('#logsearch').oninput = function (e) { logQuery = e.target.value.toLowerCase(); refilterLog(); };

    route('dashboard');

    // seed log + prove the bridge
    appendLog('INFO', 'AntiMal UI ready.');
    appendLog('INFO', 'Use Base Setup to build/import a clean VHDX.');
    appendLog('SAFE', 'Network disabled.');
    appendLog('SAFE', 'Sample execution blocked by safety gate.');
    send('ping', {}).then(function (r) {
      if (r && r.ok && r.result) {
        appendLog('INFO', 'Host bridge online (host v' + String(r.result.version || '?') + ').');
        $('#vm-badge').className = 'badge idle';
      } else {
        appendLog('ERROR', 'Host bridge not responding: ' + String((r && r.error) || 'unknown'));
      }
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}());
