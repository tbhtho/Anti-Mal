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
  var state = { scans: [] };
  var currentPage = 'dashboard';
  var livePollTimer = null;
  var liveWatchRun = null; // run id whose live telemetry tail is already started
  var liveMouse = { btn: 0, dx: 0, dy: 0 }; // accumulated relative mouse state
  var liveMouseTimer = null;                // flushes accumulated movement
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
      if (m.evt === 'scan.result' && m.data) onScanResult(m.data);
      if (m.evt === 'scan.progress' && m.data) onScanProgress(m.data);
      if (m.evt === 'reports.data' && m.data) onReportsData(m.data);
      if (m.evt === 'dashboard.data' && m.data) onDashboardData(m.data);
      if (m.evt === 'browser.data' && m.data) onBrowserData(m.data);
      if (m.evt === 'run.status' && m.data) onRunStatus(m.data);
      if (m.evt === 'telemetry' && m.data) onTelemetry(m.data);
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

  // (Mock data fully retired in P4 — every page now renders live bridge data.)

  // ---------- pages ----------
  var pages = {
    dashboard: function () {
      return '<h1 class="page-title">Dashboard</h1><p class="page-sub">Latest run, live telemetry, event feed, and analysis results.</p>' +
        '<div class="panel"><h2>Latest Run Preview</h2><div class="preview-wrap">' +
        '<div class="screenframe" id="dash-frame">No run yet — build a base image and detonate a sample to populate this.</div>' +
        '<div id="dash-run"><p class="page-sub" style="margin:0">Loading latest run…</p></div>' +
        '</div></div>' +
        '<div class="panel"><h2>Live Run Telemetry</h2><div class="grid-cards" id="dash-metrics"><div class="page-sub">Loading…</div></div></div>' +
        '<div class="panel"><h2>Event Feed</h2><div id="dash-events"><p class="page-sub" style="margin:0">Loading events…</p></div></div>' +
        '<div class="panel"><h2>Analysis Results (this session)</h2><div id="dash-results"></div></div>';
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
        '<div class="panel"><h2>Result</h2><div id="scan-results"></div></div>';
    },
    vm: function () {
      var steps = [['OVMF firmware', 'done'], ['bootmgfw.efi', 'done'], ['winload.efi', 'done'], ['ntoskrnl', 'done'], ['AHCI storage mount', 'done'], ['win32k / GUI stack', 'done'], ['Getting Ready (OOBE)', 'done'], ['GuestAgent heartbeat', 'cur'], ['Artifact return', 'todo']];
      return '<h1 class="page-title">VM Analysis</h1><p class="page-sub">In-house WHP sandbox: live view, state, boot timeline, and safety gates.</p>' +
        '<div class="panel"><h2>Live VM <span id="vm-live-status" class="page-sub" style="font-weight:400"></span></h2>' +
        '<div class="actions"><button class="btn primary" id="vm-boot-btn">Boot VM (live)</button><button class="btn danger" id="vm-detonate-btn">Detonate Sample (live)</button><button class="btn" id="vm-stop-btn">Stop</button></div>' +
        '<div class="screenframe" id="live-frame" style="margin-top:12px">Click “Boot VM (live)” for a clean session, or “Detonate Sample (live)” to run a BENIGN sample inside it — watch it execute here.</div></div>' +
        '<div class="panel"><h2>Live Process Telemetry <span id="vm-telemetry-status" class="page-sub" style="font-weight:400"></span></h2>' +
        '<div id="vm-events"><p class="page-sub" style="margin:0">No events yet — boot the VM to stream live process activity from the GuestAgent over COM2.</p></div></div>' +
        '<div class="row"><div class="panel" style="flex:1;min-width:280px"><h2>VM State</h2>' +
        '<div id="vm-state"><p class="page-sub" style="margin:0">Loading…</p></div>' +
        '<p class="page-sub" style="margin:8px 0 0">“Boot VM (live)” starts a clean interactive session; “Detonate Sample (live)” runs a chosen BENIGN sample inside it and streams its process / registry / file / network behavior below.</p></div>' +
        '<div class="panel" style="flex:1;min-width:260px"><h2>Boot Timeline</h2><ul class="timeline">' +
        steps.map(function (s) { return '<li class="' + s[1] + '"><span class="mark"></span>' + esc(s[0]) + '</li>'; }).join('') + '</ul></div></div>' +
        '<div class="panel"><h2>Safety Gates</h2><div id="vm-gates"><p class="page-sub" style="margin:0">Loading…</p></div></div>';
    },
    reports: function () {
      return '<h1 class="page-title">Reports</h1><p class="page-sub">Static and dynamic analysis reports archived under the workspace.</p>' +
        '<div class="panel"><table class="grid"><thead><tr><th>Run</th><th>File</th><th>Risk</th><th>Verdict</th><th>Created</th><th>Type</th><th>Actions</th></tr></thead><tbody id="reports-rows"><tr><td colspan="7" class="page-sub" style="padding:14px">Loading&hellip;</td></tr></tbody></table></div>';
    },
    base: function () {
      var steps = ['Select Windows ISO', 'Choose workspace path', 'Create or import base VHDX', 'Validate boot files', 'Install GuestAgent', 'Confirm ready state'];
      var reqs = ['Windows x64', 'Visual Studio 2022 C++ toolchain', 'Windows SDK', 'MSBuild', 'Windows Hypervisor Platform'];
      return '<h1 class="page-title">Base Setup</h1><p class="page-sub">Build or import the clean Windows base image the sandbox boots.</p>' +
        '<div class="panel"><h2>Base Image Status</h2><div id="base-status"><p class="page-sub" style="margin:0">Checking…</p></div></div>' +
        '<div class="panel"><h2>Setup Steps</h2><ul class="timeline">' +
        steps.map(function (s, i) { return '<li class="' + (i === 0 ? 'cur' : 'todo') + '"><span class="mark"></span>' + esc((i + 1) + '. ' + s) + '</li>'; }).join('') +
        '</ul><p class="page-sub" style="margin:8px 0 0">Build or import the base image from the command line — see <span class="mono">tools\\New-AntiMalVmBase.ps1</span> (README → Base Image).</p></div>' +
        '<div class="panel"><h2>Requirements</h2>' + reqs.map(function (r) { return '<div class="gate"><span class="g">✓</span>' + esc(r) + '</div>'; }).join('') + '</div>';
    },
    browser: function () {
      return '<h1 class="page-title">Browser Risk</h1><p class="page-sub">Saved browser sites and credentials potentially exposed by the latest run’s network activity. Decrypting stored secrets is a separate, gated action — never run automatically.</p>' +
        '<div class="panel"><h2>Impact Assessment</h2><div id="browser-body"><p class="page-sub" style="margin:0">Loading…</p></div></div>';
    },
    config: function () {
      return '<h1 class="page-title">Config</h1><p class="page-sub">Live settings loaded from config/antimal.toml via the host bridge.</p>' +
        '<div id="cfg-body" class="row"><div class="panel"><h2>Loading&hellip;</h2></div></div>';
    },
    safety: function () {
      var dz = ['Enable dynamic execution', 'Enable live network', 'Disable overlay discard']
        .map(function (d) { return '<label class="toggle" style="display:flex;margin:6px 0;opacity:.5"><span class="track"></span>' + esc(d) + ' <span style="color:var(--muted)">— locked until all gates pass</span></label>'; }).join('');
      return '<h1 class="page-title">Safety</h1><p class="page-sub">AntiMal is safety-first. Dangerous actions are locked by default.</p>' +
        '<div class="banner" id="safety-banner">Dynamic execution is blocked by default.</div>' +
        '<div class="panel"><h2>Status</h2><div class="grid-cards" id="safety-cards"><div class="page-sub">Loading…</div></div></div>' +
        '<div class="panel danger-zone"><h2>Danger Zone</h2>' + dz + '</div>';
    }
  };

  // ---------- scan results (P3 live data over the bridge) ----------
  function n(a) { return (a && a.length) || 0; }
  function shortPath(p) { p = String(p || ''); var i = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\')); return i >= 0 ? p.slice(i + 1) : p; }
  function scanRow(x) {
    var sha = String(x.sha256 || '');
    var tagNames = (x.tags || []).map(function (tg) { return tg && tg.tag; }).filter(Boolean);
    return '<tr><td>' + riskChip(x.score | 0) + '</td><td>' + verdictBadge(x.verdict || '?') +
      '</td><td>' + tags(tagNames) + '</td><td class="mono">' + esc(x.path || '') +
      '</td><td class="mono">' + esc(sha.slice(0, 16)) + (sha ? '…' : '') + '</td></tr>';
  }
  function renderScans() {
    var box = $('#scan-results'); if (!box) return;
    if (!state.scans.length) {
      box.innerHTML = '<p class="page-sub" style="margin:0">No scan yet. Pick a file to see hashes, entropy, PE info, imports, strings, IOCs, tags, and report links.</p>';
      return;
    }
    var rows = state.scans.map(scanRow).join('');
    var last = state.scans[state.scans.length - 1];
    var io = last.iocs || {};
    var detail = kv([
      ['Path', last.path || '—'], ['SHA-256', last.sha256 || '—'],
      ['Entropy', last.entropy != null ? Number(last.entropy).toFixed(3) : '—'],
      ['PE file', last.isPe ? 'yes' : 'no'], ['Authenticode signed', last.authenticodeSigned ? 'yes' : 'no'],
      ['Imports', n(last.imports)], ['Score', last.score | 0], ['Verdict', last.verdict || '—'],
      ['URLs', n(io.urls)], ['IPs', n(io.ips)], ['Domains', n(io.domains)],
      ['Registry paths', n(io.registryPaths)], ['Mutex hints', n(io.mutexHints)], ['Suspicious APIs', n(io.suspiciousApis)],
      ['YARA matches', n(last.yaraMatches)], ['capa capabilities', n(last.capaCapabilities)],
      ['DIE detections', n(last.dieDetections)], ['Intel hits', n(last.intelHits)]
    ]);
    box.innerHTML = '<table class="grid"><thead><tr><th>Score</th><th>Verdict</th><th>Tags</th><th>Path</th><th>SHA-256</th></tr></thead><tbody>' + rows + '</tbody></table>' +
      '<h2 style="margin:16px 0 8px">Latest Result Detail</h2>' + detail;
  }
  function onScanResult(d) {
    state.scans.push(d);
    appendLog((d.score | 0) >= 70 ? 'WARN' : 'INFO',
      'Scan: ' + String(d.verdict || '?') + ' (' + (d.score | 0) + ') ' + shortPath(d.path));
    if (currentPage === 'scan') renderScans();
  }
  function onScanProgress(d) {
    if (d && d.stage === 'done') appendLog('INFO', 'Scan complete (' + (d.count != null ? d.count : '?') + ' file(s)).');
  }

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
  function loadReports() {
    var body = $('#reports-rows');
    if (body) body.innerHTML = '<tr><td colspan="7" class="page-sub" style="padding:14px">Loading…</td></tr>';
    send('reports.list').then(function (r) {
      // The rows arrive asynchronously via a reports.data event; this reply
      // only confirms the worker started (or surfaces a dispatch failure).
      if ((!r || !r.ok) && body) {
        body.innerHTML = '<tr><td colspan="7" class="page-sub" style="padding:14px">Reports failed to load.</td></tr>';
        appendLog('ERROR', 'Reports load failed: ' + String((r && r.error) || 'unknown'));
      }
    });
  }
  function onReportsData(d) {
    var body = $('#reports-rows'); if (!body) return;
    var list = (d && d.reports) || [];
    if (!list.length) {
      body.innerHTML = '<tr><td colspan="7" class="page-sub" style="padding:14px">No reports yet. Scan or detonate a sample to generate one.</td></tr>';
      appendLog('INFO', 'No reports found in workspace.');
      return;
    }
    body.innerHTML = list.map(function (x) {
      return '<tr><td class="mono">' + esc(String(x.id || '').slice(0, 8)) + '</td><td>' + esc(x.file || '—') + '</td><td>' + riskChip(x.score | 0) + '</td><td>' + verdictBadge(x.verdict || '?') +
        '</td><td class="mono">' + esc(x.created || '—') + '</td><td>' + esc(x.type || '—') + '</td><td><button class="iconbtn" title="Open run folder" data-open="' + esc(x.runDir || '') + '">▤</button></td></tr>';
    }).join('');
    $all('#reports-rows [data-open]').forEach(function (b) {
      b.onclick = function () {
        var p = b.getAttribute('data-open'); if (!p) return;
        send('run.open', { runDir: p }).then(function (rr) {
          var ok = rr && rr.ok;
          appendLog(ok ? 'INFO' : 'ERROR', ok ? 'Opened run folder.' : 'Open failed: ' + String((rr && rr.error) || 'unknown'));
        });
      };
    });
    var total = (d && d.total != null) ? d.total : list.length;
    appendLog('INFO', 'Loaded ' + list.length + ' of ' + total + ' report(s).');
  }
  function renderDashResults() {
    var box = $('#dash-results'); if (!box) return;
    if (!state.scans.length) { box.innerHTML = '<p class="page-sub" style="margin:0">No scans this session. Use Scan File to analyze a sample.</p>'; return; }
    box.innerHTML = '<table class="grid"><thead><tr><th>Score</th><th>Verdict</th><th>Tags</th><th>Path</th><th>SHA-256</th></tr></thead><tbody>' + state.scans.map(scanRow).join('') + '</tbody></table>';
  }
  function renderEventFeed(events) {
    var box = $('#dash-events'); if (!box) return;
    if (!events || !events.length) { box.innerHTML = '<p class="page-sub" style="margin:0">No events recorded for this run.</p>'; return; }
    var rows = events.slice().reverse().map(function (e) {
      var when = String(e.time || '').replace('T', ' ').replace('Z', '');
      var mit = e.mitre ? '<span class="tag">' + esc(e.mitre) + '</span>' : '';
      return '<tr><td class="mono">' + esc(when) + '</td><td><span class="tag">' + esc(e.category || '?') + '</span></td><td>' + esc(e.action || '') +
        '</td><td class="mono">' + esc(e.pid | 0) + '</td><td class="mono">' + esc(shortPath(e.image)) + '</td><td class="mono">' + esc(e.target || '') + '</td><td>' + mit + '</td></tr>';
    }).join('');
    box.innerHTML = '<table class="grid"><thead><tr><th>Time</th><th>Category</th><th>Action</th><th>PID</th><th>Image</th><th>Target</th><th>MITRE</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }
  function onDashboardData(d) {
    if (!d || !d.hasRun) {
      var fr0 = $('#dash-frame'); if (fr0) fr0.textContent = 'No run yet — build a base image and detonate a sample to populate this.';
      var run0 = $('#dash-run'); if (run0) run0.innerHTML = '<p class="page-sub" style="margin:0">No runs found in the workspace.</p>';
      var mt0 = $('#dash-metrics'); if (mt0) mt0.innerHTML = '<div class="page-sub">No runs yet.</div>';
      var ev0 = $('#dash-events'); if (ev0) ev0.innerHTML = '<p class="page-sub" style="margin:0">No events yet.</p>';
      appendLog('INFO', 'Dashboard: no runs in workspace yet.');
      return;
    }
    var lr = d.latestRun || {};
    var fr = $('#dash-frame');
    if (fr) {
      if (lr.frame) { fr.innerHTML = ''; var img = document.createElement('img'); img.alt = 'VM framebuffer'; img.src = lr.frame; fr.appendChild(img); }
      else { fr.textContent = 'Run has no screenshots.'; }
    }
    var run = $('#dash-run');
    if (run) {
      run.innerHTML = kv([['Verdict', lr.verdict || '—'], ['Scanner', (lr.scannerVerdict || '—') + ' (' + (lr.score | 0) + ')'], ['Run ID', lr.runId || '—'], ['When', lr.when || '—']]) +
        '<div class="actions" style="margin-top:12px"><button class="btn" data-open-run="' + esc(lr.runDir || '') + '">Open Run Folder</button><button class="btn primary" data-watch-run="' + esc(lr.runDir || '') + '">Watch Live Telemetry</button></div>';
      var ob = run.querySelector('[data-open-run]');
      if (ob) ob.onclick = function () { var p = ob.getAttribute('data-open-run'); if (!p) return; send('run.open', { runDir: p }).then(function (rr) { appendLog(rr && rr.ok ? 'INFO' : 'ERROR', rr && rr.ok ? 'Opened run folder.' : 'Open failed.'); }); };
      var wb = run.querySelector('[data-watch-run]');
      if (wb) wb.onclick = function () { var p = wb.getAttribute('data-watch-run'); appendLog('INFO', 'Live telemetry tail requested.'); send('run.watch', p ? { runDir: p } : {}); };
    }
    var m = d.metrics || {};
    var cards = [['Events', m.events | 0], ['Frames', m.frames | 0], ['Network Domains', m.domains | 0], ['Artifacts', m.artifacts | 0], ['MITRE', m.mitre | 0], ['Errors', m.errors | 0]];
    var mt = $('#dash-metrics');
    if (mt) mt.innerHTML = cards.map(function (c) { return '<div class="metric"><div class="k">' + esc(c[0]) + '</div><div class="v">' + esc(c[1]) + '</div></div>'; }).join('');
    renderEventFeed(d.events || []);
    appendLog('INFO', 'Dashboard loaded run ' + String(lr.runId || '').slice(0, 8) + ' (' + (m.events | 0) + ' events).');
  }
  // P5 live telemetry: a run.watch worker streams journal events here.
  function onTelemetry(d) {
    if (!d) return;
    var cat = String(d.category || '?'), act = String(d.action || ''), tgt = String(d.target || '');
    appendLog('INFO', 'EVT ' + cat + (act ? ' · ' + act : '') + (tgt ? ' · ' + shortPath(tgt) : ''));
    // Prefer the VM page's live panel; fall back to the dashboard feed.
    var box = $('#vm-events') || $('#dash-events'); if (!box) return;
    var tbody = box.querySelector('tbody');
    if (!tbody) {
      box.innerHTML = '<table class="grid"><thead><tr><th>Time</th><th>Category</th><th>Action</th><th>PID</th><th>Image</th><th>Target</th><th>MITRE</th></tr></thead><tbody></tbody></table>';
      tbody = box.querySelector('tbody');
    }
    var when = String(d.time || '').replace('T', ' ').replace('Z', '');
    var tr = document.createElement('tr');
    tr.innerHTML = '<td class="mono">' + esc(when) + '</td><td><span class="tag">' + esc(cat) + '</span></td><td>' + esc(act) +
      '</td><td class="mono">' + esc(d.pid | 0) + '</td><td class="mono">' + esc(shortPath(d.image)) + '</td><td class="mono">' + esc(tgt) +
      '</td><td>' + (d.mitre ? '<span class="tag">' + esc(d.mitre) + '</span>' : '') + '</td>';
    tbody.insertBefore(tr, tbody.firstChild);
  }
  function onRunStatus(d) {
    if (!d) return;
    var s = String(d.state || '');
    var ts = $('#vm-telemetry-status');
    if (s === 'watching') { appendLog('SAFE', 'Live telemetry: watching journal for events…'); if (ts) ts.textContent = '· watching'; }
    else if (s === 'done') { appendLog('INFO', 'Live telemetry ended (' + (d.streamed | 0) + ' events streamed).'); if (ts) ts.textContent = '· ended (' + (d.streamed | 0) + ' events)'; }
    else if (s === 'no-run') { appendLog('WARN', 'Live telemetry: no run available to watch.'); if (ts) ts.textContent = '· no run'; }
  }
  function loadDashboard() {
    renderDashResults();
    send('dashboard.get').then(function (r) {
      if (!r || !r.ok) appendLog('ERROR', 'Dashboard load failed: ' + String((r && r.error) || 'unknown'));
    });
  }
  // Map a keydown event to Set-1 make/break scancodes (with LShift wrapping for
  // uppercase + shifted symbols) for live host->guest keyboard input.
  function keyToScancodes(e) {
    var key = e.key;
    var L = { a: 0x1E, b: 0x30, c: 0x2E, d: 0x20, e: 0x12, f: 0x21, g: 0x22, h: 0x23, i: 0x17, j: 0x24, k: 0x25, l: 0x26, m: 0x32, n: 0x31, o: 0x18, p: 0x19, q: 0x10, r: 0x13, s: 0x1F, t: 0x14, u: 0x16, v: 0x2F, w: 0x11, x: 0x2D, y: 0x15, z: 0x2C };
    var D = { '1': 0x02, '2': 0x03, '3': 0x04, '4': 0x05, '5': 0x06, '6': 0x07, '7': 0x08, '8': 0x09, '9': 0x0A, '0': 0x0B };
    var SYM = { '-': 0x0C, '=': 0x0D, '[': 0x1A, ']': 0x1B, ';': 0x27, "'": 0x28, '`': 0x29, '\\': 0x2B, ',': 0x33, '.': 0x34, '/': 0x35 };
    var SH = { '!': 0x02, '@': 0x03, '#': 0x04, '$': 0x05, '%': 0x06, '^': 0x07, '&': 0x08, '*': 0x09, '(': 0x0A, ')': 0x0B, '_': 0x0C, '+': 0x0D, '{': 0x1A, '}': 0x1B, ':': 0x27, '"': 0x28, '~': 0x29, '|': 0x2B, '<': 0x33, '>': 0x34, '?': 0x35 };
    var SPECIAL = { Enter: 0x1C, Backspace: 0x0E, Tab: 0x0F, Escape: 0x01, ' ': 0x39 };
    var code = null, shift = false;
    if (key && key.length === 1) {
      var lc = key.toLowerCase();
      if (L[lc] != null) { code = L[lc]; shift = (key !== lc); }
      else if (D[key] != null) { code = D[key]; }
      else if (SYM[key] != null) { code = SYM[key]; }
      else if (SH[key] != null) { code = SH[key]; shift = true; }
    } else if (SPECIAL[key] != null) { code = SPECIAL[key]; }
    if (code == null) return null;
    var out = [];
    if (shift) out.push(0x2A);
    out.push(code); out.push(code | 0x80);
    if (shift) out.push(0xAA);
    return out;
  }
  function stopLivePoll() {
    if (livePollTimer) { clearInterval(livePollTimer); livePollTimer = null; }
    if (liveMouseTimer) { clearInterval(liveMouseTimer); liveMouseTimer = null; }
    liveMouse = { btn: 0, dx: 0, dy: 0 };
  }
  // Flush accumulated relative mouse movement to the guest (~20/s). PS/2 mouse
  // Y is positive-up, screen Y is positive-down -> negate dy.
  function flushLiveMouse() {
    if (!livePollTimer) return;
    if (Math.abs(liveMouse.dx) >= 1 || Math.abs(liveMouse.dy) >= 1) {
      var dx = Math.round(liveMouse.dx), dy = Math.round(liveMouse.dy);
      liveMouse.dx = 0; liveMouse.dy = 0;
      send('vm.input', { mouse: { buttons: liveMouse.btn, dx: dx, dy: -dy } });
    }
  }
  function startLivePoll() {
    stopLivePoll();
    liveWatchRun = null; // each boot re-tails the new run's journal
    liveMouseTimer = setInterval(flushLiveMouse, 50);
    livePollTimer = setInterval(function () {
      var box = $('#live-frame');
      if (!box) { stopLivePoll(); return; } // navigated away from VM page
      send('vm.frame').then(function (r) {
        var res = (r && r.result) || {};
        // Once the live run dir is known, start its telemetry tail exactly once
        // (live mode keeps tailing through the quiet boot until the VM exits).
        var run = res.run;
        if (run && run !== liveWatchRun) {
          liveWatchRun = run;
          appendLog('INFO', 'Live telemetry tail starting for ' + run + '…');
          var ts = $('#vm-telemetry-status'); if (ts) ts.textContent = '· tailing ' + run;
          send('run.watch', { runDir: run, live: true });
        }
        var f = res.frame || '';
        if (!f) return;
        var img = document.getElementById('live-frame-img');
        if (!img) { box.innerHTML = ''; img = document.createElement('img'); img.id = 'live-frame-img'; box.appendChild(img); }
        img.src = f;
      });
    }, 1500);
  }
  function loadVm() {
    var bb = $('#vm-boot-btn');
    if (bb) bb.onclick = function () {
      appendLog('INFO', 'Booting live VM…');
      var s = $('#vm-live-status'); if (s) s.textContent = '· starting…';
      send('vm.boot').then(function (r) {
        var ok = r && r.ok && r.result && r.result.started;
        appendLog(ok ? 'INFO' : 'ERROR', ok ? ('Live VM booting' + (r.result.seeded ? ' from snapshot' : ' (full OOBE)') + '…') : 'VM boot failed: ' + String((r && r.result && r.result.error) || 'unknown'));
        if (ok && s) s.textContent = r.result.seeded ? '· booting from snapshot' : '· booting (full OOBE)';
        if (ok) startLivePoll();
      });
    };
    var db = $('#vm-detonate-btn');
    if (db) db.onclick = function () { onAction('detonate.selected'); };
    var sb = $('#vm-stop-btn');
    if (sb) sb.onclick = function () { send('vm.stop'); stopLivePoll(); liveWatchRun = null; appendLog('WARN', 'Live VM stopped.'); var box = $('#live-frame'); if (box) box.textContent = 'Stopped.'; var s = $('#vm-live-status'); if (s) s.textContent = '· stopped'; var ts = $('#vm-telemetry-status'); if (ts) ts.textContent = '· stopped'; var mb = $('#mode-badge'); if (mb) { mb.className = 'badge idle'; mb.innerHTML = '<span class="dot"></span>Sandbox Ready'; } };
    // Live mouse: route movement/clicks over the frame into the guest (relative
    // PS/2 mouse). Movement deltas are scaled from displayed px to guest px and
    // accumulated; flushLiveMouse sends them ~20/s. Buttons go immediately.
    var lf = $('#live-frame');
    if (lf) {
      function frameScale() {
        var img = document.getElementById('live-frame-img');
        if (img && img.clientWidth > 0 && img.naturalWidth > 0) {
          return { x: img.naturalWidth / img.clientWidth, y: img.naturalHeight / Math.max(1, img.clientHeight) };
        }
        return { x: 1, y: 1 };
      }
      function btnBit(b) { return b === 2 ? 0x02 : (b === 1 ? 0x04 : 0x01); }
      lf.addEventListener('mousemove', function (e) {
        if (!livePollTimer) return;
        var s = frameScale();
        liveMouse.dx += (e.movementX || 0) * s.x;
        liveMouse.dy += (e.movementY || 0) * s.y;
      });
      lf.addEventListener('mousedown', function (e) {
        if (!livePollTimer) return;
        e.preventDefault();
        liveMouse.btn |= btnBit(e.button);
        send('vm.input', { mouse: { buttons: liveMouse.btn, dx: 0, dy: 0 } });
      });
      lf.addEventListener('mouseup', function (e) {
        if (!livePollTimer) return;
        e.preventDefault();
        liveMouse.btn &= ~btnBit(e.button);
        send('vm.input', { mouse: { buttons: liveMouse.btn, dx: 0, dy: 0 } });
      });
      lf.addEventListener('contextmenu', function (e) { e.preventDefault(); });
    }
    send('config.get').then(function (r) {
      var c = (r && r.ok && r.result) ? r.result : {};
      var net = c.networkMode || 'disabled';
      var dyn = !!c.dynamicExecutionEnabled;
      var to = (c.defaultTimeoutSec != null ? c.defaultTimeoutSec : '—');
      var st = $('#vm-state');
      if (st) st.innerHTML = kv([['State', 'Idle'], ['Base VHDX', c.baseVhdxPath || '—'], ['Workspace', c.workspaceRoot || '—'], ['Provider', c.vmProvider || '—'], ['Overlay', 'disposable (per run)'], ['Firmware', 'OVMF (debug)'], ['Timeout', to + ' sec'], ['Network', net]]);
      var gates = [
        ['Network ' + net + (net === 'disabled' ? '' : ' (review)'), net === 'disabled'],
        ['Disposable overlay active', true],
        ['Base image not mutated', true],
        ['GuestAgent heartbeat required', true],
        ['Sample execution ' + (dyn ? 'ENABLED' : 'blocked by default'), !dyn],
        ['Timeout configured (' + to + 's)', (c.defaultTimeoutSec | 0) > 0],
        ['Artifact return enabled', true]
      ];
      var g = $('#vm-gates');
      if (g) g.innerHTML = gates.map(function (gg) { return '<div class="gate"><span class="' + (gg[1] ? 'g' : 'b') + '">' + (gg[1] ? '✓' : '✕') + '</span>' + esc(gg[0]) + '</div>'; }).join('');
    });
  }
  function loadSafety() {
    send('config.get').then(function (r) {
      var c = (r && r.ok && r.result) ? r.result : {};
      var net = c.networkMode || 'disabled';
      var dyn = !!c.dynamicExecutionEnabled;
      var cards = [
        ['Network', net, net === 'disabled' ? 'g' : 'b'],
        ['Execution', dyn ? 'Enabled' : 'Blocked', dyn ? 'b' : 'g'],
        ['Overlay', 'Required', 'g'],
        ['GuestAgent', 'Required', 'g'],
        ['Artifact Return', 'Required', 'g'],
        ['Timeout', (c.defaultTimeoutSec != null ? c.defaultTimeoutSec : '—') + ' sec', 'g']
      ];
      var box = $('#safety-cards');
      if (box) box.innerHTML = cards.map(function (cc) {
        var color = cc[2] === 'g' ? 'var(--green)' : 'var(--red)';
        return '<div class="metric"><div class="k">' + esc(cc[0]) + '</div><div class="v" style="color:' + color + ';font-size:15px">' + esc(cc[1]) + '</div></div>';
      }).join('');
      var banner = $('#safety-banner');
      if (banner) banner.textContent = dyn ? 'WARNING: dynamic execution is ENABLED — detonations will run live samples.' : 'Dynamic execution is blocked by default.';
    });
  }
  function loadBrowser() {
    var box = $('#browser-body'); if (box) box.innerHTML = '<p class="page-sub" style="margin:0">Analyzing latest run…</p>';
    send('browser.get').then(function (r) {
      if ((!r || !r.ok) && box) { box.innerHTML = '<p class="page-sub" style="margin:0">Browser analysis failed.</p>'; appendLog('ERROR', 'Browser analysis failed: ' + String((r && r.error) || 'unknown')); }
    });
  }
  function onBrowserData(d) {
    var box = $('#browser-body'); if (!box) return;
    var risks = (d && d.risks) || [];
    var domains = (d && d.domains) | 0;
    if (!risks.length) {
      box.innerHTML = '<p class="page-sub" style="margin:0">No browser-credential exposure detected. The latest run contacted ' + domains + ' domain(s).</p>';
      appendLog('INFO', 'Browser risk: clean (' + domains + ' domains contacted).');
      return;
    }
    var rows = risks.map(function (x) {
      var flags = [];
      if (x.contactedBySample) flags.push('contacted');
      if (x.savedCredentials) flags.push('saved creds');
      if (x.cookiesPresent) flags.push('cookies');
      return '<tr><td>' + esc(x.site || x.domain || '—') + '</td><td class="mono">' + esc(x.domain || '—') + '</td><td>' + tags(flags) + '</td><td>' + esc(x.recommendation || '') + '</td></tr>';
    }).join('');
    box.innerHTML = '<table class="grid"><thead><tr><th>Site</th><th>Domain</th><th>Signals</th><th>Recommendation</th></tr></thead><tbody>' + rows + '</tbody></table>';
    appendLog('WARN', risks.length + ' site(s) flagged for browser-credential risk.');
  }
  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n <= 0) return '0 B';
    var u = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), u.length - 1);
    return (n / Math.pow(1024, i)).toFixed(i ? 1 : 0) + ' ' + u[i];
  }
  function loadBase() {
    send('config.get').then(function (r) {
      var c = (r && r.ok && r.result) ? r.result : {};
      var box = $('#base-status'); if (!box) return;
      var exists = !!c.baseExists;
      var color = exists ? 'var(--green)' : 'var(--amber, #d9a441)';
      box.innerHTML = '<div class="grid-cards">' +
        '<div class="metric"><div class="k">Base Image</div><div class="v" style="color:' + color + ';font-size:15px">' + (exists ? 'Ready' : 'Not built') + '</div></div>' +
        '<div class="metric"><div class="k">Size</div><div class="v">' + esc(exists ? fmtBytes(c.baseSizeBytes) : '—') + '</div></div>' +
        '<div class="metric"><div class="k">Format</div><div class="v">' + esc(c.baseDiskFormat || '—') + '</div></div>' +
        '</div>' + kv([['Path', c.baseVhdxPath || '—']]);
      appendLog(exists ? 'INFO' : 'WARN', exists ? 'Base image ready (' + fmtBytes(c.baseSizeBytes) + ').' : 'Base image not built yet.');
    });
  }
  var mounts = { dashboard: loadDashboard, vm: loadVm, base: loadBase, config: loadConfig, scan: renderScans, reports: loadReports, browser: loadBrowser, safety: loadSafety };

  // ---------- router ----------
  function route(page) {
    if (!pages[page]) page = 'dashboard';
    currentPage = page;
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
    var labels = { 'scan.file': 'Scan File', 'scan.folder': 'Scan Folder', 'scan.computer': 'Scan Computer', 'detonate.selected': 'Detonate Selected' };
    var label = labels[cmd] || cmd;
    if (cmd === 'scan.file' || cmd === 'scan.folder' || cmd === 'scan.computer') {
      appendLog('INFO', label + ' — choose a target…');
      send(cmd).then(function (r) {
        if (!r || !r.ok) { appendLog('ERROR', label + ' failed: ' + String((r && r.error) || 'unknown')); return; }
        var res = r.result || {};
        if (res.cancelled) { appendLog('INFO', label + ' cancelled.'); return; }
        appendLog('INFO', label + ' started.');
        if (currentPage !== 'scan') route('scan');
      });
      return;
    }
    if (cmd === 'detonate.selected') {
      appendLog('WARN', 'Detonate — pick a BENIGN sample to execute live in the VM…');
      send('vm.detonate').then(function (r) {
        var res = (r && r.result) || {};
        if (res.cancelled) { appendLog('INFO', 'Detonate cancelled.'); return; }
        if (!res.started) { appendLog('ERROR', 'Detonate failed: ' + String(res.error || 'unknown')); return; }
        appendLog('WARN', 'Detonating ' + (res.sample || 'sample') + ' live' + (res.seeded ? ' (seed-boot)' : ' (cold boot)') + ' — watch it run on VM Analysis.');
        var mb = $('#mode-badge'); if (mb) { mb.className = 'badge blocked'; mb.innerHTML = '<span class="dot"></span>Detonating'; }
        if (currentPage !== 'vm') route('vm');
        // The VM page just mounted; start streaming the framebuffer + telemetry.
        setTimeout(function () {
          startLivePoll();
          var s = $('#vm-live-status'); if (s) s.textContent = '· detonating ' + (res.sample || '');
        }, 80);
      });
      return;
    }
    appendLog('INFO', label + ' requested.');
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
    var at = $('#autodet'); if (at) at.onclick = function () { appendLog('INFO', 'Auto-detonate is not wired — detonation is gated off (boots run a GuestAgent healthcheck only).'); };
    $all('.logtools .f').forEach(function (f) {
      f.onclick = function () { $all('.logtools .f').forEach(function (x) { x.classList.remove('on'); }); f.classList.add('on'); logFilter = f.dataset.filter; refilterLog(); };
    });
    $('#logsearch').oninput = function (e) { logQuery = e.target.value.toLowerCase(); refilterLog(); };

    // Live VM keyboard: when the VM page is showing a live session, route key
    // presses into the guest (skip when typing into a UI input field).
    document.addEventListener('keydown', function (e) {
      if (currentPage !== 'vm' || !livePollTimer) return;
      var t = e.target;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA')) return;
      var sc = keyToScancodes(e);
      if (!sc) return;
      e.preventDefault();
      send('vm.input', { scancodes: sc });
    });

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
