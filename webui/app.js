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
  // CSP-safe confirm dialog (built with createElement/textContent, no innerHTML).
  // Resolves true (confirm) / false (cancel). Esc or backdrop = cancel.
  function confirmModal(title, body, confirmLabel) {
    return new Promise(function (resolve) {
      var ov = document.createElement('div'); ov.className = 'modal-overlay';
      var box = document.createElement('div'); box.className = 'modal';
      var h = document.createElement('h3'); h.textContent = title;
      var p = document.createElement('p'); p.textContent = body;
      var acts = document.createElement('div'); acts.className = 'modal-actions';
      var no = document.createElement('button'); no.className = 'btn'; no.textContent = 'Cancel';
      var yes = document.createElement('button'); yes.className = 'btn danger'; yes.textContent = confirmLabel || 'Confirm';
      acts.appendChild(no); acts.appendChild(yes);
      box.appendChild(h); box.appendChild(p); box.appendChild(acts); ov.appendChild(box);
      function close(v) { if (ov.parentNode) ov.parentNode.removeChild(ov); document.removeEventListener('keydown', onKey, true); resolve(v); }
      function onKey(e) { if (e.key === 'Escape') { e.preventDefault(); close(false); } else if (e.key === 'Enter') { e.preventDefault(); close(true); } }
      no.onclick = function () { close(false); };
      yes.onclick = function () { close(true); };
      ov.addEventListener('mousedown', function (e) { if (e.target === ov) close(false); });
      document.addEventListener('keydown', onKey, true);
      document.body.appendChild(ov);
      yes.focus();
    });
  }

  // ---------- bridge ----------
  var nextReqId = 1, pending = new Map();
  var state = { scans: [] };
  var currentPage = 'dashboard';
  var livePollTimer = null;
  var liveWatchRun = null; // run id whose live telemetry tail is already started
  var liveSession = null;  // null | 'boot' | 'running' | 'detonate' (UI state)
  var heldKeys = {};       // e.code -> break scancodes, flushed on blur/stop
  var liveMouse = { btn: 0, dx: 0, dy: 0 }; // accumulated relative mouse state
  var liveMouseTimer = null;                // flushes accumulated movement
  // The guest draws its pointer as a HARDWARE cursor sprite that is NOT in the
  // linear framebuffer we capture, so once Pointer Lock hides the host cursor
  // there'd be no visible pointer. We reconstruct an absolute position from the
  // same relative deltas we feed the guest and draw a synthetic pointer on the
  // canvas (an aiming aid — it can drift slightly from the guest's own ballistics).
  var liveCursor = { x: 0, y: 0, valid: false };
  var curFrameW = 0, curFrameH = 0, liveRaf = 0; // render loop decoupled from publish rate
  var liveFrameBuffer = null;    // host-shared ArrayBuffer of live RGBA pixels
  var usingSharedFrames = false; // true once the canvas path is live (no <img>)
  var liveFrameCount = 0, liveFps = 0, liveFpsTimer = null; // canvas fps readout
  var liveStartMs = 0;   // session start (ms) for the uptime readout
  var evtBurst = null;   // {line,n,t} — collapse telemetry log floods into one line
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
      if (m.evt === 'scan.yara' && m.data) onYaraResult(m.data);
      if (m.evt === 'scan.config' && m.data) onConfigResult(m.data);
      if (m.evt === 'reports.data' && m.data) onReportsData(m.data);
      if (m.evt === 'dashboard.data' && m.data) onDashboardData(m.data);
      if (m.evt === 'run.status' && m.data) onRunStatus(m.data);
      if (m.evt === 'telemetry' && m.data) onTelemetry(m.data);
      if (m.evt === 'vmframe' && m.w) onVmFrame(m.w, m.h);
    });
    // The host shares the VM framebuffer as a zero-copy SharedBuffer (created
    // once, reused). 'sharedbufferreceived' delivers/updates the ArrayBuffer and
    // its first frame's dimensions; later frames just signal via 'vmframe'.
    window.chrome.webview.addEventListener('sharedbufferreceived', function (e) {
      try {
        liveFrameBuffer = e.getBuffer();
        var d = e.additionalData;
        if (typeof d === 'string') { try { d = JSON.parse(d); } catch (x) { d = null; } }
        if (d && d.w) onVmFrame(d.w, d.h);
      } catch (x) { /* ignore */ }
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
        '<div class="panel"><h2>VM Console <span id="vm-live-status" class="page-sub" style="font-weight:400"></span><span id="vm-display-mode" class="page-sub" style="font-weight:600;margin-left:10px;font-size:12px"></span></h2>' +
        '<div class="actions"><button class="btn primary" id="vm-boot-btn">Boot VM (live)</button><button class="btn danger" id="vm-detonate-btn">Detonate Sample (live)</button><button class="btn" id="vm-stop-btn">Stop</button><button class="btn" id="vm-fs-btn" title="Fill the screen with the VM (Esc to exit)">⛶ Fullscreen</button></div>' +
        '<div class="screenframe" id="live-frame" tabindex="0" style="margin-top:12px;outline:none">Click “Boot VM (live)” for a clean session, or “Detonate Sample (live)” to run a BENIGN sample inside it.</div>' +
        '</div>' +
        '<div class="panel"><h2>Process Telemetry <span id="vm-telemetry-status" class="page-sub" style="font-weight:400"></span></h2>' +
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
  function findingsBlock(arr) {
    arr = arr || [];
    if (!arr.length) {
      return '<p class="page-sub" style="margin:0">No findings — nothing notable matched.</p>';
    }
    // Sort by descending score so the strongest signals lead (Any.Run tracker rows).
    var sorted = arr.slice().sort(function (a, b) { return (b.score | 0) - (a.score | 0); });
    return '<table class="grid"><thead><tr><th>Score</th><th>Rule</th><th>Detail</th></tr></thead><tbody>' +
      sorted.map(function (f) {
        return '<tr><td>' + riskChip(f.score | 0) + '</td><td class="mono">' +
          esc(f.ruleId || '') + '</td><td>' + esc(f.message || '') + '</td></tr>';
      }).join('') + '</tbody></table>';
  }
  function renderScans() {
    var box = $('#scan-results'); if (!box) return;
    if (!state.scans.length) {
      box.innerHTML = '<p class="page-sub" style="margin:0">No scan yet. Pick a file to see its type, hashes, entropy, PE info, findings, IOCs, tags, and report links.</p>';
      return;
    }
    var rows = state.scans.map(scanRow).join('');
    var last = state.scans[state.scans.length - 1];
    var io = last.iocs || {};
    var detail = kv([
      ['Path', last.path || '—'], ['File type', last.detectedType || '—'],
      ['SHA-256', last.sha256 || '—'],
      ['SHA-1', last.sha1 || '—'], ['MD5', last.md5 || '—'],
      ['imphash', last.imphash || '—'], ['CTPH (fuzzy)', last.ctph || '—'],
      ['Entropy', last.entropy != null ? Number(last.entropy).toFixed(3) : '—'],
      ['PE file', last.isPe ? 'yes' : 'no'],
      ['Authenticode signed', last.authenticodeSigned ? 'yes' : 'no'],
      ['Signer', last.signerName || '—'],
      ['Imports', n(last.imports)], ['Findings', n(last.findings)],
      ['Score', last.score | 0], ['Verdict', last.verdict || '—'],
      ['URLs', n(io.urls)], ['IPs', n(io.ips)], ['Domains', n(io.domains)],
      ['Registry paths', n(io.registryPaths)], ['Mutex hints', n(io.mutexHints)], ['Suspicious APIs', n(io.suspiciousApis)],
      ['YARA matches', n(last.yaraMatches)], ['capa capabilities', n(last.capaCapabilities)],
      ['DIE detections', n(last.dieDetections)], ['Intel hits', n(last.intelHits)]
    ]);
    box.innerHTML = '<table class="grid"><thead><tr><th>Score</th><th>Verdict</th><th>Tags</th><th>Path</th><th>SHA-256</th></tr></thead><tbody>' + rows + '</tbody></table>' +
      '<h2 style="margin:16px 0 8px">Latest Result Detail</h2>' + detail +
      '<div class="actions" style="margin:10px 0"><button class="btn" id="yara-gen-btn">Generate YARA rule</button><button class="btn" id="yara-copy-btn" style="display:none">Copy</button><button class="btn" id="cfg-btn">Recover config / C2</button></div>' +
      '<pre id="yara-out" class="mono" style="display:none;white-space:pre-wrap;background:var(--panel-2,#11151c);padding:10px;border-radius:6px;overflow:auto;max-height:340px"></pre>' +
      '<div id="cfg-out" style="display:none;margin-top:8px"></div>' +
      '<h2 style="margin:16px 0 8px">Findings</h2>' + findingsBlock(last.findings);
    var yb = $('#yara-gen-btn');
    if (yb) yb.onclick = function () {
      yb.disabled = true; yb.textContent = 'Generating…';
      send('scan.yara', { path: last.path || '', sha256: last.sha256 || '', imphash: last.imphash || '', detectedType: last.detectedType || '', isPe: !!last.isPe });
    };
    var cb = $('#cfg-btn');
    if (cb) cb.onclick = function () {
      cb.disabled = true; cb.textContent = 'Extracting…';
      send('scan.config', { path: last.path || '' });
    };
  }
  function onConfigResult(d) {
    var cb = $('#cfg-btn'); if (cb) { cb.disabled = false; cb.textContent = 'Recover config / C2'; }
    var out = $('#cfg-out'); if (!out) return;
    out.style.display = 'block';
    if (d && d.error) { appendLog('ERROR', 'Config extraction failed.'); return; }
    var items = (d && d.config) || [];
    if (!items.length) {
      out.innerHTML = '<p class="page-sub" style="margin:0">No embedded config / C2 recovered statically.</p>';
      appendLog('INFO', 'No config recovered.');
      return;
    }
    // textContent per row => injection-safe
    var html = '<h2 style="margin:8px 0">Malware Configuration (' + items.length + ')</h2><ul class="why">';
    out.innerHTML = html + items.map(function () { return '<li></li>'; }).join('') + '</ul>';
    var lis = out.querySelectorAll('li');
    for (var i = 0; i < lis.length && i < items.length; i++) lis[i].textContent = items[i];
    appendLog('WARN', 'Recovered ' + items.length + ' config/C2 indicator(s).');
  }
  function onYaraResult(d) {
    var yb = $('#yara-gen-btn'); if (yb) { yb.disabled = false; yb.textContent = 'Generate YARA rule'; }
    var out = $('#yara-out'); if (!out) return;
    if (d && d.error) { appendLog('ERROR', 'YARA generation failed.'); return; }
    out.style.display = 'block';
    out.textContent = (d && d.rule) || '';  // textContent => injection-safe
    var cb = $('#yara-copy-btn');
    if (cb) {
      cb.style.display = '';
      cb.onclick = function () {
        try { navigator.clipboard.writeText(out.textContent); appendLog('INFO', 'YARA rule copied.'); }
        catch (e) { appendLog('WARN', 'Clipboard unavailable.'); }
      };
    }
    appendLog('INFO', 'YARA rule generated.');
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
      function chk(id, label, on) { return '<label style="display:flex;gap:8px;align-items:center;margin:6px 0;font-size:13px"><input type="checkbox" id="' + id + '"' + (on ? ' checked' : '') + '> ' + esc(label) + '</label>'; }
      var inp = 'background:var(--panel2);border:1px solid var(--border2);color:var(--text,#e6edf3);border-radius:6px;padding:5px 8px;width:100%';
      function lbl(t) { return '<label style="display:block;margin:8px 0 2px;font-size:12px;color:var(--muted)">' + esc(t) + '</label>'; }
      var net = c.networkMode || 'disabled';
      var vmSec = '<div class="kv" style="margin-bottom:10px"><div class="k">Base VHDX</div><div class="v mono">' + esc(c.baseVhdxPath || '—') +
        '</div><div class="k">Workspace</div><div class="v mono">' + esc(c.workspaceRoot || '—') + '</div><div class="k">Provider</div><div class="v">' + esc(c.vmProvider || '—') + '</div></div>' +
        lbl('Network mode') + '<select id="cfg-net" style="' + inp + '">' + ['disabled', 'hostonly', 'nat'].map(function (o) { return '<option value="' + o + '"' + (net === o ? ' selected' : '') + '>' + o + '</option>'; }).join('') + '</select>' +
        lbl('VM timeout (sec)') + '<input id="cfg-timeout" type="number" min="10" value="' + (c.defaultTimeoutSec != null ? c.defaultTimeoutSec : 180) + '" style="' + inp + '">' +
        lbl('Live frame interval (ms)') + '<input id="cfg-shot" type="number" min="100" value="' + (c.screenshotIntervalMs != null ? c.screenshotIntervalMs : 2000) + '" style="' + inp + '">';
      var scanSec = chk('cfg-yara', 'YARA', c.enrichYara) + chk('cfg-capa', 'capa', c.enrichCapa) + chk('cfg-die', 'Detect It Easy', c.enrichDie) + chk('cfg-tagger', 'Tagger', c.enrichTagger);
      var intelSec = chk('cfg-intel', 'Enable network lookups (off by default)', c.intelEnabled) + chk('cfg-mb', 'MalwareBazaar', c.intelMalwareBazaar) +
        lbl('VirusTotal API key' + (c.virusTotalKeySet ? ' (currently set)' : '')) + '<input id="cfg-vt" type="password" autocomplete="off" placeholder="' + (c.virusTotalKeySet ? '•••••• (blank = keep)' : 'not set') + '" style="' + inp + '">';
      var safeSec = chk('cfg-dyn', 'Dynamic execution enabled (DANGER — lets the CLI run samples)', c.dynamicExecutionEnabled) +
        '<p class="page-sub" style="margin:6px 0 0">Theme: Dark (security) · Base disk format: ' + esc(c.baseDiskFormat || '—') + '</p>';
      var html = section('VM / Sandbox', vmSec) + section('Scanner', scanSec) + section('Threat Intel', intelSec) + section('Safety / General', safeSec);
      var body = $('#cfg-body'); if (body) { body.innerHTML = html + '<div style="flex-basis:100%;display:flex;gap:12px;align-items:center;margin-top:4px"><button class="btn primary" id="cfg-save">Save Settings</button><span class="page-sub" id="cfg-save-status"></span></div>'; }
      var save = $('#cfg-save');
      if (save) save.onclick = function () {
        var vt = ($('#cfg-vt') && $('#cfg-vt').value) || '';
        var payload = {
          networkMode: $('#cfg-net').value,
          defaultTimeoutSec: parseInt($('#cfg-timeout').value, 10) || 180,
          screenshotIntervalMs: parseInt($('#cfg-shot').value, 10) || 2000,
          enrichYara: $('#cfg-yara').checked, enrichCapa: $('#cfg-capa').checked, enrichDie: $('#cfg-die').checked, enrichTagger: $('#cfg-tagger').checked,
          intelEnabled: $('#cfg-intel').checked, intelMalwareBazaar: $('#cfg-mb').checked, dynamicExecutionEnabled: $('#cfg-dyn').checked
        };
        if (vt) payload.virusTotalApiKey = vt; // blank = keep existing key
        send('config.set', payload).then(function (rr) {
          var ok = rr && rr.ok && rr.result && rr.result.ok;
          var st = $('#cfg-save-status'); if (st) { st.textContent = ok ? '✓ saved to antimal.toml' : '✗ ' + String((rr && rr.result && rr.result.error) || 'save failed'); st.style.color = ok ? '#7ee2a8' : '#ff9b9b'; }
          appendLog(ok ? 'INFO' : 'ERROR', ok ? 'Settings saved to antimal.toml.' : 'Settings save failed.');
        });
      };
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
  // Show a run's report.html in an in-app modal iframe (served read-only from
  // runs.antimal.local), so analysts never have to leave the console for Explorer.
  function viewReportModal(folder) {
    var ov = document.createElement('div'); ov.className = 'modal-overlay';
    var box = document.createElement('div'); box.className = 'modal-wide';
    var bar = document.createElement('div'); bar.className = 'modal-bar';
    var ttl = document.createElement('span'); ttl.textContent = 'Report — ' + folder;
    var cls = document.createElement('button'); cls.className = 'btn'; cls.textContent = 'Close';
    bar.appendChild(ttl); bar.appendChild(cls);
    var frame = document.createElement('iframe'); frame.className = 'modal-frame';
    frame.setAttribute('sandbox', 'allow-same-origin'); // render content, no scripts
    frame.src = 'https://runs.antimal.local/' + encodeURIComponent(folder) + '/report.html';
    box.appendChild(bar); box.appendChild(frame); ov.appendChild(box);
    function close() { if (ov.parentNode) ov.parentNode.removeChild(ov); document.removeEventListener('keydown', onKey, true); }
    function onKey(e) { if (e.key === 'Escape') { e.preventDefault(); close(); } }
    cls.onclick = close;
    ov.addEventListener('mousedown', function (e) { if (e.target === ov) close(); });
    document.addEventListener('keydown', onKey, true);
    document.body.appendChild(ov);
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
      var folder = String(x.runDir || '').split(/[\\/]/).filter(Boolean).pop() || '';
      var viewBtn = (x.type && x.type.indexOf('HTML') >= 0 && folder) ? '<button class="iconbtn" title="View report in-app" data-view="' + esc(folder) + '">&#128065;</button> ' : '';
      return '<tr><td class="mono">' + esc(String(x.id || '').slice(0, 8)) + '</td><td>' + esc(x.file || '—') + '</td><td>' + riskChip(x.score | 0) + '</td><td>' + verdictBadge(x.verdict || '?') +
        '</td><td class="mono">' + esc(x.created || '—') + '</td><td>' + esc(x.type || '—') + '</td><td>' + viewBtn + '<button class="iconbtn" title="Open run folder" data-open="' + esc(x.runDir || '') + '">▤</button></td></tr>';
    }).join('');
    $all('#reports-rows [data-view]').forEach(function (b) {
      b.onclick = function () { var f = b.getAttribute('data-view'); if (f) viewReportModal(f); };
    });
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
  // Renders the dropped-file enrichment cell: the magic-byte type plus a short
  // sha256 (full hash in the tooltip), or the skip marker the agent set when it
  // couldn't read/hash the drop. Empty for non-file events.
  function dropCell(e) {
    var type = e.fileType || '';
    var sha = e.sha256 || '';
    var skip = e.hashSkipped || '';
    if (!type && !sha && !skip) return '<td></td>';
    var label = '';
    if (type) label += '<span class="tag">' + esc(type) + '</span> ';
    if (sha) label += '<span class="mono" title="' + esc(sha) + '">' + esc(sha.slice(0, 16)) + '…</span>';
    else if (skip) label += '<span class="mono" title="hash skipped: ' + esc(skip) + '">(' + esc(skip) + ')</span>';
    return '<td>' + label + '</td>';
  }
  function renderEventFeed(events) {
    var box = $('#dash-events'); if (!box) return;
    if (!events || !events.length) { box.innerHTML = '<p class="page-sub" style="margin:0">No events recorded for this run.</p>'; return; }
    var rows = events.slice().reverse().map(function (e) {
      var when = String(e.time || '').replace('T', ' ').replace('Z', '');
      var mit = e.mitre ? '<span class="tag">' + esc(e.mitre) + '</span>' : '';
      var cmd = e.commandLine || (e.exitCode ? ('exit ' + e.exitCode) : '');
      var img = shortPath(e.fullImagePath || e.image);
      return '<tr><td class="mono">' + esc(when) + '</td><td><span class="tag">' + esc(e.category || '?') + '</span></td><td>' + esc(e.action || '') +
        '</td><td class="mono">' + esc(e.pid | 0) + '</td><td class="mono" title="' + esc(e.fullImagePath || '') + '">' + esc(img) + '</td><td class="mono">' + esc(e.user || '') + '</td><td class="mono">' + esc(e.integrity || '') + '</td><td class="mono" title="' + esc(e.commandLine || '') + '">' + esc(cmd) + '</td><td class="mono">' + esc(e.target || '') + '</td>' + dropCell(e) + '<td>' + mit + '</td></tr>';
    }).join('');
    box.innerHTML = '<table class="grid"><thead><tr><th>Time</th><th>Category</th><th>Action</th><th>PID</th><th>Image</th><th>User</th><th>Integ.</th><th>Cmd / Exit</th><th>Target</th><th>Drop (type · sha256)</th><th>MITRE</th></tr></thead><tbody>' + rows + '</tbody></table>';
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
      // Boot/healthcheck runs have no real analysis target — don't show a scanner
      // verdict for the bundled test binary (it was 'malicious (100)' noise).
      var rows = (lr.kind === 'boot')
        ? [['Verdict', lr.verdict || 'boot session'], ['Run ID', lr.runId || '—'], ['When', lr.when || '—']]
        : [['Verdict', lr.verdict || '—'], ['Scanner', (lr.scannerVerdict || '—') + ' (' + (lr.score | 0) + ')'], ['Run ID', lr.runId || '—'], ['When', lr.when || '—']];
      run.innerHTML = kv(rows) +
        '<div class="actions" style="margin-top:12px"><button class="btn" data-open-run="' + esc(lr.runDir || '') + '">Open Run Folder</button></div>';
      var ob = run.querySelector('[data-open-run]');
      if (ob) ob.onclick = function () { var p = ob.getAttribute('data-open-run'); if (!p) return; send('run.open', { runDir: p }).then(function (rr) { appendLog(rr && rr.ok ? 'INFO' : 'ERROR', rr && rr.ok ? 'Opened run folder.' : 'Open failed.'); }); };
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
    // VM stopped/ended: drop the still-draining backlog so the status log can't
    // keep scrolling with no VM running (the WebView message queue can hold
    // thousands of events buffered during a crash-loop). livePollTimer is the
    // definitive "a live VM is streaming" flag, cleared by stopLivePoll().
    if (!livePollTimer) return;
    var cat = String(d.category || '?'), act = String(d.action || ''), tgt = String(d.target || '');
    var msg = 'EVT ' + cat + (act ? ' · ' + act : '') + (tgt ? ' · ' + shortPath(tgt) : '');
    // Coalesce floods: a crash-loop can emit 100+/sec. Within a short window,
    // collapse onto one log line with a running count instead of spamming N lines.
    var now = Date.now();
    if (evtBurst && evtBurst.line && evtBurst.line.parentNode && (now - evtBurst.t) < 400) {
      evtBurst.n++; evtBurst.t = now;
      var more = evtBurst.line.querySelector('.evt-more');
      if (!more) {
        more = document.createElement('span'); more.className = 'evt-more'; more.style.opacity = '0.55';
        var mm = evtBurst.line.querySelector('.msg'); if (mm) mm.appendChild(more);
      }
      if (more) more.textContent = '  (+' + evtBurst.n + ' more)';
    } else {
      appendLog('INFO', msg);
      evtBurst = { line: logEl ? logEl.lastChild : null, n: 0, t: now };
    }
    // Prefer the VM page's live panel; fall back to the dashboard feed.
    var box = $('#vm-events') || $('#dash-events'); if (!box) return;
    var tbody = box.querySelector('tbody');
    if (!tbody) {
      box.innerHTML = '<table class="grid"><thead><tr><th>Time</th><th>Category</th><th>Action</th><th>PID</th><th>Image</th><th>User</th><th>Integ.</th><th>Cmd / Exit</th><th>Target</th><th>Drop (type · sha256)</th><th>MITRE</th></tr></thead><tbody></tbody></table>';
      tbody = box.querySelector('tbody');
    }
    var when = String(d.time || '').replace('T', ' ').replace('Z', '');
    var cmd = d.commandLine || (d.exitCode ? ('exit ' + d.exitCode) : '');
    var img = shortPath(d.fullImagePath || d.image);
    var tr = document.createElement('tr');
    tr.innerHTML = '<td class="mono">' + esc(when) + '</td><td><span class="tag">' + esc(cat) + '</span></td><td>' + esc(act) +
      '</td><td class="mono">' + esc(d.pid | 0) + '</td><td class="mono" title="' + esc(d.fullImagePath || '') + '">' + esc(img) + '</td><td class="mono">' + esc(d.user || '') + '</td><td class="mono">' + esc(d.integrity || '') + '</td><td class="mono" title="' + esc(d.commandLine || '') + '">' + esc(cmd) + '</td><td class="mono">' + esc(tgt) +
      '</td>' + dropCell(d) + '<td>' + (d.mitre ? '<span class="tag">' + esc(d.mitre) + '</span>' : '') + '</td>';
    tbody.insertBefore(tr, tbody.firstChild);
    while (tbody.children.length > 500) tbody.removeChild(tbody.lastChild); // cap DOM growth on floods
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
  // Physical-key (e.code) -> Set-1 scancode maps. We send MAKE on keydown and
  // BREAK on keyup so press / hold / release and real modifier keys (Shift, Ctrl,
  // Alt, Win) all reach the guest exactly as on a local keyboard -- capitals,
  // Ctrl/Alt chords, function and navigation keys included. e.code is layout-
  // independent (KeyA is the physical A key regardless of shift/locale).
  var SC = {
    Escape: 0x01, Digit1: 0x02, Digit2: 0x03, Digit3: 0x04, Digit4: 0x05, Digit5: 0x06,
    Digit6: 0x07, Digit7: 0x08, Digit8: 0x09, Digit9: 0x0A, Digit0: 0x0B, Minus: 0x0C,
    Equal: 0x0D, Backspace: 0x0E, Tab: 0x0F, KeyQ: 0x10, KeyW: 0x11, KeyE: 0x12,
    KeyR: 0x13, KeyT: 0x14, KeyY: 0x15, KeyU: 0x16, KeyI: 0x17, KeyO: 0x18, KeyP: 0x19,
    BracketLeft: 0x1A, BracketRight: 0x1B, Enter: 0x1C, ControlLeft: 0x1D, KeyA: 0x1E,
    KeyS: 0x1F, KeyD: 0x20, KeyF: 0x21, KeyG: 0x22, KeyH: 0x23, KeyJ: 0x24, KeyK: 0x25,
    KeyL: 0x26, Semicolon: 0x27, Quote: 0x28, Backquote: 0x29, ShiftLeft: 0x2A,
    Backslash: 0x2B, KeyZ: 0x2C, KeyX: 0x2D, KeyC: 0x2E, KeyV: 0x2F, KeyB: 0x30,
    KeyN: 0x31, KeyM: 0x32, Comma: 0x33, Period: 0x34, Slash: 0x35, ShiftRight: 0x36,
    NumpadMultiply: 0x37, AltLeft: 0x38, Space: 0x39, CapsLock: 0x3A, F1: 0x3B,
    F2: 0x3C, F3: 0x3D, F4: 0x3E, F5: 0x3F, F6: 0x40, F7: 0x41, F8: 0x42, F9: 0x43,
    F10: 0x44, NumLock: 0x45, ScrollLock: 0x46, Numpad7: 0x47, Numpad8: 0x48,
    Numpad9: 0x49, NumpadSubtract: 0x4A, Numpad4: 0x4B, Numpad5: 0x4C, Numpad6: 0x4D,
    NumpadAdd: 0x4E, Numpad1: 0x4F, Numpad2: 0x50, Numpad3: 0x51, Numpad0: 0x52,
    NumpadDecimal: 0x53, IntlBackslash: 0x56, F11: 0x57, F12: 0x58
  };
  var SCE = { // 0xE0-prefixed (extended) keys
    ControlRight: 0x1D, AltRight: 0x38, NumpadEnter: 0x1C, NumpadDivide: 0x35,
    ArrowUp: 0x48, ArrowDown: 0x50, ArrowLeft: 0x4B, ArrowRight: 0x4D, Home: 0x47,
    End: 0x4F, PageUp: 0x49, PageDown: 0x51, Insert: 0x52, Delete: 0x53,
    MetaLeft: 0x5B, MetaRight: 0x5C
  };
  // Make (down=true) or break (down=false) scancodes for a physical key, or null.
  function keyScancodes(code, down) {
    if (SC[code] != null) { var s = SC[code]; return [down ? s : (s | 0x80)]; }
    if (SCE[code] != null) { var e = SCE[code]; return [0xE0, down ? e : (e | 0x80)]; }
    return null;
  }
  // Release every key currently held (used on blur / stop) so the guest can
  // never be left with a stuck modifier when capture leaves the frame.
  function releaseHeldKeys() {
    for (var c in heldKeys) { if (heldKeys[c]) send('vm.input', { scancodes: heldKeys[c] }); }
    heldKeys = {};
  }
  // Character -> a complete Set-1 tap (optional LShift wrap + key make/break) for
  // reliably "typing" a string (e.g. the login password) into the guest.
  var CH = {
    a: 0x1E, b: 0x30, c: 0x2E, d: 0x20, e: 0x12, f: 0x21, g: 0x22, h: 0x23, i: 0x17, j: 0x24, k: 0x25, l: 0x26, m: 0x32, n: 0x31, o: 0x18, p: 0x19, q: 0x10, r: 0x13, s: 0x1F, t: 0x14, u: 0x16, v: 0x2F, w: 0x11, x: 0x2D, y: 0x15, z: 0x2C,
    '1': 0x02, '2': 0x03, '3': 0x04, '4': 0x05, '5': 0x06, '6': 0x07, '7': 0x08, '8': 0x09, '9': 0x0A, '0': 0x0B,
    '-': 0x0C, '=': 0x0D, '[': 0x1A, ']': 0x1B, ';': 0x27, "'": 0x28, '`': 0x29, '\\': 0x2B, ',': 0x33, '.': 0x34, '/': 0x35, ' ': 0x39
  };
  var CHS = { '!': 0x02, '@': 0x03, '#': 0x04, '$': 0x05, '%': 0x06, '^': 0x07, '&': 0x08, '*': 0x09, '(': 0x0A, ')': 0x0B, '_': 0x0C, '+': 0x0D, '{': 0x1A, '}': 0x1B, ':': 0x27, '"': 0x28, '~': 0x29, '|': 0x2B, '<': 0x33, '>': 0x34, '?': 0x35 };
  function charToScancodes(ch) {
    var shift = false, code = null;
    if (ch >= 'A' && ch <= 'Z') { code = CH[ch.toLowerCase()]; shift = true; }
    else if (CH[ch] != null) { code = CH[ch]; }
    else if (CHS[ch] != null) { code = CHS[ch]; shift = true; }
    if (code == null) return null;
    var out = [];
    if (shift) out.push(0x2A);
    out.push(code, code | 0x80);
    if (shift) out.push(0xAA);
    return out;
  }
  // Type a string into the guest one keystroke per ~70ms burst. Unpaced bursts
  // get mangled by the guest keyboard stack (consecutive keys lost) -- pacing is
  // exactly what makes the password reliably accepted. Optional trailing Enter.
  function sendTextToGuest(text, withEnter) {
    if (!livePollTimer) { appendLog('WARN', 'Boot a VM first — no live session to type into.'); return; }
    var seq = [];
    for (var i = 0; i < text.length; i++) {
      var sc = charToScancodes(text[i]);
      if (sc) seq.push(sc);
    }
    if (withEnter) seq.push([0x1C, 0x9C]); // Enter make/break
    if (!seq.length) return;
    var k = 0;
    (function step() {
      if (k >= seq.length) { appendLog('INFO', 'Sent ' + seq.length + ' keystroke(s) to the VM.'); return; }
      send('vm.input', { scancodes: seq[k++] });
      // >100ms so each keystroke lands in its own host input-poll window (the VM
      // polls _live-input.bin every 100ms); batching multiple keys per poll is
      // what the guest keyboard stack drops, so spacing them out is the fix.
      setTimeout(step, 120);
    })();
  }
  function toggleFullscreen() {
    var lf = $('#live-frame'); if (!lf) return;
    if (document.fullscreenElement) { document.exitFullscreen(); }
    else if (lf.requestFullscreen) { lf.requestFullscreen().then(function () { lf.focus(); }).catch(function () {}); }
  }
  function stopLivePoll() {
    if (livePollTimer) { clearInterval(livePollTimer); livePollTimer = null; }
    if (liveMouseTimer) { clearInterval(liveMouseTimer); liveMouseTimer = null; }
    if (liveFpsTimer) { clearInterval(liveFpsTimer); liveFpsTimer = null; }
    if (liveRaf) { cancelAnimationFrame(liveRaf); liveRaf = 0; }
    curFrameW = 0; curFrameH = 0;
    liveMouse = { btn: 0, dx: 0, dy: 0 };
    usingSharedFrames = false; // next boot re-establishes the shared canvas path
    liveFrameCount = 0; liveFps = 0;
    liveStartMs = 0; evtBurst = null;
    var dm = $('#vm-display-mode'); if (dm) dm.textContent = '';
    releaseHeldKeys();
  }
  // Reset the live canvas to a placeholder and STOP blitting the previous run's
  // shared-buffer pixels. Without this, clicking Boot flashes the prior run's last
  // frame (the "jumps to the latest-run screenshot" glitch) until the new VM
  // publishes its first frame.
  function clearLiveFrame(msg) {
    usingSharedFrames = false; curFrameW = 0; curFrameH = 0;
    if (liveRaf) { cancelAnimationFrame(liveRaf); liveRaf = 0; }
    var box = $('#live-frame'); if (box) box.textContent = msg || ''; // drops the stale canvas/img
  }
  // Single source of truth for the VM status indicators (#vm-badge + #mode-badge +
  // the inline #vm-live-status), so they can never desync. Replaces the ad-hoc
  // writes scattered across the boot/detonate/stop/poll handlers.
  function setVmState(state, detail) {
    function badge(sel, cls, text) {
      var el = $(sel); if (!el) return;
      el.className = 'badge ' + cls;
      el.innerHTML = '<span class="dot"></span>' + esc(text);
    }
    var live = $('#vm-live-status'), lt = '';
    if (state === 'booting') { badge('#vm-badge', 'booting', 'VM Booting'); badge('#mode-badge', 'idle', 'Sandbox Ready'); lt = '· ' + (detail || 'booting…'); }
    else if (state === 'running') { badge('#vm-badge', 'ready', 'VM Running'); badge('#mode-badge', 'idle', 'Sandbox Ready'); lt = detail ? '· ' + detail : ''; }
    else if (state === 'detonating') { badge('#vm-badge', 'ready', 'VM Running'); badge('#mode-badge', 'blocked', 'Detonating'); lt = '· ' + (detail || 'detonating'); }
    else if (state === 'stopped') { badge('#vm-badge', 'idle', 'VM Idle'); badge('#mode-badge', 'idle', 'Sandbox Ready'); lt = '· stopped'; }
    else { badge('#vm-badge', 'idle', 'VM Idle'); badge('#mode-badge', 'idle', 'Sandbox Ready'); lt = ''; }
    if (live) live.textContent = lt;
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
  // Render a host-shared framebuffer (zero-copy) straight to a <canvas> — the
  // production "real VM display" path: no PNG encode, no disk, no decode. Falls
  // back to the <img>/PNG poll automatically if no shared frame ever arrives
  // (older WebView2 runtime).
  function ensureLiveCanvas() {
    var box = $('#live-frame'); if (!box) return null;
    var cv = document.getElementById('live-frame-canvas');
    if (!cv) {
      box.innerHTML = '';
      cv = document.createElement('canvas');
      cv.id = 'live-frame-canvas';
      box.appendChild(cv);
    }
    return cv;
  }
  // A new published frame just arrived: remember its geometry and count it for the
  // FPS readout. The actual drawing is done by the render loop (decoupled from the
  // publish rate) so the cursor stays smooth even when the guest content is frozen.
  function onVmFrame(w, h) {
    if (!liveFrameBuffer || !w || !h) return;
    if (liveFrameBuffer.byteLength < w * h * 4) return;
    curFrameW = w; curFrameH = h;
    usingSharedFrames = true;
    liveFrameCount++;
    if (liveSession === 'boot') { liveSession = 'running'; setVmState('running'); }
    if (!liveRaf) liveRaf = requestAnimationFrame(renderLoop);
  }
  // ~60fps redraw of the LATEST shared frame + the synthetic cursor. Runs
  // independently of how often the guest produces frames, so moving the mouse is
  // always responsive (the host updates the shared buffer in place; we just keep
  // blitting it). The cursor moving over a held-still desktop is what makes the VM
  // feel alive instead of frozen when the guest is busy.
  function renderLoop() {
    liveRaf = 0;
    var box = $('#live-frame');
    if (!box || !livePollTimer || !usingSharedFrames || !liveFrameBuffer || !curFrameW) return;
    var need = curFrameW * curFrameH * 4;
    if (liveFrameBuffer.byteLength >= need) {
      var cv = ensureLiveCanvas();
      if (cv) {
        if (cv.width !== curFrameW) cv.width = curFrameW;
        if (cv.height !== curFrameH) cv.height = curFrameH;
        var ctx = cv.getContext('2d');
        if (ctx) {
          try { ctx.putImageData(new ImageData(new Uint8ClampedArray(liveFrameBuffer, 0, need), curFrameW, curFrameH), 0, 0); } catch (e) { }
          // No synthetic cursor: the guest renders its own pointer into the
          // captured framebuffer, so drawing a second one here just produced the
          // "two cursors" artifact. The host cursor is hidden on capture
          // (cursor:none), leaving only the guest's real cursor.
        }
      }
    }
    liveRaf = requestAnimationFrame(renderLoop);
  }
  // A crisp white arrow with a dark outline so it reads on any background.
  function drawLiveCursor(ctx, x, y) {
    var p = [[0, 0], [0, 16], [4, 12], [7, 18], [9, 17], [6, 11], [11, 11]];
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(x + p[0][0], y + p[0][1]);
    for (var i = 1; i < p.length; i++) ctx.lineTo(x + p[i][0], y + p[i][1]);
    ctx.closePath();
    ctx.fillStyle = '#fff';
    ctx.strokeStyle = '#000';
    ctx.lineWidth = 1.5;
    ctx.lineJoin = 'round';
    ctx.fill();
    ctx.stroke();
    ctx.restore();
  }
  // Honest liveness readout while a live session runs. fps counts frames the VM
  // process actually published this second; 0 now means the publisher isn't
  // advancing frameSeq (the VM process stalled/exited) -- NOT the old blank-skip
  // freeze, which is fixed host-side (LiveFramePublishGate). Surfacing "stalled"
  // vs a real fps is exactly what the "live vm fps = 0" confusion needed.
  function fmtUptime(ms) {
    var s = Math.floor(ms / 1000), m = Math.floor(s / 60);
    return m + ':' + pad2(s % 60);
  }
  function updateDisplayMode() {
    var el = $('#vm-display-mode'); if (!el) return;
    if (!livePollTimer || !usingSharedFrames) { el.textContent = ''; return; }
    liveFps = liveFrameCount; liveFrameCount = 0;
    var up = liveStartMs ? ' · up ' + fmtUptime(Date.now() - liveStartMs) : '';
    if (liveFps > 0) {
      el.textContent = '● ' + liveFps + ' fps' + up;
      el.style.color = '#7ee2a8';
    } else {
      el.textContent = '○ stalled · 0 fps' + up;
      el.style.color = '#d9a441';
    }
  }
  function startLivePoll() {
    stopLivePoll();
    liveStartMs = Date.now(); // begin the uptime clock
    liveWatchRun = null; // each boot re-tails the new run's journal
    liveMouseTimer = setInterval(flushLiveMouse, 50);
    liveFpsTimer = setInterval(updateDisplayMode, 1000);
    livePollTimer = setInterval(function () {
      var box = $('#live-frame');
      if (!box) { stopLivePoll(); return; } // navigated away from VM page
      send('vm.frame').then(function (r) {
        var res = (r && r.result) || {};
        // The host reports live:false once the VM process has exited. End the
        // session cleanly instead of repainting a frozen frame forever.
        if (res.live === false) {
          stopLivePoll(); liveWatchRun = null; liveSession = null;
          setVmState('idle');
          var ts0 = $('#vm-telemetry-status'); if (ts0) ts0.textContent = '· ended';
          appendLog('INFO', 'Live VM ended.');
          return;
        }
        // Once the live run dir is known, start its telemetry tail exactly once
        // (live mode keeps tailing through the quiet boot until the VM exits).
        var run = res.run;
        if (run && run !== liveWatchRun) {
          liveWatchRun = run;
          appendLog('INFO', 'Live telemetry tail starting for ' + run + '…');
          var ts = $('#vm-telemetry-status'); if (ts) ts.textContent = '· tailing ' + run;
          send('run.watch', { runDir: run, live: true });
        }
        // Pixels come from the shared-buffer <canvas> when active; only fall back
        // to the <img>/PNG frame if no shared frame has arrived (older runtime).
        if (usingSharedFrames) {
          if (liveSession === 'boot') { liveSession = 'running'; setVmState('running'); }
          return;
        }
        var f = res.frame || '';
        if (!f) return;
        var img = document.getElementById('live-frame-img');
        if (!img) { box.innerHTML = ''; img = document.createElement('img'); img.id = 'live-frame-img'; box.appendChild(img); }
        img.src = f;
        // First real frame of a plain boot: promote 'booting' -> 'running'.
        if (liveSession === 'boot') { liveSession = 'running'; setVmState('running'); }
      });
    }, 200); // matches the interactive host frame cadence for a live-desktop feel
  }
  function loadVm() {
    var bb = $('#vm-boot-btn');
    if (bb) bb.onclick = function () {
      appendLog('INFO', 'Booting live VM…');
      setVmState('booting', 'starting…');
      clearLiveFrame('Booting the VM…'); // drop any stale/previous-run frame immediately
      send('vm.boot').then(function (r) {
        var ok = r && r.ok && r.result && r.result.started;
        appendLog(ok ? 'INFO' : 'ERROR', ok ? ('Live VM booting' + (r.result.seeded ? ' from snapshot' : ' (full OOBE)') + '…') : 'VM boot failed: ' + String((r && r.result && r.result.error) || 'unknown'));
        if (ok) {
          liveSession = 'boot';
          setVmState('booting', r.result.seeded ? 'from snapshot' : 'full OOBE');
          startLivePoll();
          var fr = $('#live-frame'); if (fr) fr.focus(); // capture keys with no extra click
        } else { setVmState('idle'); }
      });
    };
    var db = $('#vm-detonate-btn');
    if (db) db.onclick = function () { onAction('detonate.selected'); };
    var sb = $('#vm-stop-btn');
    if (sb) sb.onclick = function () {
      send('vm.stop'); stopLivePoll(); liveWatchRun = null; liveSession = null;
      appendLog('WARN', 'Live VM stopped.');
      var box = $('#live-frame'); if (box) box.textContent = 'Stopped.';
      setVmState('stopped');
      var ts = $('#vm-telemetry-status'); if (ts) ts.textContent = '· stopped';
    };
    var fsb = $('#vm-fs-btn');
    if (fsb) fsb.onclick = toggleFullscreen;
    // Live mouse: route movement/clicks over the frame into the guest (relative
    // PS/2 mouse). Movement deltas are scaled from displayed px to guest px and
    // accumulated; flushLiveMouse sends them ~20/s. Buttons go immediately.
    var lf = $('#live-frame');
    if (lf) {
      function frameScale() {
        var cv = document.getElementById('live-frame-canvas');
        if (cv && cv.clientWidth > 0 && cv.width > 0) {
          return { x: cv.width / cv.clientWidth, y: cv.height / Math.max(1, cv.clientHeight) };
        }
        var img = document.getElementById('live-frame-img');
        if (img && img.clientWidth > 0 && img.naturalWidth > 0) {
          return { x: img.naturalWidth / img.clientWidth, y: img.naturalHeight / Math.max(1, img.clientHeight) };
        }
        return { x: 1, y: 1 };
      }
      function btnBit(b) { return b === 2 ? 0x02 : (b === 1 ? 0x04 : 0x01); }
      // Captured = the pointer is locked to the frame. Like a VirtualBox window,
      // the first click captures the mouse: the host cursor vanishes and only the
      // guest's cursor shows; movement/clicks/keys all go to the VM. Esc releases.
      // Query by id (never close over a specific element) so this stays correct
      // across page remounts.
      function vmCaptured() { var pl = document.pointerLockElement; return !!pl && pl.id === 'live-frame'; }
      // Per-mount: the frame element is recreated on every VM-page mount, so its
      // own listeners die with it. First click grabs the mouse.
      lf.addEventListener('mousedown', function (e) {
        if (!livePollTimer) return;
        e.preventDefault();
        if (!vmCaptured()) { if (lf.requestPointerLock) { try { lf.requestPointerLock(); } catch (_) {} } lf.focus(); return; }
        liveMouse.btn |= btnBit(e.button);
        send('vm.input', { mouse: { buttons: liveMouse.btn, dx: 0, dy: 0 } });
      });
      lf.addEventListener('contextmenu', function (e) { e.preventDefault(); });
      // Document-level listeners attach ONCE -- they outlive page remounts, so
      // attaching them per-mount would stack duplicates and double every keystroke.
      // They act only while the live frame holds the pointer lock.
      if (!loadVm._inputWired) {
        loadVm._inputWired = true;
        document.addEventListener('pointerlockchange', function () {
          var f = document.getElementById('live-frame');
          var cv = document.getElementById('live-frame-canvas');
          if (vmCaptured()) {
            // Hide the HOST cursor over the VM so only the guest's pointer shows
            // (WebView2 does NOT hide the OS cursor on pointer-lock, hence cursor:none).
            if (f) { f.style.outline = '2px solid #4ea1ff'; f.style.cursor = 'none'; }
            if (cv) cv.style.cursor = 'none';
            liveCursor.x = cv ? cv.width / 2 : 0; liveCursor.y = cv ? cv.height / 2 : 0; liveCursor.valid = !!cv; // center the synthetic pointer on capture
          } else {
            if (f) { f.style.outline = 'none'; f.style.cursor = ''; } // restore the host cursor on release
            if (cv) cv.style.cursor = '';
            liveCursor.valid = false; releaseHeldKeys(); // never leave a key stuck
          }
        });
        // While driving the VM, the scroll wheel must NOT scroll the host page.
        // passive:false so preventDefault actually takes effect. (Delivering the
        // wheel to the guest needs PS/2 IntelliMouse 4-byte packets -- not yet
        // implemented; for now we just stop the leak.)
        document.addEventListener('wheel', function (e) {
          if (!livePollTimer || !vmCaptured()) return;
          e.preventDefault();
          e.stopPropagation();
        }, { passive: false });
        // Relative motion (movementX/Y) keeps coming under pointer lock even past
        // the window edge -- exactly what a guest mouse expects.
        document.addEventListener('mousemove', function (e) {
          if (!livePollTimer || !vmCaptured()) return;
          var s = frameScale();
          var gx = (e.movementX || 0) * s.x, gy = (e.movementY || 0) * s.y;
          liveMouse.dx += gx;            // delta -> guest (relative PS/2)
          liveMouse.dy += gy;
          var cv = document.getElementById('live-frame-canvas'); // integrate -> synthetic pointer
          if (cv) {
            liveCursor.x = Math.max(0, Math.min(cv.width, liveCursor.x + gx));
            liveCursor.y = Math.max(0, Math.min(cv.height, liveCursor.y + gy));
            liveCursor.valid = true;
          }
        });
        document.addEventListener('mouseup', function (e) {
          if (!livePollTimer || !vmCaptured()) return;
          e.preventDefault();
          liveMouse.btn &= ~btnBit(e.button);
          send('vm.input', { mouse: { buttons: liveMouse.btn, dx: 0, dy: 0 } });
        });
        // CRITICAL: skip the OS key auto-repeat (a held key fires keydown over and
        // over). Re-sending the MAKE each repeat is what typed garbled/duplicated
        // passwords. Send ONE make per physical press; break goes on keyup.
        document.addEventListener('keydown', function (e) {
          if (!livePollTimer || !vmCaptured()) return;
          e.preventDefault(); e.stopPropagation();
          if (heldKeys[e.code]) return;                   // OS auto-repeat -> ignore
          var mk = keyScancodes(e.code, true);
          if (!mk) return;
          heldKeys[e.code] = keyScancodes(e.code, false); // remember its break
          send('vm.input', { scancodes: mk });            // MAKE (once)
        });
        document.addEventListener('keyup', function (e) {
          if (!livePollTimer || !vmCaptured()) return;
          e.preventDefault(); e.stopPropagation();
          var bk = keyScancodes(e.code, false);
          delete heldKeys[e.code];
          if (bk) send('vm.input', { scancodes: bk });    // BREAK on release
        });
      }
    }
    // If a VM is actually running (navigated away and came back), resume the live
    // frame + input stream. vm.frame reports live:false when no VM is running, so a
    // leftover run dir can no longer masquerade as a live session on startup.
    send('vm.frame').then(function (r) {
      var res = (r && r.result) || {};
      if (res.live && !livePollTimer) {
        appendLog('INFO', 'Resuming live VM control…');
        liveSession = 'running';
        setVmState('running');
        var box = $('#live-frame'); if (box && res.frame) { box.innerHTML = ''; var im = document.createElement('img'); im.id = 'live-frame-img'; im.src = res.frame; box.appendChild(im); }
        startLivePoll();
        if (box) box.focus();
      }
    });
    send('config.get').then(function (r) {
      var c = (r && r.ok && r.result) ? r.result : {};
      var net = c.networkMode || 'disabled';
      var dyn = !!c.dynamicExecutionEnabled;
      var to = (c.defaultTimeoutSec != null ? c.defaultTimeoutSec : '—');
      var st = $('#vm-state');
      if (st) st.innerHTML = kv([['State', liveSession ? 'Running' : 'Idle'], ['Base VHDX', c.baseVhdxPath || '—'], ['Workspace', c.workspaceRoot || '—'], ['Provider', c.vmProvider || '—'], ['Overlay', 'disposable (per run)'], ['Firmware', 'OVMF (debug)'], ['Timeout', to + ' sec'], ['Network', net]]);
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
  var mounts = { dashboard: loadDashboard, vm: loadVm, base: loadBase, config: loadConfig, scan: renderScans, reports: loadReports, safety: loadSafety };

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
      confirmModal('Detonate a sample LIVE in the VM?',
        'This ARMS in-guest execution and will RUN the file you pick inside the sandbox. Use a BENIGN sample only — never real malware on a non-disposable host.',
        'Detonate').then(function (ok) {
        if (!ok) { appendLog('INFO', 'Detonate cancelled.'); return; }
        appendLog('WARN', 'Detonate — pick a BENIGN sample to execute live in the VM…');
        send('vm.detonate').then(function (r) {
          var res = (r && r.result) || {};
          if (res.cancelled) { appendLog('INFO', 'Detonate cancelled.'); return; }
          if (!res.started) { appendLog('ERROR', 'Detonate failed: ' + String(res.error || 'unknown')); return; }
          appendLog('WARN', 'Detonating ' + (res.sample || 'sample') + ' live' + (res.seeded ? ' (seed-boot)' : ' (cold boot)') + ' — watch it run on VM Analysis.');
          liveSession = 'detonate';
          if (currentPage !== 'vm') route('vm');
          // The VM page just mounted; start streaming the framebuffer + telemetry.
          setTimeout(function () {
            setVmState('detonating', res.sample || '');
            startLivePoll();
            var fr = $('#live-frame'); if (fr) fr.focus();
          }, 80);
        });
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
    $all('.logtools .f').forEach(function (f) {
      f.onclick = function () { $all('.logtools .f').forEach(function (x) { x.classList.remove('on'); }); f.classList.add('on'); logFilter = f.dataset.filter; refilterLog(); };
    });
    $('#logsearch').oninput = function (e) { logQuery = e.target.value.toLowerCase(); refilterLog(); };

    // (Live VM keyboard is handled on the #live-frame element itself, only while
    // it has focus, so keys can never leak to the UI and trigger buttons.)

    route('dashboard');

    // seed log + prove the bridge
    appendLog('INFO', 'AntiMal UI ready.');
    appendLog('INFO', 'Use Base Setup to build/import a clean VHDX.');
    appendLog('SAFE', 'Network disabled.');
    appendLog('SAFE', 'Sample execution blocked by safety gate.');
    send('ping', {}).then(function (r) {
      if (r && r.ok && r.result) {
        appendLog('INFO', 'Host bridge online (host v' + String(r.result.version || '?') + ').');
        setVmState('idle');
      } else {
        appendLog('ERROR', 'Host bridge not responding: ' + String((r && r.error) || 'unknown'));
      }
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
}());
