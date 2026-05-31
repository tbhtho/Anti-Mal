// AntiMal web UI bridge client (P1 smoke). Proves JS->C++ commands and C++->JS
// events both work. Strict discipline: every value that could be host/sample
// derived is written via textContent, never innerHTML (Section 5).
(function () {
  'use strict';

  var statusEl = document.getElementById('status');
  var logEl = document.getElementById('log');
  var nextReqId = 1;
  var pending = new Map();

  function send(cmd, args) {
    var reqId = nextReqId++;
    return new Promise(function (resolve) {
      pending.set(reqId, resolve);
      window.chrome.webview.postMessage({ cmd: cmd, reqId: reqId, args: args || {} });
    });
  }

  function appendLog(level, msg) {
    var line = document.createElement('div');
    line.className = 'log-line log-' + String(level).toLowerCase();
    var lvl = document.createElement('span');
    lvl.className = 'log-level';
    lvl.textContent = String(level);
    var txt = document.createElement('span');
    txt.textContent = ' ' + String(msg); // textContent => injection-safe
    line.appendChild(lvl);
    line.appendChild(txt);
    logEl.appendChild(line);
  }

  // Single inbound channel: replies (have a numeric reqId) and events (have evt).
  window.chrome.webview.addEventListener('message', function (e) {
    var m = e.data;
    if (!m || typeof m !== 'object') { return; }
    if (typeof m.reqId === 'number') {
      var resolve = pending.get(m.reqId);
      if (resolve) { pending.delete(m.reqId); resolve(m); }
      return;
    }
    if (m.evt === 'log' && m.data) {
      appendLog(m.data.level || 'INFO', m.data.msg || '');
    }
  });

  // P1 smoke: round-trip a ping.
  send('ping', {}).then(function (reply) {
    if (reply && reply.ok && reply.result) {
      statusEl.textContent = 'Bridge: OK  (host v' + String(reply.result.version || '?') + ')';
      statusEl.className = 'ok';
    } else {
      statusEl.textContent = 'Bridge: ERROR  ' + String((reply && reply.error) || 'unknown');
      statusEl.className = 'err';
    }
  });
}());
