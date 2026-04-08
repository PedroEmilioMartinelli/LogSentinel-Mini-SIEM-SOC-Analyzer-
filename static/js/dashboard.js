/* ============================================================
   LogSentinel — Dashboard JS
   ============================================================ */

var allAlerts  = [];
var blockedIPs = [];
var loginFails = [];
var currentFilter = 'all';
var selectedId    = null;
var liveMode      = false;
var liveInterval  = null;
var liveTick      = 0;
var sparkH = {
  total: Array(12).fill(0),
  crit:  Array(12).fill(0),
  ips:   Array(12).fill(0),
  blk:   Array(12).fill(0)
};

/* ── Severity / status maps ────────────────────────────────── */

var SEV_MAP = {
  'Brute Force SSH':         { s:'critical', t:'blocked' },
  'DDoS HTTP':               { s:'critical', t:'blocked' },
  'SQL Injection':           { s:'critical', t:'blocked' },
  'RCE Attempt':             { s:'critical', t:'blocked' },
  'Combined Attack':         { s:'critical', t:'investigating' },
  'Port Scan':               { s:'high',     t:'blocked' },
  'XSS Attack':              { s:'high',     t:'investigating' },
  'Path Traversal':          { s:'high',     t:'blocked' },
  'Scan + Exploit Attempt':  { s:'high',     t:'investigating' },
  'Advanced Reconnaissance': { s:'high',     t:'investigating' },
  'Suspicious Behavior':     { s:'medium',   t:'investigating' },
};

function gs(n) { return (SEV_MAP[n] || { s:'medium' }).s; }
function gt(n) { return (SEV_MAP[n] || { t:'investigating' }).t; }

var SL  = { critical:'CRÍTICO', high:'ALTO', medium:'MÉDIO', low:'BAIXO' };
var SC  = { critical:'bc', high:'bh', medium:'bm', low:'bl' };
var STL = { blocked:'Bloqueado', investigating:'Investigando', resolved:'Resolvido' };
var STC = { blocked:'#e84040', investigating:'#e88c30', resolved:'#40c070' };
var SEVC= { critical:'#e84040', high:'#e88c30', medium:'#e8c830', low:'#40c070' };
var BC1 = ['#e84040','#e88c30','#e8c830','#40c0e0','#a060e0','#40c070'];
var BC2 = ['#7c5cfc','#5c9cfc','#5cccfc','#5cfccc','#5cfc9c','#bcfc5c'];

/* ── Clock ─────────────────────────────────────────────────── */

function tickClock() {
  var el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleString('pt-BR');
}
setInterval(tickClock, 1000);
tickClock();

/* ── Sparkline ─────────────────────────────────────────────── */

function drawSpark(id, data, color) {
  var svg = document.getElementById(id);
  if (!svg) return;
  var w = 72, h = 30;
  var mx = Math.max.apply(null, data);
  var mn = Math.min.apply(null, data);
  var pts = data.map(function(v, i) {
    var x = (i / (data.length - 1)) * w;
    var y = h - ((v - mn) / (mx - mn || 1)) * h;
    return x + ',' + y;
  }).join(' ');
  var last = pts.split(' ').slice(-1)[0].split(',');
  svg.innerHTML =
    '<polyline points="' + pts + '" fill="none" stroke="' + color + '" stroke-width="1.5" stroke-linejoin="round"/>' +
    '<circle cx="' + last[0] + '" cy="' + last[1] + '" r="2.5" fill="' + color + '"/>';
}

function pushSpark(k, v) {
  sparkH[k].push(v);
  if (sparkH[k].length > 12) sparkH[k].shift();
}

/* ── Mini bar charts ───────────────────────────────────────── */

function renderBars(id, counts, colors) {
  var entries = Object.entries(counts).sort(function(a, b) { return b[1] - a[1]; }).slice(0, 6);
  var mx = Math.max.apply(null, entries.map(function(e) { return e[1]; }).concat([1]));
  var el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = entries.map(function(e, i) {
    var pct = Math.round((e[1] / mx) * 100);
    return '<div>' +
      '<div class="bar-item-lbl" title="' + e[0] + '">' + e[0] + '</div>' +
      '<div class="mini-bar-row">' +
        '<div class="mini-bar-track"><div class="mini-bar-fill" style="width:' + pct + '%;background:' + colors[i % colors.length] + '"></div></div>' +
        '<span class="mini-bar-count">' + e[1] + '</span>' +
      '</div>' +
    '</div>';
  }).join('');
}

/* ── Update stats cards ────────────────────────────────────── */

function updateStats() {
  var total = allAlerts.length;
  var crits = allAlerts.filter(function(a) { return gs(a.alert) === 'critical'; }).length;
  var uniq  = new Set(allAlerts.map(function(a) { return a.ip; })).size;
  var blk   = blockedIPs.length;

  document.getElementById('v-total').textContent = total;
  document.getElementById('v-crit').textContent  = crits;
  document.getElementById('v-ips').textContent   = uniq;
  document.getElementById('v-block').textContent = blk;
  document.getElementById('hdr-total').textContent = total;

  pushSpark('total', total);
  pushSpark('crit',  crits);
  pushSpark('ips',   uniq);
  pushSpark('blk',   blk);

  drawSpark('sp-total', sparkH.total, '#7c5cfc');
  drawSpark('sp-crit',  sparkH.crit,  '#e84040');
  drawSpark('sp-ips',   sparkH.ips,   '#e88c30');
  drawSpark('sp-block', sparkH.blk,   '#40c070');

  var tc = {}, ic = {};
  allAlerts.forEach(function(a) {
    tc[a.alert] = (tc[a.alert] || 0) + 1;
    ic[a.ip]    = (ic[a.ip]    || 0) + 1;
  });
  renderBars('type-bars', tc, BC1);
  renderBars('ip-bars',   ic, BC2);
}

/* ── Alerts table ──────────────────────────────────────────── */

function setFilter(f, btn) {
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(function(b) { b.classList.remove('active'); });
  if (btn) btn.classList.add('active');
  renderAlerts();
}

function renderAlerts(isNew) {
  var search = ((document.getElementById('search') || {}).value || '').toLowerCase();
  var filtered = allAlerts.filter(function(a) {
    var s = gs(a.alert), t = gt(a.alert);
    var mf = currentFilter === 'all' || s === currentFilter || t === currentFilter;
    var ms = !search || a.ip.toLowerCase().indexOf(search) > -1 || a.alert.toLowerCase().indexOf(search) > -1;
    return mf && ms;
  });

  var tbody = document.getElementById('alerts-body');
  if (!filtered.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="6">Nenhum alerta encontrado</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(function(a, i) {
    var s   = gs(a.alert);
    var t   = gt(a.alert);
    var sel = selectedId === a.id ? ' sel' : '';
    var nc  = (i === 0 && isNew) ? ' new-row' : '';
    var ts  = (a.timestamp || '').slice(11, 19);
    var det = (a.details || '—').toString().substring(0, 55);
    return '<tr class="' + sel + nc + '" onclick="selectAlert(' + a.id + ')">' +
      '<td><span class="badge ' + SC[s] + '">' + SL[s] + '</span></td>' +
      '<td style="color:#ccc">' + a.alert + '</td>' +
      '<td class="ip-text">' + a.ip + '</td>' +
      '<td><span style="color:' + STC[t] + ';font-size:11px">' + STL[t] + '</span></td>' +
      '<td class="ts-text" title="' + (a.details || '') + '">' + det + '</td>' +
      '<td class="ts-text">' + ts + '</td>' +
    '</tr>';
  }).join('');
}

/* ── Alert detail ──────────────────────────────────────────── */

function selectAlert(id) {
  selectedId = id;
  renderAlerts();
  var a = allAlerts.filter(function(x) { return x.id === id; })[0];
  if (!a) return;
  var s  = gs(a.alert);
  var t  = gt(a.alert);
  var sc = SEVC[s];
  document.getElementById('detail-panel').outerHTML =
    '<div class="side-panel" id="detail-panel" style="border-color:' + sc + '44">' +
      '<div class="detail-header">' +
        '<span class="side-panel-title">Detalhe do Alerta</span>' +
        '<button class="close-btn" onclick="clearDetail()">×</button>' +
      '</div>' +
      '<div class="detail-alert" style="color:' + sc + '">' + a.alert + '</div>' +
      '<div class="detail-row"><span class="detail-key">IP: </span><span class="detail-val ip-text">' + a.ip + '</span></div>' +
      '<div class="detail-row"><span class="detail-key">Severidade: </span><span class="detail-val" style="color:' + sc + '">' + SL[s] + '</span></div>' +
      '<div class="detail-row"><span class="detail-key">Status: </span><span class="detail-val" style="color:' + STC[t] + '">' + STL[t] + '</span></div>' +
      '<div class="detail-row"><span class="detail-key">Timestamp: </span><span class="detail-val">' + (a.timestamp || '—') + '</span></div>' +
      '<div class="detail-row"><span class="detail-key">Detalhes: </span><span class="detail-val">' + (a.details || '—') + '</span></div>' +
      '<div class="detail-row"><span class="detail-key">ID: </span><span class="detail-val">#' + a.id + '</span></div>' +
    '</div>';
}

function clearDetail() {
  selectedId = null;
  renderAlerts();
  document.getElementById('detail-panel').outerHTML =
    '<div class="placeholder" id="detail-panel">Clique em um alerta para ver detalhes</div>';
}

/* ── Blocked list ──────────────────────────────────────────── */

function renderBlocked() {
  var el = document.getElementById('blocked-list');
  if (!blockedIPs.length) {
    el.innerHTML = '<div style="color:var(--muted2);text-align:center;padding:24px">Nenhum IP bloqueado</div>';
    return;
  }
  var ic = {};
  allAlerts.forEach(function(a) { ic[a.ip] = (ic[a.ip] || 0) + 1; });
  el.innerHTML = blockedIPs.map(function(ip) {
    return '<div class="blocked-item">' +
      '<div>' +
        '<div class="blocked-ip">' + ip + '</div>' +
        '<div class="blocked-meta">' + (ic[ip] || 0) + ' alerta(s)</div>' +
      '</div>' +
      '<div class="blocked-right">' +
        '<span class="badge bs">BLOQUEADO</span>' +
        '<button class="btn btn-danger btn-sm" onclick="doUnblock(\'' + ip + '\')">Desbloquear</button>' +
      '</div>' +
    '</div>';
  }).join('');
}

async function doUnblock(ip) {
  if (!confirm('Desbloquear ' + ip + '?')) return;
  await fetch('/api/unblock/' + ip, { method: 'POST' });
  await loadBlocked();
}

/* ── Login failures ────────────────────────────────────────── */

function renderLogins() {
  var tbody = document.getElementById('logins-body');
  if (!loginFails.length) {
    tbody.innerHTML = '<tr class="empty-row"><td colspan="5">Nenhuma tentativa falha registrada</td></tr>';
    return;
  }
  var cm = {};
  loginFails.forEach(function(r) { var k = r.username + '|' + r.ip; cm[k] = (cm[k] || 0) + 1; });
  tbody.innerHTML = loginFails.map(function(r) {
    var k = r.username + '|' + r.ip;
    var c = cm[k];
    var badge = c >= 5
      ? '<span class="badge bs">BLOQUEADO (' + c + '×)</span>'
      : '<span class="badge bi">TENTATIVA (' + c + '×)</span>';
    return '<tr>' +
      '<td style="color:var(--muted)">' + r.id + '</td>' +
      '<td style="color:#fbbf24;font-weight:600">' + r.username + '</td>' +
      '<td class="ip-text">' + r.ip + '</td>' +
      '<td>' + badge + '</td>' +
      '<td class="ts-text">' + r.timestamp + '</td>' +
    '</tr>';
  }).join('');
}

/* ── AI Analysis ───────────────────────────────────────────── */

async function analyzeWithAI() {
  var btn = document.getElementById('btn-analyze');
  var out = document.getElementById('ai-output');
  var desc = document.getElementById('ai-desc');
  btn.disabled = true;
  out.innerHTML =
    '<div class="ai-loading">' +
      '<div class="ai-spinner"></div>' +
      '<span class="ai-spinner-lbl">Analisando padrões de ameaça...</span>' +
    '</div>';

  var summary = allAlerts.slice(0, 20).map(function(a) {
    return '[' + gs(a.alert).toUpperCase() + '] ' + a.alert + ' de ' + a.ip + ' — ' + (a.details || 'sem detalhes');
  }).join('\n');

  try {
    var res = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 800,
        system: 'Você é um analista de SOC sênior. Analise os alertas e responda em português com relatório CONCISO: 1) Padrão de ameaça identificado, 2) IPs mais suspeitos, 3) Ataque mais crítico, 4) Recomendações imediatas (máx 3). Direto e técnico. Máx 200 palavras.',
        messages: [{ role: 'user', content: 'Alertas (' + allAlerts.length + ' total):\n' + summary + '\nIPs bloqueados: ' + (blockedIPs.join(', ') || 'nenhum') }]
      })
    });
    var data = await res.json();
    var text = (data.content || []).map(function(b) { return b.text || ''; }).join('') || 'Não foi possível obter análise.';
    out.textContent = text;
    if (desc) desc.textContent = 'Análise gerada em ' + new Date().toLocaleTimeString('pt-BR');
  } catch (e) {
    out.textContent = 'Erro ao conectar com a API. Verifique a conexão.';
  }
  btn.disabled = false;
}

/* ── Tabs ──────────────────────────────────────────────────── */

function switchTab(tab, btn) {
  ['alerts', 'analysis', 'blocked', 'logins'].forEach(function(t) {
    document.getElementById('tab-' + t).style.display = t === tab ? '' : 'none';
  });
  document.querySelectorAll('.tab').forEach(function(b) { b.classList.remove('active'); });
  if (btn) btn.classList.add('active');
  if (tab === 'blocked') renderBlocked();
  if (tab === 'logins')  renderLogins();
}

/* ── Live mode ─────────────────────────────────────────────── */

var liveTypes = [
  { alert:'Brute Force SSH', details:'Tentativas de login SSH simuladas' },
  { alert:'Port Scan',       details:'Varredura SYN em múltiplas portas' },
  { alert:'XSS Attack',      details:'Script detectado em parâmetro GET' },
  { alert:'SQL Injection',   details:'UNION SELECT em query detectado' },
  { alert:'DDoS HTTP',       details:'Taxa de requisições anômala' },
];
var liveIPs = ['45.77.65.211', '198.100.44.5', '103.99.0.12', '185.220.101.8', '91.108.4.22'];

function toggleLive() {
  liveMode = !liveMode;
  var btn = document.getElementById('btn-live');
  var dot = document.getElementById('dot-live');
  if (liveMode) {
    btn.classList.add('live-on');
    dot.classList.add('on');
    btn.textContent = '● LIVE OFF';
    liveInterval = setInterval(function() {
      var p  = liveTypes[liveTick % liveTypes.length];
      var ip = liveIPs[liveTick % liveIPs.length];
      liveTick++;
      var ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
      allAlerts.unshift({ id: Date.now(), alert: p.alert, ip: ip, details: p.details + ' (simulado)', timestamp: ts });
      if (allAlerts.length > 100) allAlerts.pop();
      updateStats();
      renderAlerts(true);
      var c = document.getElementById('card-total');
      c.classList.add('flash');
      setTimeout(function() { c.classList.remove('flash'); }, 700);
    }, 3000);
  } else {
    btn.classList.remove('live-on');
    dot.classList.remove('on');
    btn.textContent = '○ LIVE ON';
    clearInterval(liveInterval);
  }
}

/* ── Data loading ──────────────────────────────────────────── */

async function loadAlerts() {
  try {
    var res = await fetch('/api/alerts');
    allAlerts = await res.json();
    updateStats();
    renderAlerts();
  } catch (e) {}
}

async function loadBlocked() {
  try {
    var res = await fetch('/api/blocked');
    blockedIPs = await res.json();
    updateStats();
    renderBlocked();
  } catch (e) { blockedIPs = []; }
}

async function loadLoginFails() {
  try {
    var res = await fetch('/api/login-failures');
    loginFails = await res.json();
  } catch (e) { loginFails = []; }
}

async function refresh() {
  await loadAlerts();
  await loadBlocked();
  await loadLoginFails();
}

setInterval(function() { if (!liveMode) refresh(); }, 15000);
refresh();