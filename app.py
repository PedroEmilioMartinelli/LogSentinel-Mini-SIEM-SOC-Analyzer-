from flask import Flask, request, render_template_string, redirect, jsonify
import bcrypt
from datetime import datetime
import json
from db import get_alerts
from utils.helpers import load_json, save_json
from os_blocker import list_blocked, block_ip, unblock_ip

app = Flask(__name__)

USERS = "output/users.json"
LOGS  = "output/login_attempts.json"

# ------------------------------------------------------------------ LOGIN
LOGIN_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Login</title>
<style>
body {
    background: linear-gradient(135deg, #0f172a, #020617);
    color: white;
    font-family: Arial;
    display:flex;
    justify-content:center;
    align-items:center;
    height:100vh;
}
.card {
    background:#1e293b;
    padding:30px;
    border-radius:12px;
    width:300px;
}
input {
    width:100%;
    padding:10px;
    margin:10px 0;
    background:#0f172a;
    border:1px solid #334155;
    color:white;
    border-radius:6px;
}
button {
    width:100%;
    padding:10px;
    background:#22c55e;
    border:none;
    color:white;
    border-radius:6px;
    cursor:pointer;
    font-weight:bold;
}
button:hover { background:#16a34a; }
.error { color:#f87171; margin-top:8px; }
a { color:#94a3b8; font-size:13px; }
</style>
</head>
<body>
<div class="card">
<h2>🔐 LogSentinel</h2>
<form method="POST">
<input name="user" placeholder="Usuário">
<input name="password" type="password" placeholder="Senha">
<button>Entrar</button>
</form>
<p class="error">{{msg}}</p>
<a href="/register">Criar conta</a>
</div>
</body>
</html>
"""

# --------------------------------------------------------------- DASHBOARD
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>SOC Dashboard — LogSentinel</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    background: #020617;
    color: white;
    font-family: Arial, sans-serif;
    padding: 24px;
}

h1 {
    font-size: 22px;
    margin-bottom: 6px;
    color: #e2e8f0;
}

.subtitle {
    color: #64748b;
    font-size: 13px;
    margin-bottom: 24px;
}

.stats {
    display: flex;
    gap: 16px;
    margin-bottom: 28px;
    flex-wrap: wrap;
}

.stat-card {
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 16px 24px;
    min-width: 160px;
    flex: 1;
}

.stat-card .label {
    font-size: 12px;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
}

.stat-card .value {
    font-size: 28px;
    font-weight: bold;
}

.stat-card.red .value   { color: #f87171; }
.stat-card.yellow .value { color: #fbbf24; }
.stat-card.green .value  { color: #22c55e; }
.stat-card.blue .value   { color: #60a5fa; }

.grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 28px;
}

@media (max-width: 768px) { .grid { grid-template-columns: 1fr; } }

.panel {
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 20px;
}

.panel h2 {
    font-size: 14px;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 16px;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}

th {
    text-align: left;
    padding: 8px 12px;
    color: #64748b;
    border-bottom: 1px solid #1e293b;
    font-weight: normal;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 1px;
}

td {
    padding: 10px 12px;
    border-bottom: 1px solid #0f172a;
    color: #cbd5e1;
}

tr:hover td { background: #1e293b; }

.badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: bold;
}

.badge.red    { background: #450a0a; color: #f87171; }
.badge.yellow { background: #422006; color: #fbbf24; }
.badge.green  { background: #052e16; color: #22c55e; }

.btn-unblock {
    background: #1e293b;
    border: 1px solid #334155;
    color: #94a3b8;
    padding: 4px 10px;
    border-radius: 6px;
    cursor: pointer;
    font-size: 12px;
}

.btn-unblock:hover {
    background: #f87171;
    border-color: #f87171;
    color: white;
}

.full-panel {
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 28px;
}

.full-panel h2 {
    font-size: 14px;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 16px;
}

.updated {
    font-size: 11px;
    color: #334155;
    margin-top: 12px;
    text-align: right;
}
</style>
</head>
<body>

<h1>🔐 LogSentinel — SOC Dashboard</h1>
<p class="subtitle">Atualização automática a cada 3 segundos</p>

<!-- Cards de resumo -->
<div class="stats">
    <div class="stat-card red">
        <div class="label">Total de Alertas</div>
        <div class="value" id="total-alerts">—</div>
    </div>
    <div class="stat-card yellow">
        <div class="label">IPs Únicos Atacantes</div>
        <div class="value" id="unique-ips">—</div>
    </div>
    <div class="stat-card green">
        <div class="label">IPs Bloqueados (SO)</div>
        <div class="value" id="blocked-count">—</div>
    </div>
    <div class="stat-card blue">
        <div class="label">Último Alerta</div>
        <div class="value" style="font-size:14px; padding-top:6px;" id="last-alert">—</div>
    </div>
</div>

<!-- Gráfico + Bloqueios -->
<div class="grid">
    <div class="panel">
        <h2>📊 Ataques por IP</h2>
        <canvas id="chart"></canvas>
    </div>

    <div class="panel">
        <h2>🚫 IPs Bloqueados no Firewall (SO)</h2>
        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Status</th>
                    <th>Ação</th>
                </tr>
            </thead>
            <tbody id="blocked-table">
                <tr><td colspan="3" style="color:#334155">Carregando...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<!-- Tabela de alertas -->
<div class="full-panel">
    <h2>🚨 Histórico de Alertas</h2>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>Tipo</th>
                <th>IP</th>
                <th>Detalhes</th>
                <th>Timestamp</th>
            </tr>
        </thead>
        <tbody id="alerts-table"></tbody>
    </table>
    <p class="updated" id="last-update"></p>
</div>

<script>
let chartInstance = null;

function alertBadge(text) {
    if (text.includes("Brute Force") || text.includes("DDoS"))
        return `<span class="badge red">${text}</span>`;
    if (text.includes("Suspeito") || text.includes("Correlação"))
        return `<span class="badge yellow">${text}</span>`;
    return `<span class="badge green">${text}</span>`;
}

async function loadAlerts() {
    const res  = await fetch("/api/alerts");
    const data = await res.json();

    document.getElementById("total-alerts").textContent = data.length;

    const uniqueIPs = new Set(data.map(a => a.ip));
    document.getElementById("unique-ips").textContent = uniqueIPs.size;

    if (data.length > 0) {
        const last = data[data.length - 1];
        document.getElementById("last-alert").textContent = last.alert;
    }

    // Gráfico
    const count = {};
    data.forEach(a => { count[a.ip] = (count[a.ip] || 0) + 1; });

    if (chartInstance) chartInstance.destroy();
    chartInstance = new Chart(document.getElementById("chart"), {
        type: "bar",
        data: {
            labels: Object.keys(count),
            datasets: [{
                label: "Ataques por IP",
                data: Object.values(count),
                backgroundColor: "#f87171",
                borderRadius: 6
            }]
        },
        options: {
            plugins: { legend: { labels: { color: "#94a3b8" } } },
            scales: {
                x: { ticks: { color: "#64748b" }, grid: { color: "#1e293b" } },
                y: { ticks: { color: "#64748b" }, grid: { color: "#1e293b" } }
            }
        }
    });

    // Tabela de alertas
    const tbody = document.getElementById("alerts-table");
    tbody.innerHTML = "";
    [...data].reverse().forEach(a => {
        tbody.innerHTML += `
        <tr>
            <td>${a.id}</td>
            <td>${alertBadge(a.alert)}</td>
            <td style="color:#f87171; font-family:monospace">${a.ip}</td>
            <td style="color:#64748b; font-size:12px">${a.details || "—"}</td>
            <td style="color:#475569; font-size:12px">${a.timestamp}</td>
        </tr>`;
    });

    document.getElementById("last-update").textContent =
        "Última atualização: " + new Date().toLocaleTimeString();
}

async function loadBlocked() {
    const res  = await fetch("/api/blocked");
    const data = await res.json();

    document.getElementById("blocked-count").textContent = data.length;

    const tbody = document.getElementById("blocked-table");

    if (data.length === 0) {
        tbody.innerHTML = `<tr><td colspan="3" style="color:#334155">Nenhum IP bloqueado</td></tr>`;
        return;
    }

    tbody.innerHTML = "";
    data.forEach(ip => {
        tbody.innerHTML += `
        <tr>
            <td style="font-family:monospace; color:#f87171">${ip}</td>
            <td><span class="badge red">BLOQUEADO</span></td>
            <td>
                <button class="btn-unblock" onclick="unblock('${ip}')">Desbloquear</button>
            </td>
        </tr>`;
    });
}

async function unblock(ip) {
    if (!confirm("Desbloquear " + ip + "?")) return;
    await fetch("/api/unblock/" + ip, { method: "POST" });
    loadBlocked();
}

function refresh() {
    loadAlerts();
    loadBlocked();
}

setInterval(refresh, 3000);
refresh();
</script>

</body>
</html>
"""

# ------------------------------------------------------------ HELPERS
def log_attempt(ip, status):
    logs = load_json(LOGS)
    logs.append({"ip": ip, "status": status, "time": str(datetime.now())})
    save_json(LOGS, logs)

# ------------------------------------------------------------ ROTAS
@app.route("/", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        user     = request.form["user"]
        password = request.form["password"].encode()
        ip       = request.remote_addr

        users = load_json(USERS)
        for u in users:
            if u["user"] == user and bcrypt.checkpw(password, u["password"].encode()):
                log_attempt(ip, "SUCCESS")
                return redirect("/dashboard")

        log_attempt(ip, "FAILED")
        msg = f"Credenciais inválidas | IP: {ip}"

    return render_template_string(LOGIN_HTML, msg=msg)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user     = request.form["user"]
        password = request.form["password"].encode()
        users    = load_json(USERS)
        hashed   = bcrypt.hashpw(password, bcrypt.gensalt()).decode()
        users.append({"user": user, "password": hashed})
        save_json(USERS, users)
        return redirect("/")
    return render_template_string(LOGIN_HTML, msg="")


@app.route("/dashboard")
def dashboard():
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/alerts")
def api_alerts():
    data = get_alerts()
    return jsonify([
        {
            "id":        a[0],
            "alert":     a[1],
            "ip":        a[2],
            "details":   a[3],
            "timestamp": a[4]
        }
        for a in data
    ])


@app.route("/api/blocked")
def api_blocked():
    try:
        ips = list_blocked()
    except Exception:
        ips = []
    return jsonify(ips)


@app.route("/api/unblock/<ip>", methods=["POST"])
def api_unblock(ip):
    try:
        unblock_ip(ip)
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)