from flask import Flask, request, render_template_string, redirect
import bcrypt
from datetime import datetime
import json
from db import get_alerts
from utils.helpers import load_json, save_json

app = Flask(__name__)

USERS = "output/users.json"
LOGS = "output/login_attempts.json"

# LOGIN 
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
}
button {
    width:100%;
    padding:10px;
    background:#22c55e;
    border:none;
    color:white;
}
.error { color:red; }
</style>
</head>
<body>
<div class="card">
<h2>Login</h2>
<form method="POST">
<input name="user" placeholder="User">
<input name="password" type="password" placeholder="Password">
<button>Entrar</button>
</form>
<p class="error">{{msg}}</p>
<a href="/register">Criar conta</a>
</div>
</body>
</html>
"""

# DASHBOARD 
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
<title>SOC Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {
    background:#020617;
    color:white;
    font-family:Arial;
    padding:20px;
}
</style>
</head>
<body>

<h1>SOC Dashboard</h1>

<canvas id="chart"></canvas>

<table border="1" style="margin-top:20px; width:100%;">
<tr>
<th>ID</th>
<th>Alerta</th>
<th>IP</th>
<th>Tempo</th>
</tr>
<tbody id="table"></tbody>
</table>

<script>
async function loadData() {
    const res = await fetch("/api/alerts");
    const data = await res.json();

    let count = {};
    let table = document.getElementById("table");
    table.innerHTML = "";

    data.forEach(a => {
        count[a.ip] = (count[a.ip] || 0) + 1;

        table.innerHTML += `
        <tr>
            <td>${a.id}</td>
            <td>${a.alert}</td>
            <td>${a.ip}</td>
            <td>${a.timestamp}</td>
        </tr>
        `;
    });

    new Chart(document.getElementById("chart"), {
        type: "bar",
        data: {
            labels: Object.keys(count),
            datasets: [{
                label: "Ataques por IP",
                data: Object.values(count)
            }]
        }
    });
}

setInterval(loadData, 3000);
loadData();
</script>

</body>
</html>
"""

# ---------------- HELPERS ----------------
def log_attempt(ip, status):
    logs = load_json(LOGS)
    logs.append({
        "ip": ip,
        "status": status,
        "time": str(datetime.now())
    })
    save_json(LOGS, logs)

# ---------------- ROTAS ----------------
@app.route("/", methods=["GET","POST"])
def login():
    msg = ""

    if request.method == "POST":
        user = request.form["user"]
        password = request.form["password"].encode()
        ip = request.remote_addr

        users = load_json(USERS)

        for u in users:
            if u["user"] == user and bcrypt.checkpw(password, u["password"].encode()):
                log_attempt(ip, "SUCCESS")
                return redirect("/dashboard")

        log_attempt(ip, "FAILED")
        msg = f"Erro | IP: {ip}"

    return render_template_string(LOGIN_HTML, msg=msg)


@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        user = request.form["user"]
        password = request.form["password"].encode()

        users = load_json(USERS)

        hashed = bcrypt.hashpw(password, bcrypt.gensalt()).decode()

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

    return [
        {
            "id": a[0],
            "alert": a[1],
            "ip": a[2],
            "details": a[3],
            "timestamp": a[4]
        }
        for a in data
    ]


if __name__ == "__main__":
    app.run(debug=True)