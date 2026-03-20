from flask import Flask, request, render_template, redirect, jsonify
import bcrypt
from datetime import datetime
from db import get_alerts
from utils.helpers import load_json, save_json
from os_blocker import list_blocked, unblock_ip
from simulator import simulate_brute_force, simulate_ddos, simulate_combined

app = Flask(__name__)

USERS = "output/users.json"
LOGS  = "output/login_attempts.json"


# ---------------------------------------------------------------- HELPERS

def log_attempt(ip, status):
    logs = load_json(LOGS)
    logs.append({"ip": ip, "status": status, "time": str(datetime.now())})
    save_json(LOGS, logs)


# ---------------------------------------------------------------- ROTAS

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

    return render_template("login.html", msg=msg)


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
    return render_template("login.html", msg="")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/simulador")
def simulador():
    return render_template("simulator.html")


# ---------------------------------------------------------------- API

@app.route("/api/alerts")
def api_alerts():
    data = get_alerts()
    return jsonify([
        {"id": a[0], "alert": a[1], "ip": a[2], "details": a[3], "timestamp": a[4]}
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


@app.route("/api/simulate/brute-force", methods=["POST"])
def sim_brute_force():
    ip     = request.json.get("ip") if request.is_json else None
    alerts = simulate_brute_force(ip)
    return jsonify({"status": "ok", "alerts_generated": len(alerts), "ip": alerts[0]["ip"]})


@app.route("/api/simulate/ddos", methods=["POST"])
def sim_ddos():
    ip     = request.json.get("ip") if request.is_json else None
    alerts = simulate_ddos(ip)
    return jsonify({"status": "ok", "alerts_generated": len(alerts), "ip": alerts[0]["ip"]})


@app.route("/api/simulate/combined", methods=["POST"])
def sim_combined():
    ip     = request.json.get("ip") if request.is_json else None
    alerts = simulate_combined(ip)
    return jsonify({"status": "ok", "alerts_generated": len(alerts), "ip": alerts[0]["ip"]})


if __name__ == "__main__":
    app.run(debug=True)