from flask import Flask, request, render_template, redirect, jsonify, session, flash
import bcrypt
import re
from datetime import datetime
from db import (get_alerts, create_user, get_user, update_password, get_db_connection,
                insert_login_failure, get_login_failures, count_recent_failures)
from utils.helpers import load_json, save_json
from os_blocker import list_blocked, unblock_ip
from simulator import simulate_brute_force, simulate_ddos, simulate_combined

app = Flask(__name__)
import os
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-troque-em-producao")

LOGS = "output/login_attempts.json"


def validate_credentials(username, password):
    errors = []
    if not username or len(username.strip()) < 3:
        errors.append("Usuário deve ter pelo menos 3 caracteres.")
    elif len(username) > 30:
        errors.append("Usuário deve ter no máximo 30 caracteres.")
    elif not re.match(r'^[a-zA-Z0-9_]+$', username):
        errors.append("Usuário só pode conter letras, números e underscores (_).")
    if not password or len(password) < 6:
        errors.append("Senha deve ter pelo menos 6 caracteres.")
    return errors


def log_attempt(ip, status):
    logs = load_json(LOGS)
    logs.append({"ip": ip, "status": status, "time": str(datetime.now())})
    save_json(LOGS, logs)


LOCK_THRESHOLD = 5   # tentativas antes de bloquear
LOCK_SECONDS   = 30  # duração do bloqueio em segundos


@app.route("/", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        username = request.form.get("user", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr

        if not username or not password:
            msg = "Preencha todos os campos."
        else:
            ip_failures   = count_recent_failures("ip",       ip,       LOCK_SECONDS)
            user_failures = count_recent_failures("username", username, LOCK_SECONDS)

            if ip_failures >= LOCK_THRESHOLD:
                msg = (f"⛔ IP {ip} bloqueado por tentativas excessivas. "
                       f"Tente novamente em {LOCK_SECONDS} segundos.")
            elif user_failures >= LOCK_THRESHOLD:
                msg = (f"⛔ Usuário '{username}' bloqueado por tentativas excessivas. "
                       f"Tente novamente em {LOCK_SECONDS} segundos.")
            else:
                row = get_user(username)
                if row and bcrypt.checkpw(password.encode(), row[2].encode()):
                    log_attempt(ip, "SUCCESS")
                    session["user"] = username
                    return redirect("/dashboard")
                else:
                    log_attempt(ip, "FAILED")
                    insert_login_failure(username, ip)
                    remaining = LOCK_THRESHOLD - count_recent_failures("ip", ip, LOCK_SECONDS)
                    remaining = max(remaining, 0)
                    if remaining == 0:
                        msg = (f"⛔ IP {ip} bloqueado. "
                               f"Tente novamente em {LOCK_SECONDS} segundos.")
                    else:
                        msg = (f"Credenciais inválidas | IP: {ip} "
                               f"({remaining} tentativa(s) restante(s) antes do bloqueio)")

    return render_template("login.html", msg=msg)


@app.route("/register", methods=["GET", "POST"])
def register():
    errors = []
    success = ""
    if request.method == "POST":
        username = request.form.get("user", "").strip()
        password = request.form.get("password", "")
        errors = validate_credentials(username, password)
        if not errors:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            if create_user(username, hashed):
                success = "Conta criada com sucesso! Faça login."
                username = ""
            else:
                errors.append("Esse usuário já existe. Escolha outro nome.")
    return render_template("register.html", errors=errors, success=success)


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    errors = []
    success = ""
    if request.method == "POST":
        username   = request.form.get("user", "").strip()
        current_pw = request.form.get("current_password", "")
        new_pw     = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")
        if not all([username, current_pw, new_pw, confirm_pw]):
            errors.append("Preencha todos os campos.")
        elif new_pw != confirm_pw:
            errors.append("A nova senha e a confirmação não coincidem.")
        elif len(new_pw) < 6:
            errors.append("A nova senha deve ter pelo menos 6 caracteres.")
        else:
            row = get_user(username)
            if not row or not bcrypt.checkpw(current_pw.encode(), row[2].encode()):
                errors.append("Usuário ou senha atual incorretos.")
            else:
                new_hashed = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
                update_password(username, new_hashed)
                success = "Senha alterada com sucesso! Faça login novamente."
    return render_template("change_password.html", errors=errors, success=success)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/simulador")
def simulador():
    return render_template("simulator.html")


# ── API ────────────────────────────────────────────────────────────────────

@app.route("/api/login-failures")
def api_login_failures():
    data = get_login_failures()
    return jsonify([
        {"id": r[0], "username": r[1], "ip": r[2], "timestamp": r[3]}
        for r in data
    ])


@app.route("/api/alerts")
def api_alerts():
    data = get_alerts()
    return jsonify([
        {"id": a[0], "alert": a[1], "ip": a[2], "details": a[3], "timestamp": a[4]}
        for a in data
    ])


@app.route("/api/blocked")
def api_blocked():
    # Le do banco de dados (funciona sem root)
    conn = get_db_connection()
    rows = conn.execute("SELECT ip FROM blocked_ips ORDER BY ip").fetchall()
    conn.close()
    ips = [r[0] for r in rows]
    # Tenta tambem pegar do iptables (so funciona com root)
    try:
        os_ips = list_blocked()
        for ip in os_ips:
            if ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return jsonify(ips)


@app.route("/api/unblock/<ip>", methods=["POST"])
def api_unblock(ip):
    # Remove do banco
    conn = get_db_connection()
    conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()
    # Tenta remover do iptables tambem (so funciona com root)
    try:
        unblock_ip(ip)
    except Exception:
        pass
    return jsonify({"ok": True})


@app.route("/api/simulate/brute-force", methods=["POST"])
def sim_brute_force():
    ip = request.json.get("ip") if request.is_json else None
    alerts = simulate_brute_force(ip)
    return jsonify({"status": "ok", "alerts_generated": len(alerts), "ip": alerts[0]["ip"]})


@app.route("/api/simulate/ddos", methods=["POST"])
def sim_ddos():
    ip = request.json.get("ip") if request.is_json else None
    alerts = simulate_ddos(ip)
    return jsonify({"status": "ok", "alerts_generated": len(alerts), "ip": alerts[0]["ip"]})


@app.route("/api/simulate/combined", methods=["POST"])
def sim_combined():
    ip = request.json.get("ip") if request.is_json else None
    alerts = simulate_combined(ip)
    return jsonify({"status": "ok", "alerts_generated": len(alerts), "ip": alerts[0]["ip"]})



@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    import requests as req
    import os
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return jsonify({"error": "ANTHROPIC_API_KEY nao configurada no servidor"}), 500

    rows = get_alerts()
    alerts = [{"alert": a[1], "ip": a[2], "details": a[3]} for a in rows[:20]]

    conn = get_db_connection()
    blocked = [r[0] for r in conn.execute("SELECT ip FROM blocked_ips").fetchall()]
    conn.close()

    lines = ["[" + a["alert"] + "] de " + a["ip"] + " - " + str(a["details"]) for a in alerts]
    summary = "\n".join(lines)
    blocked_str = ", ".join(blocked) if blocked else "nenhum"
    prompt = "Alertas (" + str(len(alerts)) + " total):\n" + summary + "\nIPs bloqueados: " + blocked_str

    try:
        res = req.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01"
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 800,
                "system": "Voce e um analista de SOC senior. Analise os alertas e responda em portugues com relatorio CONCISO: 1) Padrao de ameaca identificado, 2) IPs mais suspeitos, 3) Ataque mais critico, 4) Recomendacoes imediatas (max 3). Direto e tecnico. Max 200 palavras.",
                "messages": [{"role": "user", "content": prompt}]
            },
            timeout=30
        )
        result = res.json()
        text = "".join(b.get("text", "") for b in result.get("content", []))
        return jsonify({"result": text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    import os
    cert = "localhost.pem"
    key  = "localhost-key.pem"
    if os.path.exists(cert) and os.path.exists(key):
        app.run(debug=True, ssl_context=(cert, key))
    else:
        app.run(debug=True, host="0.0.0.0", port=5000)

# ── Monitor em background thread ──────────────────────────────────────────────

import threading
import os as _os

def run_monitor():
    import time
    from core.parser import LogParser
    from core.detector import Detector
    from core.correlator import Correlator
    from db import insert_alert
    from blocker import block_ip, is_blocked

    AUTO_BLOCK = {
        "Brute Force SSH", "DDoS HTTP", "SQL Injection", "XSS Attack",
        "Path Traversal", "RCE Attempt", "Port Scan",
        "Combined Attack", "Advanced Reconnaissance", "Scan + Exploit Attempt"
    }

    log_path = _os.environ.get("LOG_PATH", "logs/auth.log")
    _os.makedirs(_os.path.dirname(log_path) if _os.path.dirname(log_path) else "logs", exist_ok=True)
    if not _os.path.exists(log_path):
        open(log_path, "w").close()

    print(f"[MONITOR] Iniciado — lendo {log_path}")

    parser     = LogParser()
    detector   = Detector()
    correlator = Correlator()

    while True:
        try:
            with open(log_path, "r") as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        continue
                    event = parser.parse_auth(line) or parser.parse_web(line)
                    if not event:
                        continue
                    ip = event.get("ip")
                    if not ip or is_blocked(ip):
                        continue
                    alerts = detector.process(event) + correlator.correlate(event)
                    for alert in alerts:
                        insert_alert(alert)
                        print("[ALERT]", alert["alert"], "—", ip)
                        if alert["alert"] in AUTO_BLOCK:
                            block_ip(ip)
                            detector.reset_ip(ip)
                            correlator.activity.pop(ip, None)
        except Exception as e:
            print(f"[MONITOR] Erro: {e} — reiniciando em 5s")
            time.sleep(5)


# Inicia o monitor em thread daemon ao importar o app
_monitor_thread = threading.Thread(target=run_monitor, daemon=True)
_monitor_thread.start()