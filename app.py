from flask import Flask, request, render_template, redirect, jsonify, session, flash
import bcrypt
import re
from datetime import datetime
from db import get_alerts, create_user, get_user, update_password
from utils.helpers import load_json, save_json
from os_blocker import list_blocked, unblock_ip
from simulator import simulate_brute_force, simulate_ddos, simulate_combined

app = Flask(__name__)
app.secret_key = "TROQUE_ISSO_POR_UMA_CHAVE_ALEATORIA_LONGA"  # ← mude antes de usar em produção

LOGS = "output/login_attempts.json"


# ── Validação ──────────────────────────────────────────────────────────────

def validate_credentials(username, password):
    """
    Retorna lista de erros. Lista vazia = tudo ok.
    Regras:
      - username: 3–30 chars, apenas letras, números e _
      - password: mínimo 6 chars
    """
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


# ── Helpers ────────────────────────────────────────────────────────────────

def log_attempt(ip, status):
    logs = load_json(LOGS)
    logs.append({"ip": ip, "status": status, "time": str(datetime.now())})
    save_json(LOGS, logs)


# ── Rotas ──────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        username = request.form.get("user", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr

        # Validação básica antes de consultar o banco
        if not username or not password:
            msg = "Preencha todos os campos."
        else:
            row = get_user(username)
            if row and bcrypt.checkpw(password.encode(), row[2].encode()):
                log_attempt(ip, "SUCCESS")
                session["user"] = username
                return redirect("/dashboard")
            else:
                log_attempt(ip, "FAILED")
                msg = f"Credenciais inválidas | IP: {ip}"

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
                username = ""  # limpa o campo após sucesso
            else:
                errors.append("Esse usuário já existe. Escolha outro nome.")

    return render_template("register.html", errors=errors, success=success)


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    errors = []
    success = ""

    if request.method == "POST":
        username     = request.form.get("user", "").strip()
        current_pw   = request.form.get("current_password", "")
        new_pw       = request.form.get("new_password", "")
        confirm_pw   = request.form.get("confirm_password", "")

        # Validações
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
    return render_template("dashboard.html")


@app.route("/simulador")
def simulador():
    return render_template("simulator.html")


# ── API ────────────────────────────────────────────────────────────────────

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


if __name__ == "__main__":
    app.run(debug=True)