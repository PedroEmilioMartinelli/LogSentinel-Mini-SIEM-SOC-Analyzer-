import random
import ipaddress
from datetime import datetime
from db import get_db_connection
from blocker import blocked_ips  # o set em memória do blocker.py

LOG_FILE = "logs/auth.log"

def random_ip():
    """Gera um IP aleatório que nunca repete e nunca está bloqueado."""
    while True:
        ip = str(ipaddress.IPv4Address(random.randint(0x01000000, 0xDFFFFFFF)))
        if ip not in blocked_ips:
            return ip

def _clear_blocklist():
    """Limpa a blocklist em memória e no banco de dados."""
    blocked_ips.clear()
    conn = get_db_connection()
    conn.execute("DELETE FROM blocked_ips")
    conn.commit()
    conn.close()

def _write_log(lines):
    with open(LOG_FILE, "a") as f:
        for line in lines:
            f.write(line + "\n")

def simulate_brute_force(ip=None):
    _clear_blocklist()
    ip = ip or random_ip()
    lines = []
    for _ in range(6):
        lines.append(
            f"Failed password for invalid user admin from {ip} port 22 ssh2"
        )
    _write_log(lines)
    return [{"alert": "Brute Force SSH", "ip": ip, "details": f"[SIM] 6 tentativas de login SSH de {ip}", "timestamp": str(datetime.now())}]

def simulate_ddos(ip=None):
    _clear_blocklist()
    ip = ip or random_ip()
    lines = []
    for _ in range(5):
        lines.append(
            f'{ip} - - "GET / HTTP/1.1" 200'
        )
    _write_log(lines)
    return [{"alert": "DDoS HTTP", "ip": ip, "details": f"[SIM] 5 requisições HTTP rápidas de {ip}", "timestamp": str(datetime.now())}]

def simulate_combined(ip=None):
    _clear_blocklist()
    ip = ip or random_ip()
    lines = [
        f"Failed password for invalid user admin from {ip} port 22 ssh2",
        f'{ip} - - "GET /admin HTTP/1.1" 200'
    ]
    _write_log(lines)
    return [{"alert": "Combined Attack", "ip": ip, "details": f"[SIM] SSH + acesso web de {ip}", "timestamp": str(datetime.now())}]