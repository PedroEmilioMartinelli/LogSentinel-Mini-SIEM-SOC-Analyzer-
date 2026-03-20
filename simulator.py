import random
from datetime import datetime
from db import insert_alert
from blocker import block_ip, is_blocked

FAKE_IPS = [
    "10.0.0.1", "10.0.0.2", "192.168.1.50",
    "172.16.0.5", "203.0.113.10", "198.51.100.7"
]

def random_ip():
    return random.choice(FAKE_IPS)

def simulate_brute_force(ip=None):
    ip = ip or random_ip()
    alerts = []
    for i in range(6):
        alert = {
            "alert": "Brute Force SSH",
            "ip": ip,
            "details": f"[SIM] Failed password attempt {i+1}/6 from {ip}",
            "timestamp": str(datetime.now())
        }
        insert_alert(alert)
        alerts.append(alert)
    return alerts

def simulate_ddos(ip=None):
    ip = ip or random_ip()
    alerts = []
    for i in range(5):
        alert = {
            "alert": "DDoS HTTP",
            "ip": ip,
            "details": f"[SIM] High request rate from {ip} — req {i+1}/5",
            "timestamp": str(datetime.now())
        }
        insert_alert(alert)
        alerts.append(alert)
    return alerts

def simulate_combined(ip=None):
    ip = ip or random_ip()
    alerts = []
    for attack in ["Brute Force SSH", "Combined Attack"]:
        alert = {
            "alert": attack,
            "ip": ip,
            "details": f"[SIM] Suspicious behavior: SSH + web access from {ip}",
            "timestamp": str(datetime.now())
        }
        insert_alert(alert)
        alerts.append(alert)
    return alerts