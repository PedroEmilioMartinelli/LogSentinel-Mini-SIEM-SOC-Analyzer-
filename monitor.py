import time
from core.parser import LogParser
from core.detector import Detector
from core.correlator import Correlator
from db import insert_alert
from blocker import block_ip, is_blocked
from os_blocker import block_ip as os_block_ip, sync_from_db

AUTO_BLOCK_ALERTS = {
    "Brute Force SSH",
    "DDoS HTTP",
    "SQL Injection",
    "XSS Attack",
    "Path Traversal",
    "RCE Attempt",
    "Port Scan",
    "Combined Attack",
    "Advanced Reconnaissance",
    "Scan + Exploit Attempt"
}

print("[+] Monitor iniciado... aguardando eventos")

sync_from_db()

parser     = LogParser()
detector   = Detector()
correlator = Correlator()

with open("logs/auth.log", "r") as f:
    f.seek(0, 2)

    while True:
        line = f.readline()
        if not line:
            time.sleep(1)
            continue

        event = (
            parser.parse_auth(line) or
            parser.parse_web(line) or
            parser.parse_port_scan(line)
        )

        if not event:
            continue

        ip = event.get("ip")

        if is_blocked(ip):
            print(f"[IGNORED] IP {ip} está bloqueado")
            continue

        new_alerts = []
        new_alerts += detector.process(event)
        new_alerts += correlator.correlate(event)

        for alert in new_alerts:
            insert_alert(alert)
            print("[ALERT]", alert)

            if alert["alert"] in AUTO_BLOCK_ALERTS:
                block_ip(ip)
                os_block_ip(ip)
                detector.reset_ip(ip)
                correlator.activity.pop(ip, None)
                print(f"[BLOCKED] IP {ip} bloqueado na aplicação e no firewall do SO ({alert['alert']})")