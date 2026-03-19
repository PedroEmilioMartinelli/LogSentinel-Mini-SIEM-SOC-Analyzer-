import time
from core.parser import LogParser
from core.detector import Detector
from core.correlator import Correlator
from db import insert_alert
from blocker import block_ip, is_blocked

print("[+] Monitor iniciado... aguardando eventos")

parser = LogParser()
detector = Detector()
correlator = Correlator()

with open("logs/auth.log", "r") as f:
    # vai para o final do arquivo (modo tempo real)
    f.seek(0, 2)

    while True:
        line = f.readline()

        if not line:
            time.sleep(1)
            continue

        event = parser.parse_auth(line) or parser.parse_web(line)

        if event:
            ip = event.get("ip")

            # 🔥 ignora IP já bloqueado
            if is_blocked(ip):
                print(f"[IGNORED] IP {ip} está bloqueado")
                continue

            new_alerts = []
            new_alerts += detector.process(event)
            new_alerts += correlator.correlate(event)

            if new_alerts:
                for alert in new_alerts:
                    insert_alert(alert)
                    print("[ALERT]", alert)

                    # 🔥 bloqueio automático
                    if "Brute Force" in alert["alert"] or "DDoS" in alert["alert"]:
                        block_ip(ip)