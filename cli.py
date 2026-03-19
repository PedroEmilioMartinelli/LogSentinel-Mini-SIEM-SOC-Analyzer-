from core.parser import LogParser
from core.detector import Detector
from core.correlator import Correlator
from utils.helpers import save_alerts

print("[+] Iniciando análise...")

parser = LogParser()
detector = Detector()
correlator = Correlator()

alerts = []

with open("logs/auth.log") as f:
    for line in f:
        event = parser.parse_auth(line) or parser.parse_web(line)

        if event:
            alerts += detector.process(event)
            alerts += correlator.correlate(event)

save_alerts(alerts)

print(f"[+] Finalizado. Alertas: {len(alerts)}")