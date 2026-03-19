from collections import defaultdict
import json
import requests
import time

class Detector:
    def __init__(self, rules_path="rules/rules.json"):
        self.failed_attempts = defaultdict(int)

        with open(rules_path) as f:
            self.rules = json.load(f)

    def check_ip(self, ip):
        try:
            data = requests.get(f"https://ipinfo.io/{ip}/json").json()
            return {
                "country": data.get("country"),
                "org": data.get("org")
            }
        except:
            return {}

    def process(self, event):
        alerts = []

        for rule in self.rules:
            if event["type"] == rule["type"]:
                ip = event["ip"]

                self.failed_attempts[ip] += 1

                if self.failed_attempts[ip] >= rule["threshold"]:
                    intel = self.check_ip(ip)

                    alerts.append({
                        "alert": rule["alert"],
                        "ip": ip,
                        "count": self.failed_attempts[ip],
                        "intel": intel
                    })

        return alerts