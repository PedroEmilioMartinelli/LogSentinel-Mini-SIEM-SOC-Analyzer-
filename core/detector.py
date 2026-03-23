from collections import defaultdict
import json
import requests

class Detector:
    def __init__(self, rules_path="rules/rules.json"):
        self.counters = defaultdict(lambda: defaultdict(int))
        self.ip_cache = {}
        with open(rules_path) as f:
            self.rules = json.load(f)

    def check_ip(self, ip):
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        try:
            data = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2).json()
            result = {
                "country": data.get("country"),
                "org":     data.get("org")
            }
        except Exception:
            result = {"country": None, "org": None}
        self.ip_cache[ip] = result
        return result

    def process(self, event):
        alerts = []
        for rule in self.rules:
            if event["type"] == rule["type"]:
                ip    = event["ip"]
                count = self._increment(rule["type"], ip)
                if count >= rule["threshold"]:
                    intel = self.check_ip(ip)
                    alerts.append({
                        "alert":     rule["alert"],
                        "ip":        ip,
                        "count":     count,
                        "path":      event.get("path", ""),
                        "intel":     intel,
                        "timestamp": event.get("timestamp", "")
                    })
        return alerts

    def _increment(self, event_type, ip):
        self.counters[event_type][ip] += 1
        return self.counters[event_type][ip]

    def reset_ip(self, ip):
        for event_type in self.counters:
            self.counters[event_type][ip] = 0