class Correlator:
    def __init__(self):
        self.activity = {}

    def correlate(self, event):
        ip = event["ip"]
        alerts = []

        if ip not in self.activity:
            self.activity[ip] = []

        self.activity[ip].append(event["type"])

        if "failed_login" in self.activity[ip] and "web_access" in self.activity[ip]:
            alerts.append({
                "alert": "Suspicious Behavior",
                "ip": ip
            })

        return alerts