class Correlator:
    def __init__(self):
        self.activity = {}

    def correlate(self, event):
        ip    = event["ip"]
        etype = event["type"]
        alerts = []

        if ip not in self.activity:
            self.activity[ip] = set()
        self.activity[ip].add(etype)

        types = self.activity[ip]

        if "failed_login" in types and "web_access" in types:
            alerts.append({
                "alert":     "Suspicious Behavior",
                "ip":        ip,
                "timestamp": event.get("timestamp", "")
            })

        if "sql_injection" in types and "path_traversal" in types:
            alerts.append({
                "alert":     "Advanced Reconnaissance",
                "ip":        ip,
                "timestamp": event.get("timestamp", "")
            })

        if "failed_login" in types and types & {"sql_injection", "xss", "rce_attempt", "path_traversal"}:
            alerts.append({
                "alert":     "Combined Attack",
                "ip":        ip,
                "timestamp": event.get("timestamp", "")
            })

        if "port_scan" in types and len(types) > 1:
            alerts.append({
                "alert":     "Scan + Exploit Attempt",
                "ip":        ip,
                "timestamp": event.get("timestamp", "")
            })

        return alerts