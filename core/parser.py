import re
from datetime import datetime

class LogParser:
    def extract_ip(self, line):
        match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
        return match.group() if match else None

    def parse_auth(self, line):
        if "Failed password" in line:
            return {
                "type": "failed_login",
                "ip": self.extract_ip(line),
                "raw": line,
                "timestamp": str(datetime.now())
            }

    def parse_web(self, line):
        ip = self.extract_ip(line)
        if ip:
            return {
                "type": "web_access",
                "ip": ip,
                "raw": line,
                "timestamp": str(datetime.now())
            }