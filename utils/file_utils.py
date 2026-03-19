import json
import os

def load_rules(path="rules/rules.json"):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Rules file not found: {path}")

    with open(path, "r") as f:
        return json.load(f)

def load_logs(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Log file not found: {path}")

    with open(path, "r") as f:
        return f.readlines()

def save_alerts(alerts, path="output/alerts.json"):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "w") as f:
        json.dump(alerts, f, indent=4, default=str)