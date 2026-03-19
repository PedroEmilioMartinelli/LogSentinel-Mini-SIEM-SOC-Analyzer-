import json
import os

def save_alerts(alerts, path="output/alerts.json"):
    os.makedirs("output", exist_ok=True)

    with open(path, "w") as f:
        json.dump(alerts, f, indent=4)

def load_json(path):
    if not os.path.exists(path):
        return []

    with open(path) as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)