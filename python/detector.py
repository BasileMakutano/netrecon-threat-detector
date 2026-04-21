import json
import os
from datetime import datetime, timedelta

BASELINE_FILE = "../data/baseline.json"
HISTORY_FILE = "../data/history.log"

def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return {
            "scan_count": 0,
            "avg_open_ports": 0,
            "known_ports": [],
            "last_scan": None
        }
    with open(BASELINE_FILE, "r") as f:
        return json.load(f)

def save_baseline(baseline):
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)

def detect_threats(port_list):
    alerts = 0
    messages = []

    baseline = load_baseline()
    current_ports = set(p["port"] for p in port_list)
    port_count = len(current_ports)

    # First scan → establish baseline
    if baseline["scan_count"] == 0:
        baseline["scan_count"] = 1
        baseline["avg_open_ports"] = port_count
        baseline["known_ports"] = list(current_ports)
        baseline["last_scan"] = str(datetime.now())
        save_baseline(baseline)
        return alerts, ["Baseline created. Monitoring initialized."]

    # Update baseline stats
    baseline["scan_count"] += 1
    baseline["avg_open_ports"] = (
        (baseline["avg_open_ports"] * (baseline["scan_count"] - 1)) + port_count
    ) / baseline["scan_count"]

    # Abnormal port increase
    if port_count > baseline["avg_open_ports"] * 2:
        alerts += 1
        messages.append(
            f"Abnormal increase in open ports ({port_count} vs baseline {int(baseline['avg_open_ports'])})"
        )

    # New services exposed
    new_ports = current_ports - set(baseline["known_ports"])
    for p in new_ports:
        alerts += 1
        messages.append(f"New network service detected on port {p}")

    # Time-based scan frequency
    try:
        with open(HISTORY_FILE, "r") as f:
            lines = f.readlines()

        timestamps = [
            datetime.fromisoformat(l.split("]")[0][1:])
            for l in lines if "Scan executed" in l
        ]

        recent = [
            t for t in timestamps
            if t > datetime.now() - timedelta(minutes=10)
        ]

        if len(recent) > 3:
            alerts += 1
            messages.append(
                f"High scan frequency detected ({len(recent)} scans in 10 minutes)"
            )
    except:
        pass

    # Sensitive ports
    for p in current_ports:
        if p in [22, 3389]:
            alerts += 1
            messages.append(f"Sensitive administrative port exposed: {p}")

    # Save updated baseline
    baseline["known_ports"] = list(set(baseline["known_ports"]) | current_ports)
    baseline["last_scan"] = str(datetime.now())
    save_baseline(baseline)

    return alerts, messages