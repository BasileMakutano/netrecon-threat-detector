from datetime import datetime

def generate_report(ports, alerts, messages):
    content = "NetRecon Threat Detection Report\n"
    content += f"Generated: {datetime.now()}\n\n"

    content += f"Total Open Ports: {len(ports)}\n"
    content += f"Alerts Raised: {alerts}\n\n"

    if messages:
        content += "Detected Anomalies:\n"
        for m in messages:
            content += f" - {m}\n"
    else:
        content += "No anomalies detected.\n"

    content += "\nObserved Services:\n"
    for p in ports:
        content += f" - Port {p['port']} ({p['service']})\n"

    with open("../data/report.txt", "w") as f:
        f.write(content)

    return content