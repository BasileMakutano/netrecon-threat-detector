from datetime import datetime

def generate_report(ports, alerts, messages):
    content = f"NetRecon Report - {datetime.now()}\n\n"
    content += f"Total Ports: {len(ports)}\n"
    content += f"Alerts: {alerts}\n\n"

    content += "Threats:\n"
    for m in messages:
        content += f"- {m}\n"

    content += "\nPorts:\n"
    for p in ports:
        content += f"{p['port']} - {p['service']}\n"

    with open("../data/report.txt", "w") as f:
        f.write(content)

    return content