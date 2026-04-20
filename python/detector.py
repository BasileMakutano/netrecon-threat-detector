previous_ports = set()

def detect_threats(port_list):
    global previous_ports

    alerts = 0
    messages = []

    current_ports = set([p["port"] for p in port_list])
    new_ports = current_ports - previous_ports

    if len(new_ports) > 5:
        alerts += 2
        messages.append("Possible Port Scan Detected")

    if len(current_ports) > 15:
        alerts += 1
        messages.append("Too many open ports")

    for p in current_ports:
        if p in [22, 3389]:
            alerts += 1
            messages.append(f"Sensitive port exposed: {p}")

    if len(port_list) > 20:
        alerts += 2
        messages.append("Possible brute-force behavior")

    previous_ports = current_ports

    return alerts, messages