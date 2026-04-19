from flask import Flask, render_template, redirect
from analyzer import read_file, extract_open_ports
import os

app = Flask(__name__)

DATA_FILE = "../data/nmap.txt"


@app.route("/")
def home():
    lines = read_file(DATA_FILE)
    raw_ports = extract_open_ports(lines)

    ports = []
    alerts = 0

    for p in raw_ports:
        port_num = int(p["port"])

        # Detection logic
        if port_num in [22, 3389]:
            severity = "high"
            alerts += 1
        elif port_num > 8000:
            severity = "medium"
        else:
            severity = "low"

        ports.append({
            "host": "target",
            "port": port_num,
            "service": p["service"],
            "severity": severity
        })

    return render_template("index.html", ports=ports, alerts=alerts)


@app.route("/scan")
def scan():
    os.system("cd ../bash && chmod +x scan.sh && ./scan.sh")
    return redirect("/")  # go back to dashboard


if __name__ == "__main__":
    app.run(debug=True)