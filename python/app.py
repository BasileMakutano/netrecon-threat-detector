from flask import Flask, render_template, redirect, jsonify, send_file
from analyzer import read_file, extract_open_ports
from detector import detect_threats
from reporter import generate_report
import os
from datetime import datetime

app = Flask(__name__)

DATA_FILE = "../data/nmap.txt"
HISTORY_FILE = "../data/history.log"

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/data")
def data():
    lines = read_file(DATA_FILE)
    ports = extract_open_ports(lines)
    alerts, messages = detect_threats(ports)

    formatted_ports = []
    for p in ports:
        if p["port"] in [22, 3389]:
            severity = "high"
        elif p["port"] > 8000:
            severity = "medium"
        else:
            severity = "low"

        formatted_ports.append({
            "host": "local",
            "port": p["port"],
            "service": p["service"],
            "severity": severity
        })

    return jsonify({
        "ports": formatted_ports,
        "alerts": alerts,
        "messages": messages
    })

@app.route("/scan")
def scan():
    os.system("cd ../bash && chmod +x scan.sh && ./scan.sh")
    with open(HISTORY_FILE, "a") as f:
        f.write(f"[{datetime.now().isoformat()}] Scan executed\n")
    return redirect("/")

@app.route("/report")
def report():
    lines = read_file(DATA_FILE)
    ports = extract_open_ports(lines)
    alerts, messages = detect_threats(ports)
    generate_report(ports, alerts, messages)
    return send_file("../data/report.txt", as_attachment=True)

@app.route("/history")
def history():
    return "<br>".join(read_file(HISTORY_FILE))

if __name__ == "__main__":
    app.run(debug=True)