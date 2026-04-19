from flask import Flask, render_template
from analyzer import read_file, extract_open_ports

app = Flask(__name__)

@app.route("/")
def home():
    data = read_file("../data/nmap.txt")
    ports = extract_open_ports(data)
    return render_template("index.html", ports=ports)

if __name__ == "__main__":
    app.run(debug=True)