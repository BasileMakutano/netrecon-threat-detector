from analyzer import read_file, extract_open_ports, extract_listening_services


def detect():
    print("[+] Running Threat Detection...\n")

    nmap_data = read_file("../data/nmap.txt")
    conn_data = read_file("../data/connections.txt")

    ports = extract_open_ports(nmap_data)
    services = extract_listening_services(conn_data)

    print("[+] Open Ports Detected:")
    for port in ports:
        print(f" - {port}")

    print("\n[+] Active Services:")
    for service in services[:5]:  # limit output
        print(f" - {service}")

    # Simple detection rules
    if len(ports) > 5:
        print("\n[!] ALERT: Too many open ports! Possible risk.")

    if len(services) > 10:
        print("[!] ALERT: High number of active connections!")

    print("\n[+] Detection complete.")


if __name__ == "__main__":
    detect()