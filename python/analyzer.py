def read_file(filepath):
    try:
        with open(filepath, "r") as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        return []


def extract_open_ports(nmap_data):
    ports = []
    for line in nmap_data:
        if "open" in line:
            parts = line.split()
            if len(parts) > 0:
                ports.append(parts[0])
    return ports


def extract_listening_services(conn_data):
    services = []
    for line in conn_data:
        if "LISTEN" in line or "tcp" in line:
            services.append(line.strip())
    return services