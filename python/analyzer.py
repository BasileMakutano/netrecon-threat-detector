def read_file(filepath):
    try:
        with open(filepath, "r") as f:
            return f.readlines()
    except:
        return []


def extract_open_ports(lines):
    ports = []

    for line in lines:
        if "/tcp" in line and "open" in line:
            parts = line.split()
            port_proto = parts[0]  # e.g. 80/tcp
            port = port_proto.split("/")[0]

            service = parts[2] if len(parts) > 2 else "unknown"

            ports.append({
                "port": port,
                "service": service
            })

    return ports