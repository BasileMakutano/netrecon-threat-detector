#!/bin/bash

# Create data folder if it doesn't exist
mkdir -p ../data

TARGET="127.0.0.1"

echo "[+] Starting Network Scan..."

# Nmap scan
echo "[+] Running Nmap..."
nmap -sS -oN ../data/nmap.txt $TARGET

# Active connections
echo "[+] Capturing active connections..."
ss -tuln > ../data/connections.txt

# Packet capture (5 seconds only for demo)
echo "[+] Capturing traffic..."
timeout 5 tcpdump -w ../data/traffic.pcap > /dev/null 2>&1

echo "[+] Scan complete. Data saved in /data folder."