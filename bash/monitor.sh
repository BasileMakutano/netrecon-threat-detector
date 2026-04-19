#!/bin/bash

echo "[+] Starting continuous monitoring (Ctrl+C to stop)..."

while true
do
    ./scan.sh
    echo "[+] Waiting 30 seconds before next scan..."
    sleep 30
done