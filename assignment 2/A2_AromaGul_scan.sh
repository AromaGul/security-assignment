#!/usr/bin/env bash

# Assignment A2 - Part B
# CIDR-based host, port and service scanner
# Usage: ./A2_AromaGul_scan.sh 192.168.1.0/24

set -o pipefail

# Check argument count
if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <CIDR>" >&2
    exit 1
fi

CIDR="$1"

# Check Nmap installation
if ! command -v nmap >/dev/null 2>&1; then
    echo "Error: Nmap is not installed." >&2
    exit 1
fi

# Validate IPv4 CIDR
if [[ ! "$CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; then
    echo "Error: Invalid IPv4 CIDR format." >&2
    exit 1
fi

IP="${CIDR%/*}"
IFS='.' read -r A B C D <<< "$IP"

for OCTET in "$A" "$B" "$C" "$D"; do
    if (( 10#$OCTET > 255 )); then
        echo "Error: Invalid IPv4 address." >&2
        exit 1
    fi
done

# Temporary workspace, automatically cleaned up
TMPDIR_SCAN=$(mktemp -d) || exit 1
trap 'rm -rf "$TMPDIR_SCAN"' EXIT

HOSTS_FILE="$TMPDIR_SCAN/hosts.txt"
RESULTS_FILE="$TMPDIR_SCAN/results.xml"

# Discover live hosts
echo "Discovering live hosts in $CIDR..." >&2

if ! nmap -sn -n "$CIDR" -oG - > "$TMPDIR_SCAN/discovery.txt"; then
    echo "Error: Host discovery failed." >&2
    exit 1
fi

awk '/Status: Up/ {print $2}' \
    "$TMPDIR_SCAN/discovery.txt" > "$HOSTS_FILE"

if [[ ! -s "$HOSTS_FILE" ]]; then
    echo "No live hosts found." >&2
    printf 'host,port,protocol,service,version\n'
    exit 0
fi

echo "Scanning live hosts..." >&2

# Scan TCP ports and identify services
if ! nmap -sT -sV -n -Pn -p- \
    -iL "$HOSTS_FILE" -oX "$RESULTS_FILE" \
    >/dev/null; then
    echo "Error: Port scan failed." >&2
    exit 1
fi

# Convert Nmap XML into CSV using Python 3
python3 - "$RESULTS_FILE" <<'PY'
import csv
import sys
import xml.etree.ElementTree as ET

writer = csv.writer(sys.stdout)
writer.writerow(["host", "port", "protocol", "service", "version"])

root = ET.parse(sys.argv[1]).getroot()

for host in root.findall("host"):
    address = host.find("address")
    if address is None:
        continue

    ip = address.get("addr", "")

    for port in host.findall("./ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue

        service = port.find("service")
        name = service.get("name", "") if service is not None else ""

        version = ""
        if service is not None:
            version = " ".join(
                x for x in [
                    service.get("product", ""),
                    service.get("version", ""),
                    service.get("extrainfo", "")
                ] if x
            )

        writer.writerow([
            ip,
            port.get("portid", ""),
            port.get("protocol", ""),
            name,
            version
        ])
PY
