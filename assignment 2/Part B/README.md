# Part B — Bash Nmap Scanner

Scanner: `A2_AromaGul_scan.sh` — CIDR-based host, port and service scanner.

## Run the scanner
```bash
chmod +x A2_AromaGul_scan.sh
./A2_AromaGul_scan.sh 127.0.0.1/32        # usage: ./A2_AromaGul_scan.sh <CIDR>
```

## Evidence
- `evidence/lab-scan.csv` — scan results (host, port, protocol, service, version)
- `evidence/nmap-lab-test.txt` — Nmap `-sV` lab test against the local lab services

## Validation
- Bash syntax validation
- Nmap dependency checking
- IPv4 CIDR and octet validation
- Host availability testing
- CSV results generation
