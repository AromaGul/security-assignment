
# Assignment 2 — Security Testing

## Part A — TryHackMe
Completion screenshots are stored in `evidence/tryhackme/`.

## Part B — Bash Nmap Scanner
Scanner: `A2_AromaGul_scan.sh`

### Run the scanner
```bash
chmod +x A2_AromaGul_scan.sh
bash A2_AromaGul_scan.sh
```

### Evidence
- `evidence/lab-scan.csv` — Scan results
- `evidence/nmap-lab-test.txt` — Nmap lab test
- `evidence/tryhackme/` — TryHackMe screenshots

### Validation
- Bash syntax validation
- Nmap dependency checking
- Host availability testing
- CSV results generation

## Part D — Attack-surface inventory
Folder: `part-d/` — OWASP Juice Shop recon (lab instance).
- `part-d/A2_AromaGul_PartD.pdf` — write-up with pipeline and 45-asset inventory
- `part-d/A2_AromaGul_PartD_inventory.csv` — inventory in the course CSV template
- `part-d/A2_AromaGul_recon.sh` — reusable recon pipeline
- `part-d/evidence/` — raw Kali output
