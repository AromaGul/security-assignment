# Part D — Attack-surface inventory (OWASP Juice Shop)

Full recon of the agreed target: **OWASP Juice Shop 20.4.0-SNAPSHOT** (`bkimminich/juice-shop`),
running as a Docker container in my own Kali lab at `http://localhost:3000`.
The public demo was **not** scanned; certificate-transparency logs show only `owasp-juice.shop`, so each
distinct server-side surface (`host:port/path`) is treated as one asset.

| File | What it is |
|---|---|
| `A2_AromaGul_PartD.pdf` | Write-up: scope, pipeline command by command, 45-row inventory, limitations |
| `A2_AromaGul_PartD_inventory.csv` | Inventory in the course CSV template (one row per asset, risk note per row) |
| `A2_AromaGul_recon.sh` | The pipeline as a reusable script — works against any authorised URL or domain |
| `evidence/` | Raw output captured on Kali, 19 Nov 2026 |

## Result summary
- **Open ports:** 3000/tcp (Juice Shop via docker-proxy, bound to 0.0.0.0 and [::]); 35651/tcp is containerd on loopback (out of scope).
- **Funnel:** 4,750 ffuf requests → 20 hits; 1.85 MB of JS → ~60 API paths + 45 client routes; 87 candidates probed → 45 assets.
- **Severity:** 2 critical, 13 high, 18 medium, 10 low, 1 not worth looking, 1 out of scope.
- **Top themes:** open directory listings (`/ftp`, `/encryptionkeys`, `/support/logs`), admin config and `/metrics` served anonymously, `Access-Control-Allow-Origin: *` with write methods, account-takeover paths.

## Reproduce
```bash
sudo apt install -y docker.io nmap whatweb ffuf seclists jq curl httpx-toolkit
sudo docker run -d --name juiceshop -p 3000:3000 bkimminich/juice-shop
chmod +x A2_AromaGul_recon.sh
./A2_AromaGul_recon.sh http://localhost:3000 out          # or any target you are authorised to test
```

## Evidence files
| File | Pipeline step |
|---|---|
| `01_ports_all.txt` | `nmap -p- --min-rate 2000 -T4` full TCP scan |
| `01b_listeners.txt` | `ss -ltnp` — which process owns each port |
| `02_service_3000.txt` | `nmap -sV -sC -p 3000` |
| `03_whatweb.txt`, `04_headers.txt` | Tech fingerprint and response headers |
| `05_robots.txt`, `06_security_txt.txt` | Published crawler / security metadata |
| `07_ffuf_root.txt` | ffuf with seclists `common.txt`, SPA size 9984 filtered |
| `08_js_endpoints.txt`, `09_spa_routes.txt` | Paths and routes mined from the JS bundle |
| `10_ftp_listing.txt`, `11_error_page.txt` | Inside `/ftp` and the Express error page |
| `13_probe.tsv` | status / size / content-type for all 87 candidates |
| `14_versions.txt` | App and Node.js version disclosure |

Recon only — nothing was exploited. Risk notes say what to test next and why.
