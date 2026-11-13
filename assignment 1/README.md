# Assignment 1 — OWASP Security Lab

## Overview
This assignment uses intentionally vulnerable OWASP practice applications for security testing in a local Docker environment.

## Applications and Ports

| Application | URL | Credentials |
|---|---|---|
| OWASP Juice Shop | http://127.0.0.1:3000 | Register a test account |
| DVWA | http://127.0.0.1:8090 | admin / password |
| OWASP WebGoat | http://127.0.0.1:8081/WebGoat | Create a test account |
| bWAPP | http://127.0.0.1:8082 | bee / bug |
| OWASP Mutillidae | http://127.0.0.1:8083 | Application-specific test accounts |

All applications are intended to be accessed locally through `127.0.0.1`.

## Requirements
- Kali Linux
- Docker Engine
- Docker Compose
- Nmap
- Burp Suite

## Start the Lab

```bash
cd ~/security-assignment-repo/"assignment 1"
sudo docker compose up -d
```

## Initialize Databases

```bash
sudo ./init-databases.sh
```

The initialization script should check DVWA, bWAPP, and Mutillidae before initializing missing databases.

**Warning:** Database setup endpoints can reset existing data. Do not rerun setup manually against an initialized database.

## Verify Containers

```bash
sudo docker compose ps
```

## Nmap Evidence

The Nmap scan output is stored at:

`evidence/nmap-lab-test.txt`

## Burp Suite Evidence

Capture an HTTP request from Juice Shop, send it to Burp Repeater, and save a screenshot at:

`evidence/juice-shop-burp-repeater.png`

## Stop the Lab Safely

```bash
sudo docker compose stop
```

Avoid `docker compose down`, especially with this lab configuration, because removing containers may destroy database data.

## Reset Procedure

For a non-destructive restart:

```bash
sudo docker compose start
```

For a full reset, first back up any data you need. Recreating containers may erase database changes. Only perform a full reset when data loss is acceptable.

## Scope and Safety

These applications are intentionally vulnerable and must only be tested in the authorized local lab environment. Do not expose them to the public internet.
