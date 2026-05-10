# GameGuard – External Attack Surface Monitor

**Technologies:** Python, Shodan API, VirusTotal API, crt.sh, DNS, Censys, GreyNoise

---

## Overview

GameGuard is a Python CLI tool that monitors the external attack surface of any web asset. It automates subdomain discovery via Certificate Transparency logs, resolves IPs, scans for open ports, checks IP reputation against threat intelligence sources, and generates risk-scored reports. All in one streamlined workflow.

This project demonstrates skills in cybersecurity, threat intelligence automation, and modular Python development.

---

## Features

- **Automated Subdomain Discovery:** Pulls subdomains from Certificate Transparency logs via crt.sh.
- **DNS Resolution:** Resolves every discovered subdomain to its IP for downstream scanning.
- **Open Port Analysis:** Queries the Shodan API for exposed ports and services on each IP.
- **IP Reputation Checks:** Uses the VirusTotal API to flag malicious IPs based on aggregated security vendor data.
- **Risk Scoring:** Classifies each host from LOW to MEDIUM to HIGH to CRITICAL based on open ports, dangerous services, and reputation flags.
- **Modular Architecture:** Built to plug in additional intelligence sources, with stub integrations for Censys and GreyNoise ready to enable via API keys.
- **Dual Format Reporting:** Outputs report.json for automation and report.md for human-readable security review.
- **Performance:** Scans 100+ subdomains in approximately 1 minute on standard free tier API limits.

---

## Usage

Install dependencies:

    pip3 install shodan requests

Run a scan:

    python3 gameguard.py --domain example.com --shodan-key YOUR_SHODAN_KEY --vt-key YOUR_VT_KEY

Optional intelligence sources:

    --censys-id YOUR_CENSYS_ID --censys-secret YOUR_CENSYS_SECRET --greynoise-key YOUR_GREYNOISE_KEY

---

## Output

report.json structured output for automation pipelines.

report.md clean Markdown report for security teams.

Each entry includes the subdomain, resolved IP, open ports from Shodan, Censys ports if enabled, GreyNoise classification if enabled, VirusTotal malicious flag count, and final risk classification.

---

## Risk Scoring Logic

- Dangerous ports such as 21, 22, 23, 3389, 4444, and 8080 add 2 points each.
- Other open ports add 1 point each.
- Each VirusTotal malicious flag adds 3 points.

| Score | Risk Level |
|-------|------------|
| 0 | LOW |
| 1 to 3 | MEDIUM |
| 4 to 7 | HIGH |
| 8+ | CRITICAL |

---

## Relevance

External attack surface enumeration, threat intelligence aggregation, and automated security reporting are core to security operations, penetration testing, and risk assessment workflows.

---

## License

Open source for educational use.
