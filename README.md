

# GameGuard – External Attack Surface Monitor

**Technologies:** Python, Shodan API, VirusTotal API, crt.sh, DNS

---

## Overview
GameGuard is a Python CLI tool designed to help monitor and assess the external attack surface of web assets. It automates subdomain discovery, DNS resolution, open-port scanning, and IP reputation checks — all in one streamlined workflow.  

This project demonstrates skills in **cybersecurity, threat intelligence, and automation**, aligning with responsibilities in security operations, monitoring, and risk assessment.

---

## Features
- **Automated Subdomain Discovery:** Uses Certificate Transparency logs (`crt.sh`) to find subdomains.
- **Open-Port & Service Analysis:** Checks exposed ports and services via the Shodan API.
- **IP Reputation Checks:** Looks up IPs through VirusTotal API to flag risky assets.
- **Fast Reporting:** Generates JSON and Markdown reports highlighting vulnerabilities. Scans 100+ subdomains in under 60 seconds.
- **Modular Architecture:** Supports future integration with additional sources like Censys and GreyNoise.
- **Risk Scoring:** Hosts are classified from **LOW → CRITICAL** based on open ports and known CVEs.

---

## Usage

1. Install dependencies:

```bash
pip3 install -r requirements.txt
````

2. Run the CLI:

```bash
python3 gameguard.py
```

3. Output:

* `report.json` → structured data for automation or analysis
* `report.md` → human-readable summary for security teams

---

## Example

```text
Scanning example1.com...
Scanning example2.com...
Scanning example3.com...
Scan complete. Reports generated: report.json, report.md
```

---

## Relevance to Security Operations

This project highlights:

* **Threat / open-source intelligence monitoring**
* **External attack surface enumeration**
* **Data analytics and automation for investigation**
* **Python scripting and modular development for cybersecurity tools**

Perfect for internships in **security operations, penetration testing, or threat intelligence**, like the Rockstar Security Operations Summer 2026 internship.

---

## License

This project is open-source and provided for educational purposes.

````

---

### ✅ **Next Steps to Upload README and Project Properly**

1. Make sure your **`README.md`** and `requirements.txt` are in the project folder.  
2. Add everything to Git:  
```bash
git add .
git commit -m "Add README and finalize GameGuard project"
````

3. Force push again (since GitHub already had conflicts before):

```bash
git push origin main --force
```

