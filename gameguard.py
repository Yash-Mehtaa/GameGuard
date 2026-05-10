import json
import time
import socket
import requests
import shodan
import argparse

def calculate_risk(open_ports, vt_malicious):
    score = 0
    dangerous_ports = [21, 22, 23, 3389, 4444, 8080]
    for port in open_ports:
        if port in dangerous_ports:
            score += 2
        else:
            score += 1
    score += vt_malicious * 3
    if score == 0:
        return "LOW"
    elif score <= 3:
        return "MEDIUM"
    elif score <= 7:
        return "HIGH"
    else:
        return "CRITICAL"

def get_subdomains(domain):
    print(f"[*] Fetching subdomains for {domain} via crt.sh (Certificate Transparency logs)...")
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=15, headers={"Accept": "application/json"})
        data = response.json()
        subdomains = set()
        for entry in data:
            name = entry["name_value"]
            for sub in name.split("\n"):
                if domain in sub and "*" not in sub:
                    subdomains.add(sub.strip())
        found = list(subdomains)
        print(f"[+] Found {len(found)} subdomains")
        return found
    except Exception as e:
        print(f"[-] crt.sh failed: {e}")
        return [domain]

def resolve_ip(subdomain):
    try:
        return socket.gethostbyname(subdomain)
    except:
        return None

def check_shodan(ip, api_key):
    try:
        api = shodan.Shodan(api_key)
        result = api.host(ip)
        ports = [item["port"] for item in result.get("data", [])]
        return ports
    except shodan.APIError:
        return []
    except Exception:
        return []

def check_virustotal(ip, api_key):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0)
    except Exception:
        return 0

def check_censys(ip, api_id=None, api_secret=None):
    # Censys integration ready - plug in API credentials to enable
    if not api_id or not api_secret:
        return []
    try:
        url = f"https://search.censys.io/api/v2/hosts/{ip}"
        response = requests.get(url, auth=(api_id, api_secret), timeout=10)
        data = response.json()
        ports = [s["port"] for s in data.get("result", {}).get("services", [])]
        return ports
    except Exception:
        return []

def check_greynoise(ip, api_key=None):
    # GreyNoise integration ready - plug in API key to enable
    if not api_key:
        return "unknown"
    try:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {"key": api_key}
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()
        return data.get("classification", "unknown")
    except Exception:
        return "unknown"

def generate_reports(report):
    with open("report.json", "w") as f:
        json.dump(report, f, indent=4)
    with open("report.md", "w") as f:
        f.write("# GameGuard Attack Surface Report\n\n")
        for sub, info in report.items():
            f.write(f"## {sub}\n")
            f.write(f"- **IP:** {info['ip']}\n")
            f.write(f"- **Open Ports (Shodan):** {info['open_ports']}\n")
            f.write(f"- **Censys Ports:** {info['censys_ports']}\n")
            f.write(f"- **GreyNoise Classification:** {info['greynoise']}\n")
            f.write(f"- **Malicious Flags (VT):** {info['vt_malicious']}\n")
            f.write(f"- **Risk:** {info['risk']}\n\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GameGuard - CLI Attack Surface Monitor")
    parser.add_argument("--domain", required=True, help="Target domain to scan")
    parser.add_argument("--shodan-key", required=True, help="Shodan API key")
    parser.add_argument("--vt-key", required=True, help="VirusTotal API key")
    parser.add_argument("--censys-id", default=None, help="Censys API ID (optional)")
    parser.add_argument("--censys-secret", default=None, help="Censys API secret (optional)")
    parser.add_argument("--greynoise-key", default=None, help="GreyNoise API key (optional)")
    args = parser.parse_args()

    subdomains = get_subdomains(args.domain)
    print(f"[*] Starting scan on {len(subdomains)} subdomains...")
    report = {}

    for sub in subdomains:
        print(f"[*] Scanning {sub}...")
        ip = resolve_ip(sub)
        if not ip:
            print(f"[-] Could not resolve {sub}, skipping")
            continue
        ports = check_shodan(ip, args.shodan_key)
        vt_malicious = check_virustotal(ip, args.vt_key)
        censys_ports = check_censys(ip, args.censys_id, args.censys_secret)
        greynoise = check_greynoise(ip, args.greynoise_key)
        risk = calculate_risk(ports, vt_malicious)
        report[sub] = {
            "ip": ip,
            "open_ports": ports,
            "censys_ports": censys_ports,
            "greynoise": greynoise,
            "vt_malicious": vt_malicious,
            "risk": risk
        }
        print(f"[+] {sub} | IP: {ip} | Ports: {ports} | Risk: {risk}")
        time.sleep(1)

    generate_reports(report)
    print(f"\n[+] Scan complete. {len(report)} subdomains scanned. Reports saved to report.json and report.md")
