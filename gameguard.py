import json
import time

# Placeholder list of subdomains
subdomains = ["example1.com", "example2.com", "example3.com"]

def scan_subdomains(subdomains):
    report = {}
    for sub in subdomains:
        print(f"Scanning {sub}...")
        time.sleep(0.5)
        # Dummy data
        report[sub] = {
            "open_ports": [22, 80],
            "ip_reputation": "SAFE"
        }
    return report

def generate_reports(report):
    with open("report.json", "w") as f:
        json.dump(report, f, indent=4)
    with open("report.md", "w") as f:
        f.write("# Scan Report\n")
        for sub, info in report.items():
            f.write(f"## {sub}\n")
            f.write(f"Open Ports: {info['open_ports']}\n")
            f.write(f"IP Reputation: {info['ip_reputation']}\n\n")

if __name__ == "__main__":
    result = scan_subdomains(subdomains)
    generate_reports(result)
    print("Scan complete. Reports generated: report.json, report.md")