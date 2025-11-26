#!/usr/bin/env python3
import json, sys

RULES = [
    {"action": "DROP", "src": "203.0.113.0/24"},
    {"action": "ALLOW", "src": "10.0.0.0/8"}
]

def check_ip(ip):
    for r in RULES:
        if r["src"].endswith("/24") and ip.startswith(r["src"][:-4]):
            return r["action"]
        if r["src"].endswith("/8") and ip.startswith(r["src"][:-2]):
            return r["action"]
    return "ALLOW"

def simulate(packets_file):
    with open(packets_file) as f:
        for line in f:
            p = json.loads(line)
            action = check_ip(p.get("src_ip"))
            print(f"{p.get('src_ip')} -> {action}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 firewall.py packets.json")
        sys.exit(1)
    simulate(sys.argv[1])
