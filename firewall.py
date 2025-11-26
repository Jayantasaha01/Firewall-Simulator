#!/usr/bin/env python3
import json, sys

RULES = [
    # Block traffic from this IP range
    {"action": "DROP", "src":"10.0/24.0/24.0/24"},
    # Allow traffic from this IP range
    {"action": "ALLOW", "src": "203.0.113.0/24"}
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
    packets_file = sys.argv[1] if len(sys.argv) > 1 else "packets.json"
    simulate(packets_file)