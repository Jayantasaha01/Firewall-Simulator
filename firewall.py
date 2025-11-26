#!/usr/bin/env python3
import json, sys

RULES = [
    {"action": "DROP", "range": ["203.0.113.0", "203.0.113.255"]},
    {"action": "ALLOW", "range": ["10.0.0.0", "10.255.255.255"]}
]

def check_ip(ip):
    import ipaddress
    ip_obj = ipaddress.ip_address(ip)

    for r in RULES:
        start = ipaddress.ip_address(r["range"][0])
        end = ipaddress.ip_address(r["range"][1])
        if start <= ip_obj <= end:
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