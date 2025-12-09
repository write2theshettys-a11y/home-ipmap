from flask import Flask, render_template, request
from scapy.all import ARP, Ether, srp
from functools import lru_cache
import requests
import ipaddress
import os

app = Flask(__name__)

# ----------------------------------
# Vendor Lookup via macvendors.com
# ----------------------------------
@lru_cache(maxsize=5000)
def lookup_vendor(mac):
    if not mac or mac == "-":
        return "Unknown Vendor"

    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text.strip()
        return "Unknown Vendor"
    except Exception:
        return "Unknown Vendor"

# ----------------------------------
# Device Type Inference with Icons
# ----------------------------------
def infer_device_type(vendor):
    if not vendor or vendor == "Unknown Vendor":
        return "Unknown", "fa-question-circle"

    v = vendor.lower()

    if "apple" in v:
        return "Apple / Mac / iPhone / iPad", "fa-apple"
    if "samsung" in v:
        return "Samsung Device", "fa-tv"
    if "amazon" in v:
        return "Amazon Smart Device", "fa-amazon"
    if "tp-link" in v or "ubiquiti" in v:
        return "Network Switch / Access Point", "fa-network-wired"
    if "lg" in v:
        return "LG Smart TV", "fa-tv"
    if "intel" in v:
        return "Computer Hardware", "fa-desktop"
    if "cisco" in v or "aruba" in v:
        return "Enterprise Network Device", "fa-server"

    return "Generic Network Device", "fa-ethernet"

# ----------------------------------
# ARP Scan Using Scapy
# ----------------------------------
def scan_subnet(subnet, timeout=2, max_hosts=1024):
    """Scan an IPv4 subnet using ARP.

    Notes:
    - Requires root privileges to send raw ARP packets.
    - Only usable host addresses are scanned (network/broadcast excluded).
    - For large networks this will raise unless `max_hosts` is increased.
    """

    print(f"Scanning {subnet} ...")

    # Basic privilege check
    if os.geteuid() != 0:
        raise PermissionError("Root privileges are required to perform an ARP scan. Run with sudo.")

    # Validate and enumerate hosts (usable addresses only)
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except Exception as e:
        raise ValueError(f"Invalid subnet '{subnet}': {e}") from e

    # Only IPv4 supported by this scanner
    if net.version != 4:
        raise ValueError("Only IPv4 subnets are supported")

    hosts = list(str(h) for h in net.hosts())

    if len(hosts) == 0:
        raise ValueError("No usable hosts in the provided subnet")

    if len(hosts) > max_hosts:
        raise ValueError(f"Subnet is too large ({len(hosts)} hosts). Increase `max_hosts` to proceed if desired.")

    # Build and send ARP packet (pdst accepts a CIDR or a list)
    arp = ARP(pdst=str(net))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    answered, _ = srp(packet, timeout=timeout, verbose=False)

    active = {}

    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc

        vendor = lookup_vendor(mac)
        dtype, icon = infer_device_type(vendor)

        active[ip] = {
            "ip": ip,
            "assigned": True,
            "mac": mac,
            "vendor": vendor,
            "device_type": dtype,
            "icon": icon
        }

    # Fill in inactive IPs
    results = []
    for ip in hosts:
        if ip in active:
            results.append(active[ip])
        else:
            results.append({
                "ip": ip,
                "assigned": False,
                "mac": "-",
                "vendor": "-",
                "device_type": "-",
                "icon": "fa-circle-minus"
            })

    # Sort: Assigned first, then numeric IP order
    results.sort(key=lambda x: (not x["assigned"], int(ipaddress.ip_address(x["ip"]))))

    # Summary counts
    summary = {
        "total": len(results),
        "assigned": sum(1 for r in results if r["assigned"]),
        "unassigned": sum(1 for r in results if not r["assigned"])
    }

    return results, summary

# ----------------------------------
# Flask Route
# ----------------------------------
@app.route("/", methods=["GET", "POST"])
def home():
    data = None
    subnet = None
    summary = None

    if request.method == "POST":
        subnet = request.form.get("subnet")
        try:
            data, summary = scan_subnet(subnet)
        except Exception as e:
            return render_template("index.html", error=str(e))

    return render_template("index.html", data=data, subnet=subnet, summary=summary)


if __name__ == "__main__":
    print("Run this app with: sudo python3 app.py")
    app.run(host="0.0.0.0", port=5000, debug=True)

