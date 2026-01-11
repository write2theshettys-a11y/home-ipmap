from flask import Flask, render_template, request
from scapy.all import ARP, Ether, srp
from functools import lru_cache
from mac_vendor_lookup import MacLookup
import requests
import ipaddress
import os

app = Flask(__name__)

# ----------------------------------
# Vendor Lookup via local database
# ----------------------------------
# Initialize MacLookup
mac_lookup = MacLookup()

def update_vendor_db():
    try:
        print("Updating MAC Vendor Database...")
        mac_lookup.update_vendors()
        print("MAC Vendor Database updated.")
    except Exception as e:
        print(f"Failed to update MAC Vendor Database: {e}")

# Check if we need to update (simple check if file exists approx logic, 
# but the library handles caching. We'll force update on start if desired, 
# or just let it use what it has. For robustness, let's try to load, 
# and if it fails to find common vendors, we might want to update.
# A safe bet is to try to update once on startup or let user trigger it.
# For now, we will attempt to update if we can't find a common vendor or just once.)
# Actually, the library keeps it in a standard location. 
# Let's just try to update on startup in a non-blocking way or just synchronous for now.
# Since this is a simple app, we can do it on module load if we want generally up to date info.
try:
    # Check if we can find a known MAC. If not, maybe we need to download.
    mac_lookup.lookup("00:00:00:00:00:00")
except Exception:
    # If it fails significantly (like file missing), try update
    update_vendor_db()

@lru_cache(maxsize=5000)
def lookup_vendor(mac):
    """Return vendor information for a MAC address using local database.

    Returns a dict: {"vendor": str, "carrier": str}
    Carrier info is not provided by mac-vendor-lookup, so it will be '-'.
    """
    if not mac or mac == "-":
        return {"vendor": "Unknown Vendor", "carrier": "-"}

    try:
        vendor = mac_lookup.lookup(mac)
        return {"vendor": vendor, "carrier": "-"}
    except Exception:
        return {"vendor": "Unknown Vendor", "carrier": "-"}

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

        vendor_info = lookup_vendor(mac)
        vendor = vendor_info.get("vendor", "Unknown Vendor")
        carrier = vendor_info.get("carrier", "-")
        dtype, icon = infer_device_type(vendor)

        active[ip] = {
            "ip": ip,
            "assigned": True,
            "mac": mac,
            "vendor": vendor,
            "carrier": carrier,
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
                "carrier": "-",
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

