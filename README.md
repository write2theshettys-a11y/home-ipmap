# home-ipmap

Small Flask app to ARP-scan a local IPv4 subnet and show which IPs are assigned.

## Features
- ARP scan using Scapy to detect assigned IPs on the same L2 network
- MAC vendor lookup (via macvendors.com) with caching
- Simple web UI (Flask) to enter a subnet (CIDR) and view results

## Prerequisites
- macOS / Linux with root privileges for raw ARP packets
- Python 3.8+
- `sudo` access (the app checks for root and will raise if not run as root)

## Install
1. (Recommended) Create a virtual environment and activate it:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Run
Because ARP scanning requires raw sockets, run the app with root privileges:

```bash
sudo python3 app.py
```

Then open `http://localhost:5000/` and enter a subnet (for example `192.168.1.0/24`).

Alternatively, call the scanner directly from Python:

```bash
sudo python3 -c "from app import scan_subnet; print(scan_subnet('192.168.1.0/24'))"
```

## Notes & Caveats
- ARP scanning only detects hosts on the same layer-2 network segment (same VLAN). It will not discover hosts behind routers.
- Some devices may not reply to ARP (firewalled/sleeping), resulting in false negatives.
- The app performs MAC vendor lookups using `https://api.macvendors.com/` and caches results; frequent scans may hit API rate limits.
- By default `scan_subnet` enforces a `max_hosts` limit (1024) to avoid flooding large networks. Adjust this parameter only if you understand the network impact.

## Configuration tips
- Increase `max_hosts` or `timeout` by calling `scan_subnet(subnet, timeout=5, max_hosts=4096)` if needed.
- Consider combining ARP with ICMP (ping sweep), reading OS ARP cache, or integrating `nmap`/SNMP/DHCP lease files for more comprehensive discovery.

## Development
- Main source: `app.py`
- Templates: `templates/index.html`

## License
MIT-style, use at your own risk. No warranty.
