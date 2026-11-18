# Reality Domain Searcher

Run on the VPS where you plan to use REALITY. Python 3.10+ with TLS 1.3 support is required.

```bash
git clone https://github.com/heymenshan/Reality-Domain-Searcher.git
cd Reality-Domain-Searcher
python3 scanner.py
```

The default scan takes up to 1,000 candidates from Tranco. It checks whether each candidate negotiates TLS 1.3 and HTTP/2 with a trusted certificate for the hostname. It selects up to 50 domains by VPS TCP connection time to port 443, then sends HTTPS HEAD requests from up to three mainland-China Globalping probes per domain. It prints only domains with a 2xx or 3xx response from at least one mainland probe. Each row shows the VPS-tested IP, its ICMP ping, and the successful Chinese probe cities and HTTP status codes. A dash means the system ping command was unavailable or no ICMP reply was received. The search prints results in the terminal.

```bash
python3 scanner.py --top 50 --limit 3000
python3 scanner.py --domains domains.txt
python3 scanner.py --help
```

A local candidate file may contain one hostname per line or `rank,hostname` CSV rows. A redirect code confirms that the initial host responded. Results depend on probe availability and API rate limits. Domains with missing or unsuccessful measurements are omitted and the scanner exits with status 1 if no domain is confirmed. Set `GLOBALPING_TOKEN` if you want to use an authenticated quota. REALITY client connectivity, X25519, and OCSP require separate verification.

## VPS port monitoring

The Check-Host monitor checks inbound TCP reachability to the VPS and writes a CSV report. Mainland-China results depend on node availability.

```bash
python3 scanner.py monitor
python3 scanner.py monitor --ip YOUR_VPS_IP --port 443
python3 scanner.py monitor --help
```
