# Reality Domain Searcher

Run on the VPS where you plan to use REALITY. Python 3.10+ with TLS 1.3 support is required.

```bash
git clone https://github.com/heymenshan/Reality-Domain-Searcher.git
cd Reality-Domain-Searcher
python3 scanner.py
```

The default scan takes up to 1,000 candidates from Tranco. It checks whether each candidate negotiates TLS 1.3 and HTTP/2 with a trusted certificate for the hostname. It prints up to 50 passing domains, ranked by TCP connection time from the VPS to port 443. Each row also shows the tested IP and its ICMP ping. A dash means the system ping command was unavailable or no ICMP reply was received. The search prints results in the terminal.

```bash
python3 scanner.py --top 50 --limit 3000
python3 scanner.py --domains domains.txt
python3 scanner.py --help
```

A local candidate file may contain one hostname per line or `rank,hostname` CSV rows. All measurements are from the VPS. Candidate checks cover TLS 1.3, certificate validation and HTTP/2. REALITY client connectivity, X25519, OCSP and mainland-China reachability require separate verification.

## VPS port monitoring

The Check-Host monitor checks inbound TCP reachability to the VPS and writes a CSV report. Mainland-China results depend on node availability.

```bash
python3 scanner.py monitor
python3 scanner.py monitor --ip YOUR_VPS_IP --port 443
python3 scanner.py monitor --help
```
