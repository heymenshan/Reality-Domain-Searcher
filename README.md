# Reality Domain Searcher

A Python tool for Reality SNI analysis and VPS TCP connectivity monitoring.

## Features

- Automatic VPS public IP detection
- ASN and BGP network analysis
- Reality SNI candidate validation
- TLS 1.3, HTTP/2, X25519 and certificate checks
- Global TCP connectivity testing via Check-Host
- Mainland China blocking assessment when test nodes are available
- CSV result export
- English output

## Installation

```bash
git clone https://github.com/heymenshan/Reality-Domain-Searcher.git
cd Reality-Domain-Searcher
```

## Usage

Run directly on your VPS:

```bash
python3 scanner.py
```

Specify a VPS IP:

```bash
python3 scanner.py --ip YOUR_VPS_IP
```

View available options:

```bash
python3 scanner.py --help
```

## Results

- `REACHABLE` — TCP connection successful
- `BLOCKED SUSPECTED` — Mainland China connection failure while overseas connectivity succeeds
- `CHINA UNKNOWN` — No mainland China test nodes available
- `UNKNOWN` — Insufficient test data

Results are exported to CSV files.

## Notes

- Python 3.10+ required.
- Mainland China test nodes may not be available.
- TCP connectivity does not guarantee VLESS-Reality connectivity.
- The latest changes must be committed and pushed to GitHub before cloning or updating the repository on another VPS.