#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""REALITY domain search and optional VPS TCP reachability monitor.

Python 3.10+. Standard library only.
No prompts, no external dependencies, English output.
"""

import argparse
import csv
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

API = "https://check-host.net"
DEFAULT_OUTPUT = Path("monitor_results.csv")
MAX_POLLS = 10
POLL_SECONDS = 3

FIELDS = [
    "checked_at",
    "ip",
    "port",
    "node",
    "country_code",
    "country",
    "city",
    "status",
    "latency_ms",
    "error",
    "verdict",
]


def api_json(url: str, timeout: int = 15) -> dict:
    req = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "VPS-TCP-Monitor/2.1",
        },
    )
    with urlopen(req, timeout=timeout) as response:
        return json.load(response)


def validate_ip(ip: str) -> str:
    address = ipaddress.IPv4Address(ip)
    if not address.is_global:
        raise ValueError("A public IPv4 address is required.")
    return str(address)


def detect_public_ip() -> str:
    sources = [
        "https://api.ipify.org?format=json",
        "https://api4.ipify.org?format=json",
    ]

    for url in sources:
        try:
            ip = api_json(url, timeout=8)["ip"]
            return validate_ip(ip)
        except (OSError, ValueError, KeyError, TypeError):
            continue

    raise RuntimeError("Public IPv4 detection failed.")


def select_nodes() -> tuple[dict, list[str]]:
    data = api_json(f"{API}/nodes/hosts")
    catalog = data.get("nodes", {})

    if not isinstance(catalog, dict) or not catalog:
        raise RuntimeError("No Check-Host nodes available.")

    china = []
    overseas = []

    for node, metadata in catalog.items():
        location = metadata.get("location", [])
        if not location:
            continue

        country_code = str(location[0]).upper()

        if country_code == "CN":
            china.append(node)
        elif country_code not in {"HK", "MO", "TW"}:
            overseas.append(node)

    # Include up to 15 mainland-China nodes.
    selected = china[:15]

    # Add up to 10 geographically distinct overseas nodes.
    seen_countries = set()
    for node in overseas:
        country_code = catalog[node]["location"][0].upper()
        if country_code in seen_countries:
            continue
        seen_countries.add(country_code)
        selected.append(node)
        if len(selected) >= 25:
            break

    if not selected:
        raise RuntimeError("No suitable checking nodes.")

    return catalog, selected


def start_check(ip: str, port: int, selected: list[str]) -> dict:
    params = [
        ("host", f"{ip}:{port}"),
        ("max_nodes", str(len(selected))),
    ]
    params.extend(("node", node) for node in selected)

    result = api_json(
        f"{API}/check-tcp?{urlencode(params)}",
        timeout=20,
    )

    if not result.get("ok") or not result.get("request_id"):
        raise RuntimeError("Check-Host rejected the request.")

    return result


def parse_tcp(value) -> tuple[str, float | str, str]:
    """Return (status, latency_ms, error) where status is PASS, FAIL, or PENDING."""
    if not isinstance(value, list) or not value:
        return "PENDING", "", ""

    times = []
    errors = []

    for sample in value:
        if not isinstance(sample, dict):
            continue

        if "error" in sample:
            errors.append(str(sample["error"]))

        elif isinstance(sample.get("time"), (int, float)):
            latency = sample["time"]
            if not isinstance(latency, bool) and latency >= 0:
                times.append(float(latency) * 1000)

    if errors:
        return "FAIL", "", "; ".join(errors)

    if times:
        return "PASS", round(min(times), 2), ""

    return "PENDING", "", ""


def poll_results(request_id: str, nodes: dict) -> dict:
    results = {}

    for attempt in range(MAX_POLLS):
        if attempt:
            time.sleep(POLL_SECONDS)

        response = api_json(f"{API}/check-result/{request_id}")

        if isinstance(response, dict):
            results.update(response)

        completed = sum(
            parse_tcp(results.get(node))[0] != "PENDING"
            for node in nodes
        )

        print(
            f"Checking: {completed}/{len(nodes)} "
            f"(attempt {attempt + 1}/{MAX_POLLS})"
        )

        if completed == len(nodes):
            break

    return results


def make_rows(ip: str, port: int, nodes: dict, results: dict) -> list[dict]:
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows = []

    for node, metadata in nodes.items():
        location = (
            metadata
            if isinstance(metadata, list)
            else metadata.get("location", [])
            if isinstance(metadata, dict)
            else []
        )

        country_code = str(location[0]).upper() if len(location) > 0 else "UNKNOWN"
        country = str(location[1]) if len(location) > 1 else ""
        city = str(location[2]) if len(location) > 2 else node

        status, latency, error = parse_tcp(results.get(node))

        rows.append({
            "checked_at": checked_at,
            "ip": ip,
            "port": port,
            "node": node,
            "country_code": country_code,
            "country": country,
            "city": city,
            "status": status,
            "latency_ms": latency,
            "error": error,
        })

    return rows


def assess(rows: list[dict]) -> str:
    china = [row for row in rows if row["country_code"] == "CN"]
    overseas = [
        row for row in rows
        if row["country_code"] not in {"CN", "HK", "MO", "TW", "UNKNOWN"}
    ]

    if not china:
        return "CHINA UNKNOWN"

    china_fail = any(row["status"] == "FAIL" for row in china)
    china_pass = any(row["status"] == "PASS" for row in china)
    overseas_pass = any(row["status"] == "PASS" for row in overseas)
    overseas_fail = any(row["status"] == "FAIL" for row in overseas)

    if china_fail and overseas_pass:
        return "BLOCKED SUSPECTED"

    if china_fail:
        return "CHINA FAILURE - VERIFY SERVER"

    if china_pass and overseas_pass:
        if overseas_fail:
            return "PARTIAL CONNECTIVITY"
        return "REACHABLE"

    if china_pass:
        return "CHINA REACHABLE - OVERSEAS UNKNOWN"

    return "UNKNOWN"


def save_csv(rows: list[dict], verdict: str, output_path: Path) -> None:
    write_header = not output_path.exists() or output_path.stat().st_size == 0

    with output_path.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)

        if write_header:
            writer.writeheader()

        for row in rows:
            writer.writerow({**row, "verdict": verdict})


def print_report(rows: list[dict], verdict: str, link: str, output_path: Path) -> None:
    print()
    print("=" * 72)
    print(f"{'CODE':<6} {'COUNTRY / CITY':<34} {'STATUS':<10} {'LATENCY':>10}")
    print("-" * 72)

    for row in rows:
        location = f"{row['country']} - {row['city']}".strip(" -") or row["node"]
        latency = f"{row['latency_ms']} ms" if row["latency_ms"] != "" else "-"

        print(
            f"{row['country_code']:<6} "
            f"{location[:34]:<34} "
            f"{row['status']:<10} "
            f"{latency:>10}"
        )

    china_count = sum(row["country_code"] == "CN" for row in rows)

    print("=" * 72)
    print(f"CHINA NODES : {china_count}")
    print(f"TOTAL NODES : {len(rows)}")
    print(f"VERDICT     : {verdict}")
    print(f"REPORT      : {link or 'N/A'}")
    print(f"CSV         : {output_path.resolve()}")

    if not china_count:
        print("NOTE: No mainland China test nodes were available.")

    print("NOTE: TCP reachability does not verify VLESS-Reality handshakes.")


def monitor_main(argv) -> int:
    parser = argparse.ArgumentParser(
        description="Automatic VPS TCP Reachability Monitor"
    )
    parser.add_argument(
        "--ip",
        default=os.getenv("TARGET_IP"),
        help="Public IPv4 (default: automatic detection)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("TARGET_PORT", "443")),
        help="TCP port (default: 443)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(os.getenv("OUTPUT_CSV", DEFAULT_OUTPUT)),
        help=f"Output CSV path (default: {DEFAULT_OUTPUT})",
    )

    args = parser.parse_args(argv)

    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")

    try:
        ip = validate_ip(args.ip) if args.ip else detect_public_ip()

        print("=" * 55)
        print("AUTOMATIC VPS TCP REACHABILITY MONITOR")
        print("=" * 55)
        print(f"Target : {ip}:{args.port}")
        print("Mode   : Automatic")
        print("Service: Check-Host")
        print()

        _, selected = select_nodes()
        check = start_check(ip, args.port, selected)

        actual_nodes = check.get("nodes", {})
        if not actual_nodes:
            raise RuntimeError("No nodes assigned to check.")

        results = poll_results(check["request_id"], actual_nodes)
        rows = make_rows(ip, args.port, actual_nodes, results)
        verdict = assess(rows)

        save_csv(rows, verdict, args.output)
        print_report(rows, verdict, check.get("permanent_link", ""), args.output)

        return 0

    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1



TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
DOMAIN_PATTERN = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def domain_candidates(source, limit):
    # 读取本地候选名单，或使用最新的 Tranco 排名。
    if source is None:
        request = Request(TRANCO_URL, headers={"User-Agent": "Reality-Domain-Searcher/3.0"})
        with urlopen(request, timeout=20) as response:
            archive = io.BytesIO(response.read(32 * 1024 * 1024 + 1))
        if archive.getbuffer().nbytes > 32 * 1024 * 1024:
            raise ValueError("Downloaded domain list exceeded 32 MiB.")
        with zipfile.ZipFile(archive) as ranked, ranked.open("top-1m.csv") as entries:
            return read_domains(io.TextIOWrapper(entries, encoding="utf-8-sig"), limit)
    with source.open(encoding="utf-8-sig", newline="") as entries:
        return read_domains(entries, limit)


def read_domains(entries, limit):
    domains = {}
    for row in csv.reader(entries):
        if not row:
            continue
        name = row[-1].strip().lower().rstrip(".")
        if len(name) <= 253 and DOMAIN_PATTERN.fullmatch(name):
            domains.setdefault(name, None)
            if len(domains) == limit:
                break
    return list(domains)


def probe_domain(domain, context, timeout):
    # 分开记录 TCP 建连时间，DNS 和 TLS 握手时间不计入。
    try:
        addresses = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
    except OSError:
        return None
    for family, kind, protocol, _, address in addresses[:4]:
        if not ipaddress.ip_address(address[0]).is_global:
            continue
        try:
            with socket.socket(family, kind, protocol) as connection:
                connection.settimeout(timeout)
                started = time.monotonic()
                connection.connect(address)
                tcp_ms = (time.monotonic() - started) * 1000
                with context.wrap_socket(connection, server_hostname=domain) as tls:
                    if tls.selected_alpn_protocol() == "h2":
                        return domain, address[0], tcp_ms
        except OSError:
            continue
    return None


def icmp_ping(address):
    command = "ping6" if ":" in address and sys.platform == "darwin" else "ping"
    try:
        result = subprocess.run(
            [command, "-n", "-c", "1", address], capture_output=True,
            text=True, timeout=2, env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return "-"
    match = re.search(r"time([=<])\s*(\d+(?:\.\d+)?)\s*ms", result.stdout)
    if match:
        prefix = "<" if match[1] == "<" else ""
        return f"{prefix}{match[2]}"
    return "-"



GLOBALPING = "https://api.globalping.io/v1/measurements"


def china_https(domain):
    # 仅接受中国大陆探针返回的有效 HTTPS 响应。
    payload = {
        "type": "http",
        "target": domain,
        "locations": [{"country": "CN"}],
        "limit": 3,
        "measurementOptions": {
            "protocol": "HTTPS",
            "port": 443,
            "request": {"method": "HEAD", "path": "/"},
        },
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    token = os.getenv("GLOBALPING_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        request = Request(GLOBALPING, data=json.dumps(payload).encode(), headers=headers)
        with urlopen(request, timeout=10) as response:
            measurement = json.load(response)
        url = f"{GLOBALPING}/{quote(measurement['id'], safe='')}"
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            time.sleep(1)
            with urlopen(Request(url, headers=headers), timeout=8) as response:
                measurement = json.load(response)
            if measurement.get("status") == "finished":
                break
        else:
            return "", "measurement timed out"
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return "", str(exc)

    mainland = 0
    successes = []
    for entry in measurement.get("results", []):
        probe = entry.get("probe") or {}
        if probe.get("country") != "CN":
            continue
        mainland += 1
        result = entry.get("result") or {}
        if result.get("status") != "finished":
            continue
        code = result.get("statusCode")
        if code is None:
            match = re.search(r"(?m)^HTTP/\S+\s+(\d{3})\b", result.get("rawOutput") or "")
            code = int(match[1]) if match else None
        if str(code).isdigit() and 200 <= int(code) < 400:
            successes.append(f"{probe.get('city') or 'CN'} {code}")
    if not mainland:
        return "", "no mainland China probes"
    if not successes:
        return "", "no successful HTTPS response"
    return ", ".join(dict.fromkeys(successes)), ""


def scan_main(argv):
    parser = argparse.ArgumentParser(description="Rank REALITY domain candidates from this VPS.")
    parser.add_argument("--top", type=int, default=50, help="Maximum results (default: 50)")
    parser.add_argument("--limit", type=int, default=1000, help="Candidate limit (default: 1000)")
    parser.add_argument("--workers", type=int, default=24, help="Parallel probes (default: 24)")
    parser.add_argument("--timeout", type=float, default=2.0, help="TCP/TLS socket timeout in seconds")
    parser.add_argument("--domains", type=Path, help="Local list, one hostname per line or rank,hostname CSV")
    args = parser.parse_args(argv)
    if args.top < 1 or args.limit < 1 or not 1 <= args.workers <= 64 or not 0 < args.timeout <= 30:
        parser.error("Use positive --top and --limit, 1–64 workers, and a timeout of 0–30 seconds.")

    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2"])
    print(f"Loading candidates from {args.domains or 'Tranco'}...", file=sys.stderr, flush=True)
    try:
        domains = domain_candidates(args.domains, args.limit)
    except (OSError, ValueError, KeyError, csv.Error, zipfile.BadZipFile) as exc:
        print(f"Could not load candidates: {exc}", file=sys.stderr)
        return 1
    if not domains:
        print("No domain candidates found.", file=sys.stderr)
        return 1

    print(f"Checking {len(domains)} domains for trusted TLS 1.3 and h2...", file=sys.stderr, flush=True)
    matches = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        pending = [pool.submit(probe_domain, domain, context, args.timeout) for domain in domains]
        for checked, future in enumerate(as_completed(pending), 1):
            result = future.result()
            if result:
                matches.append(result)
            if checked % 100 == 0 or checked == len(domains):
                print(f"Checked {checked}/{len(domains)}; passed {len(matches)}.", file=sys.stderr, flush=True)
        ranked = sorted(matches, key=lambda row: (row[2], row[0]))[:args.top]
    if not ranked:
        print("No VPS candidates passed TLS checks.", file=sys.stderr)
        return 1

    print(f"Checking the top {len(ranked)} candidates from mainland China via Globalping HTTPS...",
          file=sys.stderr, flush=True)
    confirmed = []
    with ThreadPoolExecutor(max_workers=min(args.workers, 5)) as pool:
        pending = {pool.submit(china_https, row[0]): row for row in ranked}
        for future in as_completed(pending):
            row = pending[future]
            evidence, error = future.result()
            if evidence:
                confirmed.append((row, evidence))
            else:
                print(f"{row[0]}: {error}", file=sys.stderr)
        confirmed.sort(key=lambda entry: (entry[0][2], entry[0][0]))
        pings = list(pool.map(icmp_ping, (row[1] for row, _ in confirmed)))

    print(f"{'#':>3}  {'DOMAIN':<36} {'TCP 443 (ms)':>12} {'PING (ms)':>10}  {'IP':<39} CHINA HTTPS")
    for rank, (((domain, address, tcp_ms), evidence), ping_ms) in enumerate(zip(confirmed, pings), 1):
        print(f"{rank:>3}  {domain:<36} {tcp_ms:>12.1f} {ping_ms:>10}  {address:<39} {evidence}")
    print(f"Confirmed {len(confirmed)} of {len(ranked)} candidates from mainland China.", file=sys.stderr)
    return 0 if confirmed else 1


def main():
    argv = sys.argv[1:]
    if argv and argv[0] == "monitor":
        return monitor_main(argv[1:])
    legacy_flags = {"--ip", "--port", "--output"}
    if any(arg.split("=", 1)[0] in legacy_flags for arg in argv):
        return monitor_main(argv)
    return scan_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
