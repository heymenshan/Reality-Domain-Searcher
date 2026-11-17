#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Automatic VPS TCP reachability monitor.

Python 3.10+. Standard library only.
No prompts, no external dependencies, English output.
"""

import argparse
import csv
import ipaddress
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
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


def main() -> int:
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

    args = parser.parse_args()

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


if __name__ == "__main__":
    raise SystemExit(main())
