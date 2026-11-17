#!/usr/bin/env python3
import argparse
import csv
import ipaddress
import json
import re
import socket
import statistics
import subprocess
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from pathlib import Path

ROUNDS = 10
TIMEOUT = 10
MIN_SUCCESS = 0.90

def public_ipv4():
    req = urllib.request.Request(
        "https://api.ipify.org",
        headers={"User-Agent": "RealityNeighborScanner/1.0"}
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode().strip()

@lru_cache(maxsize=2048)
def network_info(ip):
    url = (
        "https://stat.ripe.net/data/network-info/data.json?"
        + urllib.parse.urlencode({
            "resource": ip,
            "sourceapp": "reality-neighbor-scanner"
        })
    )
    with urllib.request.urlopen(url, timeout=10) as r:
        data = json.load(r)["data"]

    return {
        "asns": {int(n) for n in data.get("asns", [])},
        "prefix": data.get("prefix") or ""
    }

def resolve_ipv4(domain):
    try:
        return sorted({
            info[4][0]
            for info in socket.getaddrinfo(
                domain, 443, family=socket.AF_INET,
                type=socket.SOCK_STREAM
            )
        })
    except (socket.gaierror, OSError):
        return []

def ptr_candidates(vps_ip):
    # Passive reverse-DNS lookups within the VPS's /24.
    network = ipaddress.ip_network(vps_ip + "/24", strict=False)
    addresses = [str(ip) for ip in network.hosts()]

    def lookup(ip):
        try:
            name = socket.gethostbyaddr(ip)[0].rstrip(".").lower()
            return name if "." in name else None
        except (OSError, socket.herror):
            return None

    with ThreadPoolExecutor(max_workers=12) as pool:
        return sorted({name for name in pool.map(lookup, addresses) if name})

def tls_probe(domain, ip):
    cmd = [
        "openssl", "s_client",
        "-connect", f"{ip}:443",
        "-servername", domain,
        "-verify_hostname", domain,
        "-verify_return_error",
        "-tls1_3",
        "-alpn", "h2",
        "-groups", "X25519",
        "-brief"
    ]
    try:
        result = subprocess.run(
            cmd, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=TIMEOUT
        )
        out = result.stdout + result.stderr
        checks = {
            "tls13": bool(re.search(r"TLSv1\.3", out)),
            "h2": bool(re.search(r"ALPN protocol:\s*h2\b", out, re.I)),
            "x25519": bool(re.search(r"Server Temp Key:\s*X25519\b", out, re.I)),
            "cert": bool(re.search(
                r"(Verification:\s*OK|Verify return code:\s*0\s*\(ok\))",
                out, re.I
            )),
        }
        passed = result.returncode == 0 and all(checks.values())
        return passed, checks
    except (subprocess.TimeoutExpired, OSError):
        return False, {}

def http_probe(domain, ip):
    cmd = [
        "curl", "--noproxy", "*",
        "-sS", "-L",
        "--max-redirs", "0",
        "--connect-timeout", "6",
        "--max-time", str(TIMEOUT),
        "--http2",
        "--tlsv1.3", "--tls-max", "1.3",
        "--resolve", f"{domain}:443:{ip}",
        "-o", "/dev/null",
        "-w", "%{http_code}|%{http_version}",
        f"https://{domain}/"
    ]
    # Disable redirect following regardless of other curl defaults.
    cmd.remove("-L")

    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=TIMEOUT + 2
        )
        code, version = p.stdout.strip().split("|", 1)
        status = int(code)
        return p.returncode == 0 and 200 <= status < 300 \
            and version.startswith("2"), status
    except (ValueError, OSError, subprocess.TimeoutExpired):
        return False, 0

def check_domain(domain, vps_info):
    ips = resolve_ipv4(domain)
    if not ips:
        return None, "DNS 실패"

    choices = []
    for ip in ips:
        try:
            info = network_info(ip)
        except Exception:
            continue

        common = info["asns"] & vps_info["asns"]
        if not common:
            continue

        same_prefix = (
            bool(vps_info["prefix"])
            and ipaddress.ip_address(ip)
            in ipaddress.ip_network(vps_info["prefix"], strict=False)
        )
        choices.append((not same_prefix, ip, info, same_prefix))

    if not choices:
        return None, "동일 ASN IP 없음"

    choices.sort()

    # Prefer a same-prefix IPv4 address if available.
    _, ip, info, same_prefix = choices[0]

    latencies = []
    failures = 0

    for _ in range(ROUNDS):
        start = __import__("time").perf_counter()
        passed, checks = tls_probe(domain, ip)
        elapsed = (__import__("time").perf_counter() - start) * 1000
        if passed:
            latencies.append(elapsed)
        else:
            failures += 1

    rate = len(latencies) / ROUNDS
    if rate < MIN_SUCCESS:
        return None, f"TLS 통과율 {rate:.0%}"

    http_ok, status = http_probe(domain, ip)
    if not http_ok:
        return None, f"HTTP 미통과 (상태 {status})"

    return {
        "domain": domain,
        "ip": ip,
        "asn": ",".join(str(n) for n in sorted(info["asns"])),
        "same_prefix": same_prefix,
        "success_rate": f"{rate:.0%}",
        "median_tls_ms": round(statistics.median(latencies), 1),
        "http_status": status,
        "target": domain + ":443",
        "sni": domain,
    }, "PASS"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ip", help="VPS public IPv4; auto-detect if omitted"
    )
    parser.add_argument(
        "--discover-ptr", action="store_true",
        help="Add PTR-derived names from the local /24"
    )
    args = parser.parse_args()

    vps_ip = args.ip or public_ipv4()
    vps_info = network_info(vps_ip)

    if not vps_info["asns"]:
        raise SystemExit("VPS ASN을 확인할 수 없습니다.")

    print(f"VPS: {vps_ip}")
    print(f"ASN: {sorted(vps_info['asns'])}")
    print(f"BGP prefix: {vps_info['prefix']}")

    candidate_file = Path("candidates.txt")
    if not candidate_file.exists():
        candidate_file.write_text(
            "# One candidate hostname per line\n",
            encoding="utf-8"
        )

    domains = {
        line.strip().lower()
        for line in candidate_file.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    if args.discover_ptr:
        print("PTR 도메인 후보 탐색 중...")
        domains.update(ptr_candidates(vps_ip))

    domains = sorted(
        d for d in domains
        if re.fullmatch(
            r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", d
        ) and "." in d and len(d) <= 253
    )

    print(f"후보 도메인: {len(domains)}개\n")

    results = []
    for i, domain in enumerate(domains, 1):
        try:
            result, reason = check_domain(domain, vps_info)
        except Exception as exc:
            result, reason = None, str(exc)[:90]

        if result:
            results.append(result)
            print(
                f"[{i}/{len(domains)}] PASS {domain} "
                f"{result['median_tls_ms']}ms "
                f"same-prefix={result['same_prefix']}"
            )
        else:
            print(f"[{i}/{len(domains)}] FAIL {domain}: {reason}")

    results.sort(
        key=lambda x: (
            not x["same_prefix"],
            x["median_tls_ms"]
        )
    )

    fields = [
        "domain", "ip", "asn", "same_prefix",
        "success_rate", "median_tls_ms",
        "http_status", "target", "sni"
    ]

    with open("results.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)

    print("\n========== 통과한 도메인 ==========")
    for i, r in enumerate(results, 1):
        print(
            f"{i}. {r['domain']} | {r['ip']} | "
            f"{r['median_tls_ms']}ms | "
            f"same-prefix={r['same_prefix']}"
        )

    print(f"\n통과: {len(results)}개 / {len(domains)}개")
    print("결과 저장: results.csv")

if __name__ == "__main__":
    main()
