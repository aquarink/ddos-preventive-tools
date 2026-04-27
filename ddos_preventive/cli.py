import argparse
import os
import shlex
import subprocess
import sys
from collections import Counter
from pathlib import Path

from ddos_preventive.detector import DDoSDetector
from ddos_preventive.firewall import block_ip
from ddos_preventive.log_parser import iter_log_entries
from ddos_preventive.models import DEFAULT_DB_PATH, DetectionConfig
from ddos_preventive.stream import iter_stdin_entries


def parse_csv_set(value, transform=str):
    if not value:
        return set()
    return {transform(item.strip()) for item in value.split(",") if item.strip()}


def build_parser():
    parser = argparse.ArgumentParser(
        description="Detect suspicious DDoS patterns from Nginx/Apache-style access logs."
    )
    parser.add_argument("--log-dir", default=None, help="Directory containing *.log files.")
    parser.add_argument(
        "--log-file",
        action="append",
        default=[],
        help="Read one log file. Can be used multiple times.",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read access log lines from stdin for streaming use with tail -F.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print detection flags and request details without calling any firewall backend.",
    )
    parser.add_argument("--enforce", action="store_true", help="Actually apply firewall blocks.")
    parser.add_argument(
        "--firewall",
        choices=("print", "firewalld", "iptables", "nft"),
        default="print",
        help="Firewall backend. Default only prints actions.",
    )
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--rate-limit", type=int, default=120)
    parser.add_argument("--same-path-limit", type=int, default=60)
    parser.add_argument("--error-limit", type=int, default=30)
    parser.add_argument("--unique-path-limit", type=int, default=80)
    parser.add_argument("--max-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-query-length", type=int, default=1_024)
    parser.add_argument(
        "--allowed-methods",
        default="GET,POST,HEAD,OPTIONS",
        help="Comma separated HTTP methods that are considered normal.",
    )
    parser.add_argument(
        "--allowed-countries",
        default="",
        help="Comma separated ISO country codes. Enables country allow-list checking.",
    )
    parser.add_argument(
        "--db-path",
        default=os.getenv("IPINFO_DB", str(DEFAULT_DB_PATH)),
        help="SQLite cache path for IP country lookups.",
    )
    parser.add_argument(
        "--ipinfo-token",
        default=os.getenv("IPINFO_TOKEN", ""),
        help="ipinfo.io token. Prefer setting IPINFO_TOKEN instead of passing this directly.",
    )
    return parser


def build_config(args):
    allowed_countries = parse_csv_set(args.allowed_countries, str.upper)
    return DetectionConfig(
        max_bytes=args.max_bytes,
        rate_limit=args.rate_limit,
        same_path_limit=args.same_path_limit,
        error_limit=args.error_limit,
        unique_path_limit=args.unique_path_limit,
        window_seconds=args.window_seconds,
        max_query_length=args.max_query_length,
        allowed_methods=parse_csv_set(args.allowed_methods, str.upper),
        allowed_countries=allowed_countries,
        country_check=bool(allowed_countries),
        db_path=Path(args.db_path),
        ipinfo_token=args.ipinfo_token,
    )


def iter_entries_from_args(args):
    if args.stdin:
        return iter_stdin_entries()

    log_dir = args.log_dir
    if not args.log_file and not log_dir:
        log_dir = "/var/log/nginx"

    entries = iter_log_entries(args.log_file, log_dir)
    return sorted(entries, key=lambda item: item.timestamp)


def format_debug_detection(entry, reasons):
    fields = {
        "flag": "DDOS_DETECTED",
        "action": "debug_only",
        "ip": entry.ip,
        "domain": entry.domain,
        "timestamp": entry.timestamp.isoformat(),
        "method": entry.method,
        "path": entry.path,
        "status": str(entry.status_code),
        "bytes": str(entry.bytes_sent),
        "reasons": ", ".join(reasons),
        "user_agent": entry.user_agent,
    }
    return " ".join(f"{key}={shlex.quote(value)}" for key, value in fields.items())


def main(argv=None):
    args = build_parser().parse_args(argv)
    config = build_config(args)
    detector = DDoSDetector(config)
    blocked = {}
    detected_ips = set()
    detected_events = 0
    reason_counter = Counter()
    backend = args.firewall if args.enforce else "print"

    try:
        for entry in iter_entries_from_args(args):
            is_attack, reasons = detector.detect(entry)
            if not is_attack:
                continue

            detected_events += 1
            detected_ips.add(entry.ip)
            reason_counter.update(reasons)

            if args.debug:
                print(format_debug_detection(entry, reasons), flush=True)
                continue

            if entry.ip in blocked:
                continue

            blocked[entry.ip] = reasons
            block_ip(entry.ip, backend)
            action = "blocked" if args.enforce else "would be blocked"
            print(f"IP {entry.ip} {action}. Reason: {', '.join(reasons)}", flush=True)
    except (FileNotFoundError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not detected_events:
        print("No attack detected.")
    elif args.debug:
        print("\nSummary:")
        print(f"- detected events: {detected_events}")
        print(f"- detected IPs: {len(detected_ips)}")
        for reason, count in reason_counter.most_common():
            print(f"- {reason}: {count}")
    else:
        print("\nSummary:")
        label = "blocked IPs" if args.enforce else "IPs that would be blocked"
        print(f"- {label}: {len(blocked)}")
        for reason, count in reason_counter.most_common():
            print(f"- {reason}: {count}")
    return 0
