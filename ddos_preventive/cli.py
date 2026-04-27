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
    parser.add_argument(
        "--burst-rate-limit",
        type=int,
        default=0,
        help="Max requests per IP inside the burst window. 0 disables this rule.",
    )
    parser.add_argument(
        "--burst-window-seconds",
        type=float,
        default=1.0,
        help="Short memory window for burst detection, for example 1 second.",
    )
    parser.add_argument("--same-path-limit", type=int, default=60)
    parser.add_argument("--error-limit", type=int, default=30)
    parser.add_argument("--unique-path-limit", type=int, default=80)
    parser.add_argument(
        "--bandwidth-limit",
        type=int,
        default=100 * 1024 * 1024,
        help="Max bytes per IP within the window before bandwidth abuse is signaled.",
    )
    parser.add_argument("--max-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-query-length", type=int, default=1_024)
    parser.add_argument(
        "--score-threshold",
        type=int,
        default=7,
        help="Minimum score before a detection becomes a block candidate.",
    )
    parser.add_argument(
        "--min-categories",
        type=int,
        default=2,
        help="Minimum distinct signal categories before a block candidate is allowed.",
    )
    parser.add_argument(
        "--ignore-large-response-extensions",
        default="avi,css,gif,jpeg,jpg,js,m4v,mov,mp3,mp4,pdf,png,svg,webm,webp,zip",
        help="Comma separated extensions where one large response is not suspicious by itself.",
    )
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
    ignored_extensions = {
        item.lstrip(".").lower()
        for item in parse_csv_set(args.ignore_large_response_extensions, str.lower)
    }
    return DetectionConfig(
        max_bytes=args.max_bytes,
        rate_limit=args.rate_limit,
        burst_rate_limit=args.burst_rate_limit,
        burst_window_seconds=args.burst_window_seconds,
        same_path_limit=args.same_path_limit,
        error_limit=args.error_limit,
        unique_path_limit=args.unique_path_limit,
        bandwidth_limit=args.bandwidth_limit,
        window_seconds=args.window_seconds,
        max_query_length=args.max_query_length,
        score_threshold=args.score_threshold,
        min_categories=args.min_categories,
        allowed_methods=parse_csv_set(args.allowed_methods, str.upper),
        ignored_large_response_extensions=ignored_extensions,
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


def format_debug_detection(entry, result):
    fields = {
        "flag": result.flag,
        "action": "debug_only",
        "score": str(result.score),
        "threshold": str(result.score_threshold),
        "categories": str(result.category_count),
        "ip": entry.ip,
        "domain": entry.domain,
        "timestamp": entry.timestamp.isoformat(),
        "method": entry.method,
        "path": entry.path,
        "status": str(entry.status_code),
        "bytes": str(entry.bytes_sent),
        "reasons": ", ".join(result.reasons),
        "user_agent": entry.user_agent,
    }
    return " ".join(f"{key}={shlex.quote(value)}" for key, value in fields.items())


def main(argv=None):
    args = build_parser().parse_args(argv)
    config = build_config(args)
    detector = DDoSDetector(config)
    blocked = {}
    signal_ips = set()
    block_candidate_events = 0
    block_candidate_ips = set()
    reason_counter = Counter()
    signal_events = 0
    backend = args.firewall if args.enforce else "print"

    try:
        for entry in iter_entries_from_args(args):
            result = detector.evaluate(entry)
            if not result.has_signal:
                continue

            signal_events += 1
            signal_ips.add(entry.ip)
            reason_counter.update(result.reasons)
            if result.should_block:
                block_candidate_events += 1
                block_candidate_ips.add(entry.ip)

            if args.debug:
                print(format_debug_detection(entry, result), flush=True)
                continue

            if not result.should_block:
                continue

            if entry.ip in blocked:
                continue

            blocked[entry.ip] = result.reasons
            block_ip(entry.ip, backend)
            action = "blocked" if args.enforce else "would be blocked"
            print(
                f"IP {entry.ip} {action}. Score: {result.score}. "
                f"Reason: {', '.join(result.reasons)}",
                flush=True,
            )
    except (FileNotFoundError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not signal_events:
        print("No attack detected.")
    elif args.debug:
        print("\nSummary:")
        print(f"- signal events: {signal_events}")
        print(f"- signal IPs: {len(signal_ips)}")
        print(f"- block candidate events: {block_candidate_events}")
        print(f"- block candidate IPs: {len(block_candidate_ips)}")
        for reason, count in reason_counter.most_common():
            print(f"- {reason}: {count}")
    else:
        print("\nSummary:")
        label = "blocked IPs" if args.enforce else "IPs that would be blocked"
        print(f"- {label}: {len(blocked)}")
        print(f"- block candidate events: {block_candidate_events}")
        print(f"- signal events: {signal_events}")
        for reason, count in reason_counter.most_common():
            print(f"- {reason}: {count}")
    return 0
