#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.request

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Set


LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)

DEFAULT_DB_PATH = Path(__file__).with_name("ipinfo.db")
DEFAULT_ALLOWED_METHODS = {"GET", "POST", "HEAD", "OPTIONS"}
DEFAULT_SUSPICIOUS_STATUSES = {400, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504}
SUSPICIOUS_USER_AGENT_RE = re.compile(
    r"(?:^$|curl|wget|python-requests|nikto|sqlmap|masscan|nmap|zgrab|acunetix|dirbuster|gobuster|httpclient)",
    re.IGNORECASE,
)
SENSITIVE_PATH_RE = re.compile(
    r"(\.env|wp-login\.php|xmlrpc\.php|phpmyadmin|/admin\b|/login\b|/vendor/|/\.git|/config|/backup|/shell)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LogEntry:
    domain: str
    ip: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status_code: int
    bytes_sent: int
    user_agent: str = "-"


@dataclass
class DetectionConfig:
    max_bytes: int = 1_000_000
    rate_limit: int = 120
    same_path_limit: int = 60
    error_limit: int = 30
    unique_path_limit: int = 80
    window_seconds: int = 60
    max_query_length: int = 1_024
    allowed_methods: Optional[Set[str]] = None
    suspicious_statuses: Optional[Set[int]] = None
    allowed_countries: Optional[Set[str]] = None
    country_check: bool = False
    db_path: Path = DEFAULT_DB_PATH
    ipinfo_token: str = ""

    def __post_init__(self):
        if self.allowed_methods is None:
            self.allowed_methods = set(DEFAULT_ALLOWED_METHODS)
        if self.suspicious_statuses is None:
            self.suspicious_statuses = set(DEFAULT_SUSPICIOUS_STATUSES)
        if self.allowed_countries is None:
            self.allowed_countries = set()


class DDoSDetector:
    def __init__(self, config: DetectionConfig):
        self.config = config
        self.ip_events = defaultdict(deque)
        self.same_path_events = defaultdict(lambda: defaultdict(deque))
        self.error_events = defaultdict(deque)
        self.unique_paths = defaultdict(lambda: defaultdict(set))

    def detect(self, entry: LogEntry):
        reasons = []
        window = timedelta(seconds=self.config.window_seconds)

        if entry.bytes_sent > self.config.max_bytes:
            reasons.append(f"large response body ({entry.bytes_sent} bytes)")

        if entry.method.upper() not in self.config.allowed_methods:
            reasons.append(f"uncommon HTTP method ({entry.method})")

        if unusual_common_format_url_path(entry.path):
            reasons.append("unusual URL format")

        if len(query_string(entry.path)) > self.config.max_query_length:
            reasons.append("query string too long")

        if SENSITIVE_PATH_RE.search(entry.path):
            reasons.append("sensitive path probing")

        if SUSPICIOUS_USER_AGENT_RE.search(entry.user_agent or ""):
            reasons.append("suspicious user-agent")

        self._append_window(self.ip_events[entry.ip], entry.timestamp, window)
        if len(self.ip_events[entry.ip]) > self.config.rate_limit:
            reasons.append(
                f"request rate exceeded ({len(self.ip_events[entry.ip])}/{self.config.window_seconds}s)"
            )

        path_window = self.same_path_events[entry.ip][entry.path]
        self._append_window(path_window, entry.timestamp, window)
        if len(path_window) > self.config.same_path_limit:
            reasons.append("same path requested too often")

        if entry.status_code in self.config.suspicious_statuses:
            self._append_window(self.error_events[entry.ip], entry.timestamp, window)
            if len(self.error_events[entry.ip]) > self.config.error_limit:
                reasons.append("too many suspicious response codes")

        minute_bucket = entry.timestamp.replace(second=0, microsecond=0)
        self.unique_paths[entry.ip][minute_bucket].add(entry.path)
        self._prune_unique_path_buckets(entry.ip, minute_bucket, window)
        unique_count = sum(len(paths) for paths in self.unique_paths[entry.ip].values())
        if unique_count > self.config.unique_path_limit:
            reasons.append("too many unique URL paths")

        if self.config.country_check and country_code_check(entry.ip, self.config):
            reasons.append("country not allowed")

        return bool(reasons), reasons

    @staticmethod
    def _append_window(items, timestamp, window):
        items.append(timestamp)
        while items and timestamp - items[0] > window:
            items.popleft()

    def _prune_unique_path_buckets(self, ip, now_bucket, window):
        old_buckets = [
            bucket for bucket in self.unique_paths[ip] if now_bucket - bucket > window
        ]
        for bucket in old_buckets:
            del self.unique_paths[ip][bucket]


def process_access_log(log_file_path, domain=None):
    data = []
    with open(log_file_path, "r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            processed_data = preprocess_log(line, domain or infer_domain(log_file_path))
            if processed_data:
                data.append(processed_data)
    return data


def preprocess_log(log_line, domain="unknown"):
    match = LOG_PATTERN.match(log_line.strip())
    if not match:
        return None

    request = match.group("request")
    request_parts = request.split()
    if len(request_parts) != 3:
        return None

    bytes_value = match.group("bytes")
    timestamp = parse_nginx_timestamp(match.group("timestamp"))
    if timestamp is None:
        return None

    return LogEntry(
        domain=domain,
        ip=match.group("ip"),
        timestamp=timestamp,
        method=request_parts[0],
        path=request_parts[1],
        protocol=request_parts[2],
        status_code=int(match.group("status")),
        bytes_sent=0 if bytes_value == "-" else int(bytes_value),
        user_agent=match.group("user_agent") or "-",
    )


def parse_nginx_timestamp(value):
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def infer_domain(log_file_path):
    name = Path(log_file_path).name
    name = re.sub(r"-(?:access|error)\.log$", "", name)
    return re.sub(r"\.log$", "", name) or "unknown"


def unusual_common_format_url_path(url):
    if "*" in url or "\\" in url or not url.startswith("/"):
        return True
    return False


def uncommon_method(method):
    return method.upper() not in DEFAULT_ALLOWED_METHODS


def query_string(path):
    return path.split("?", 1)[1] if "?" in path else ""


def create_database(db_path):
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS ip_data (ip text PRIMARY KEY, country text)"
        )
        conn.commit()
    finally:
        conn.close()


def get_country_from_database(ip, db_path=DEFAULT_DB_PATH):
    create_database(db_path)
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.execute("SELECT country FROM ip_data WHERE ip=?", (ip,))
        country = cursor.fetchone()
    finally:
        conn.close()
    if country:
        return country[0]
    return None


def store_country_in_database(ip, country, db_path=DEFAULT_DB_PATH):
    create_database(db_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO ip_data (ip, country) VALUES (?, ?)",
            (ip, country),
        )
        conn.commit()
    finally:
        conn.close()


def get_country(ip, config):
    country = get_country_from_database(ip, config.db_path)
    if country:
        return country

    if not config.ipinfo_token:
        return "Unknown"

    url = f"https://ipinfo.io/{ip}/json?token={config.ipinfo_token}"
    request = urllib.request.Request(url, headers={"User-Agent": "ddos-preventive-tools/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return "Unknown"

    country = data.get("country") or "Unknown"
    store_country_in_database(ip, country, config.db_path)
    return country


def country_code_check(ip, config):
    ip_from = get_country(ip, config)
    return ip_from not in config.allowed_countries


def iter_log_entries(log_files, log_dir):
    paths = []
    for log_file in log_files:
        paths.append(Path(log_file))

    if log_dir:
        log_dir = Path(log_dir)
        if not log_dir.exists():
            raise FileNotFoundError(f"Log directory not found: {log_dir}")
        paths.extend(sorted(log_dir.glob("*.log")))

    for path in paths:
        if not path.exists():
            print(f"skip missing log file: {path}", file=sys.stderr)
            continue
        yield from process_access_log(path, infer_domain(path))


def detect_ddos_attack_v2(processed_data_list, max_requests=120, interval_seconds=60):
    config = DetectionConfig(rate_limit=max_requests, window_seconds=interval_seconds)
    detector = DDoSDetector(config)

    if len(processed_data_list) == 7:
        domain, ip, timestamp, method, path_url, status_code, bytes_sent = processed_data_list
        entry = LogEntry(
            domain=domain,
            ip=ip,
            timestamp=parse_nginx_timestamp(timestamp) or datetime.now(),
            method=method,
            path=path_url,
            protocol="HTTP/1.1",
            status_code=int(status_code),
            bytes_sent=int(bytes_sent),
        )
    elif isinstance(processed_data_list, LogEntry):
        entry = processed_data_list
    else:
        return True, "Data length not equal to 7"

    is_attack, reasons = detector.detect(entry)
    return is_attack, ", ".join(reasons) if reasons else "No attack detected"


def block_ip(ip, backend="print"):
    address = ipaddress.ip_address(ip)

    if backend == "print":
        print(f"DRY-RUN block {address}")
        return

    if backend == "firewalld":
        family = "ipv6" if address.version == 6 else "ipv4"
        rule = f"rule family='{family}' source address='{address}' drop"
        subprocess.run(
            ["firewall-cmd", "--permanent", f"--add-rich-rule={rule}"], check=True
        )
        subprocess.run(["firewall-cmd", "--reload"], check=True)
        return

    if backend == "iptables":
        binary = "ip6tables" if address.version == 6 else "iptables"
        subprocess.run([binary, "-I", "INPUT", "-s", str(address), "-j", "DROP"], check=True)
        return

    if backend == "nft":
        family_field = "ip6" if address.version == 6 else "ip"
        subprocess.run(
            [
                "nft",
                "add",
                "rule",
                "inet",
                "filter",
                "input",
                family_field,
                "saddr",
                str(address),
                "drop",
            ],
            check=True,
        )
        return

    raise ValueError(f"Unsupported firewall backend: {backend}")


def block_ip_with_firewalld(ip):
    block_ip(ip, "firewalld")


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


def main(argv=None):
    args = build_parser().parse_args(argv)
    log_dir = args.log_dir
    if not args.log_file and not log_dir:
        log_dir = "/var/log/nginx"

    allowed_countries = parse_csv_set(args.allowed_countries, str.upper)
    config = DetectionConfig(
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
    detector = DDoSDetector(config)
    blocked = {}
    backend = args.firewall if args.enforce else "print"

    try:
        entries = iter_log_entries(args.log_file, log_dir)
        for entry in sorted(entries, key=lambda item: item.timestamp):
            is_attack, reasons = detector.detect(entry)
            if not is_attack or entry.ip in blocked:
                continue
            blocked[entry.ip] = reasons
            block_ip(entry.ip, backend)
            print(f"IP {entry.ip} is blocked. Reason: {', '.join(reasons)}")
    except (FileNotFoundError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not blocked:
        print("No attack detected.")
    else:
        reason_counter = Counter(reason for reasons in blocked.values() for reason in reasons)
        print("\nSummary:")
        print(f"- blocked IPs: {len(blocked)}")
        for reason, count in reason_counter.most_common():
            print(f"- {reason}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
