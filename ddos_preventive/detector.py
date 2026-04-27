import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

from ddos_preventive.geoip import country_code_check
from ddos_preventive.log_parser import parse_nginx_timestamp
from ddos_preventive.models import (
    DEFAULT_ALLOWED_METHODS,
    DetectionConfig,
    LogEntry,
)


SUSPICIOUS_USER_AGENT_RE = re.compile(
    r"(?:^$|curl|wget|python-requests|nikto|sqlmap|masscan|nmap|zgrab|acunetix|dirbuster|gobuster|httpclient)",
    re.IGNORECASE,
)
SENSITIVE_PATH_RE = re.compile(
    r"(\.env|wp-login\.php|xmlrpc\.php|phpmyadmin|/admin\b|/login\b|/vendor/|/\.git|/config|/backup|/shell)",
    re.IGNORECASE,
)


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


def unusual_common_format_url_path(url):
    if "*" in url or "\\" in url or not url.startswith("/"):
        return True
    return False


def uncommon_method(method):
    return method.upper() not in DEFAULT_ALLOWED_METHODS


def query_string(path):
    return path.split("?", 1)[1] if "?" in path else ""


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
