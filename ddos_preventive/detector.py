import re
from collections import defaultdict, deque
from datetime import datetime, timedelta

from ddos_preventive.geoip import country_code_check
from ddos_preventive.log_parser import parse_nginx_timestamp
from ddos_preventive.models import (
    DEFAULT_ALLOWED_METHODS,
    DetectionConfig,
    DetectionResult,
    DetectionSignal,
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
        self.burst_events = defaultdict(deque)
        self.same_path_events = defaultdict(lambda: defaultdict(deque))
        self.error_events = defaultdict(deque)
        self.byte_events = defaultdict(deque)
        self.unique_paths = defaultdict(lambda: defaultdict(set))

    def evaluate(self, entry: LogEntry):
        signals = []
        window = timedelta(seconds=self.config.window_seconds)
        burst_window = timedelta(seconds=self.config.burst_window_seconds)

        if (
            entry.bytes_sent > self.config.max_bytes
            and file_extension(entry.path) not in self.config.ignored_large_response_extensions
        ):
            signals.append(
                DetectionSignal(
                    f"large response body ({entry.bytes_sent} bytes)", "bandwidth", 1
                )
            )

        if entry.method.upper() not in self.config.allowed_methods:
            signals.append(
                DetectionSignal(f"uncommon HTTP method ({entry.method})", "method", 2)
            )

        if unusual_common_format_url_path(entry.path):
            signals.append(DetectionSignal("unusual URL format", "path", 3))

        if len(query_string(entry.path)) > self.config.max_query_length:
            signals.append(DetectionSignal("query string too long", "path", 2))

        if SENSITIVE_PATH_RE.search(entry.path):
            signals.append(DetectionSignal("sensitive path probing", "path", 5))

        if SUSPICIOUS_USER_AGENT_RE.search(entry.user_agent or ""):
            signals.append(DetectionSignal("suspicious user-agent", "client", 1))

        self._append_window(self.ip_events[entry.ip], entry.timestamp, window)
        if len(self.ip_events[entry.ip]) > self.config.rate_limit:
            signals.append(
                DetectionSignal(
                    f"request rate exceeded ({len(self.ip_events[entry.ip])}/{self.config.window_seconds}s)",
                    "rate",
                    4,
                )
            )

        if self.config.burst_rate_limit > 0:
            self._append_window(self.burst_events[entry.ip], entry.timestamp, burst_window)
            if len(self.burst_events[entry.ip]) > self.config.burst_rate_limit:
                signals.append(
                    DetectionSignal(
                        f"burst rate exceeded ({len(self.burst_events[entry.ip])}/{self.config.burst_window_seconds:g}s)",
                        "rate",
                        4,
                    )
                )

        path_window = self.same_path_events[entry.ip][entry.path]
        self._append_window(path_window, entry.timestamp, window)
        if len(path_window) > self.config.same_path_limit:
            signals.append(DetectionSignal("same path requested too often", "rate", 3))

        if entry.status_code in self.config.suspicious_statuses:
            self._append_window(self.error_events[entry.ip], entry.timestamp, window)
            if len(self.error_events[entry.ip]) > self.config.error_limit:
                signals.append(
                    DetectionSignal("too many suspicious response codes", "error", 3)
                )

        byte_window = self.byte_events[entry.ip]
        byte_window.append((entry.timestamp, entry.bytes_sent))
        while byte_window and entry.timestamp - byte_window[0][0] > window:
            byte_window.popleft()
        total_bytes = sum(bytes_sent for _, bytes_sent in byte_window)
        if total_bytes > self.config.bandwidth_limit:
            signals.append(
                DetectionSignal(
                    f"bandwidth exceeded ({total_bytes} bytes/{self.config.window_seconds}s)",
                    "bandwidth",
                    4,
                )
            )

        minute_bucket = entry.timestamp.replace(second=0, microsecond=0)
        self.unique_paths[entry.ip][minute_bucket].add(entry.path)
        self._prune_unique_path_buckets(entry.ip, minute_bucket, window)
        unique_count = sum(len(paths) for paths in self.unique_paths[entry.ip].values())
        if unique_count > self.config.unique_path_limit:
            signals.append(DetectionSignal("too many unique URL paths", "path", 3))

        if self.config.country_check and country_code_check(entry.ip, self.config):
            signals.append(DetectionSignal("country not allowed", "geo", 2))

        score = sum(signal.score for signal in signals)
        category_count = len({signal.category for signal in signals})
        return DetectionResult(
            signals=signals,
            score=score,
            category_count=category_count,
            score_threshold=self.config.score_threshold,
            min_categories=self.config.min_categories,
        )

    def detect(self, entry: LogEntry):
        result = self.evaluate(entry)
        return result.should_block, result.reasons

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


def file_extension(path):
    clean_path = path.split("?", 1)[0].rsplit("/", 1)[-1]
    if "." not in clean_path:
        return ""
    return clean_path.rsplit(".", 1)[1].lower()


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

    result = detector.evaluate(entry)
    return result.should_block, ", ".join(result.reasons) if result.reasons else "No attack detected"
