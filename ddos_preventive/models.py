from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set


DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "ipinfo.db"
DEFAULT_ALLOWED_METHODS = {"GET", "POST", "HEAD", "OPTIONS"}
DEFAULT_SUSPICIOUS_STATUSES = {400, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504}
DEFAULT_IGNORED_LARGE_RESPONSE_EXTENSIONS = {
    "avi",
    "css",
    "gif",
    "jpeg",
    "jpg",
    "js",
    "m4v",
    "mov",
    "mp3",
    "mp4",
    "pdf",
    "png",
    "svg",
    "webm",
    "webp",
    "zip",
}


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


@dataclass(frozen=True)
class DetectionSignal:
    reason: str
    category: str
    score: int


@dataclass(frozen=True)
class DetectionResult:
    signals: List[DetectionSignal]
    score: int
    category_count: int
    score_threshold: int
    min_categories: int

    @property
    def reasons(self):
        return [signal.reason for signal in self.signals]

    @property
    def has_signal(self):
        return bool(self.signals)

    @property
    def should_block(self):
        return self.score >= self.score_threshold and self.category_count >= self.min_categories

    @property
    def flag(self):
        return "DDOS_DETECTED" if self.should_block else "SUSPICIOUS"


@dataclass
class DetectionConfig:
    max_bytes: int = 1_000_000
    rate_limit: int = 120
    burst_rate_limit: int = 0
    burst_window_seconds: float = 1.0
    same_path_limit: int = 60
    error_limit: int = 30
    unique_path_limit: int = 80
    bandwidth_limit: int = 100 * 1024 * 1024
    window_seconds: int = 60
    max_query_length: int = 1_024
    score_threshold: int = 7
    min_categories: int = 2
    allowed_methods: Optional[Set[str]] = None
    suspicious_statuses: Optional[Set[int]] = None
    ignored_large_response_extensions: Optional[Set[str]] = None
    allowed_countries: Optional[Set[str]] = None
    country_check: bool = False
    db_path: Path = DEFAULT_DB_PATH
    ipinfo_token: str = ""

    def __post_init__(self):
        if self.allowed_methods is None:
            self.allowed_methods = set(DEFAULT_ALLOWED_METHODS)
        if self.suspicious_statuses is None:
            self.suspicious_statuses = set(DEFAULT_SUSPICIOUS_STATUSES)
        if self.ignored_large_response_extensions is None:
            self.ignored_large_response_extensions = set(
                DEFAULT_IGNORED_LARGE_RESPONSE_EXTENSIONS
            )
        if self.allowed_countries is None:
            self.allowed_countries = set()
