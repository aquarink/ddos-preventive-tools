from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Set


DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "ipinfo.db"
DEFAULT_ALLOWED_METHODS = {"GET", "POST", "HEAD", "OPTIONS"}
DEFAULT_SUSPICIOUS_STATUSES = {400, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504}


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
