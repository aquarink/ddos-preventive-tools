import re
import sys
from datetime import datetime
from pathlib import Path

from ddos_preventive.models import LogEntry


LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)


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
