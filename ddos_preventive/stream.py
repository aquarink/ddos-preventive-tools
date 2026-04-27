import sys

from ddos_preventive.log_parser import preprocess_log


def iter_stdin_entries(domain="stdin", stream=None):
    stream = stream or sys.stdin
    for line in stream:
        entry = preprocess_log(line, domain)
        if entry:
            yield entry
