import json
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path

from ddos_preventive.models import DEFAULT_DB_PATH


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
    request = urllib.request.Request(
        url, headers={"User-Agent": "ddos-preventive-tools/1.0"}
    )
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
