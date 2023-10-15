import re
import csv
import os
import shlex
import sqlite3
import requests
import subprocess

from collections import defaultdict, Counter
from datetime import datetime, timedelta

def process_access_log(log_file_path):
    data = []
    with open(log_file_path, "r") as log_file:
        for line in log_file:
            processed_data = preprocess_log(line)
            if processed_data:
                data.append(processed_data)

    return data

def preprocess_log(log_line):
    line = re.sub(r"[\[\]]", "", log_line)
    parts = shlex.split(line)

    if(len(parts[5].split()) == 3):
        url_method = parts[5].split()

        ip = parts[0]
        timestamp = parts[3] + " " + parts[4]
        method = url_method[0]
        path_url = url_method[1]
        status_code = int(parts[6])
        bytes_sent = int(parts[7])

        return ip, timestamp, method, path_url, status_code, bytes_sent
    else:
        return None

def unusual_common_format_url_path(url):
    if '*' in url or '\\' in url or '/' not in url:
        return True
    return False

def uncommon_method(method):
    if 'GET' not in method and 'POST' not in method:
        return True
    return False

# Path ke database SQLite
db_path = "/var/www/ipinfo.db"

def create_database(db_path):
    if not os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE ip_data
                     (ip text PRIMARY KEY, country text)''')
        conn.commit()
        conn.close()

def get_country_from_database(ip):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT country FROM ip_data WHERE ip=?", (ip,))
    country = c.fetchone()
    conn.close()
    if country:
        return country[0]
    return None

def store_country_in_database(ip, country):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO ip_data (ip, country) VALUES (?, ?)", (ip, country))
    conn.commit()
    conn.close()

def get_country(ip):
    country = get_country_from_database(ip)
    if country:
        return country
    else:
        response = requests.get(f"https://ipinfo.io/{ip}/?token=9ef4c72848b641")
        if response.status_code == 200:
            data = response.json()
            country = data.get("country")
            if country:
                store_country_in_database(ip, country)
                return country
    return "Unknown"

def country_code_check(ip):
    ip_from = get_country(ip)
    if 'ID' not in ip_from and 'TL' not in ip_from:
        return True
    return False

def detect_ddos_attack_v2(processed_data_list, max_requests=1, interval_seconds=1):
    ip_counter = defaultdict(lambda: defaultdict(int))
    interval = timedelta(seconds=interval_seconds)

    ip = processed_data_list[1]
    timestamp = processed_data_list[2]
    method = processed_data_list[3]
    path_url = processed_data_list[4]
    status_code = processed_data_list[5]
    bytes_sent = processed_data_list[6]

    if len(processed_data_list) != 7:
        return True, "Data length not equal to 7"

    # Rule 1: Data Volume
    if bytes_sent > 1000000:  # Misalnya, jika lebih dari 1MB
        return True, "Large data volume"

    # Rule 2: Unusual Method
    if uncommon_method(method):
        return True, "Uncommon method"

    # Rule 3: Response code
    if status_code == 404:
        return True, "404 status code"

    if status_code == 500:
        return True, "500 status code"

    # Rule 4: Request Rate
    if path_url in ip_counter[ip]:
        if datetime.now() - ip_counter[ip][path_url] < interval:
            ip_counter[ip][path_url] += 1
            if ip_counter[ip][path_url] > max_requests:
                return True, "Request rate exceeded"
        else:
            ip_counter[ip][path_url] = datetime.now()
    else:
        ip_counter[ip][path_url] = datetime.now()
    
    # Rule 5: Unusual URL
    if unusual_common_format_url_path(path_url):
        return True, "Unusual URL format"

    # Rule 6: Check IP come from (only from ID and TL)
    if country_code_check(ip):
      return True, "Country exclude"

    return False, "No attack detected"

def block_ip_with_firewalld(ip):
    cmd = f'firewall-cmd --permanent --add-rich-rule="rule family=\'ipv4\' source address=\'{ip}\' drop"'
    subprocess.run(cmd, shell=True, check=True)
    subprocess.run("firewall-cmd --reload", shell=True, check=True)

if __name__ == "__main__":
    log_folder_path = "/var/log/nginx"  # semua file yang ada didalamnya

    domain_data = defaultdict(list)
    combined_data = []

    for log_file in os.listdir(log_folder_path):
        if log_file.endswith(".log"):
            domain = re.sub(r"-access.log", "", log_file)
            domain = re.sub(r"-error.log", "", domain)

            full_log_path = os.path.join(log_folder_path, log_file)
            log_entries = process_access_log(full_log_path)
            domain_data[domain] += log_entries

            for domain, log_entries in domain_data.items():
                for log_entry in log_entries:
                    combined_data.append([domain] + list(log_entry))

    # detect_ddos_attack_v2(processed_data)
    ip_blocked = set()
    block_reasons = {} 

    for dt in combined_data:
        is_attack, reason = detect_ddos_attack_v2(dt)

        if is_attack == True:
            ip_blocked.add(dt[1])
            block_reasons[dt[1]] = reason

    # Cetak daftar IP yang terblokir beserta alasannya
    for ip, reason in block_reasons.items():
        # block_ip_with_firewalld(ip)
        print(f"IP {ip} is blocked. Reason: {reason}")
