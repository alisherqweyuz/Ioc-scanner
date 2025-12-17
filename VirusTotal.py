import re
import json
import requests
import base64
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

api_key = "api_key"

def get_ioc(ioc):
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{64}$", ioc):
        return "hash_sha256"
    if re.match(r"^[a-fA-F0-9]{40}$", ioc):
        return "hash_sha1"
    if re.match(r"^[a-fA-F0-9]{32}$", ioc):
        return "hash_md5"
    if ioc.startswith("http"):
        return "url"
    if "." in ioc:
        return "domain"
    return "unknown"

def extract_hostname(ioc, ioc_type):
    if ioc_type == "url":
        return urlparse(ioc).hostname
    if ioc_type in ["domain", "ip"]:
        return ioc
    return None

def get_ssl_info(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_after = cert.get("After")

        not_after_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        ssl_status = "Сертификат действителен" if datetime.utcnow() <= not_after_dt else "Сертификат недействителен"

        return {
            "ssl_subject": subject.get("Name", "не найдено"),
            "ssl_issuer": issuer.get("Name", "не найдено"),
            "ssl_valid": not_after,
            "ssl_status": ssl_status
        }

    except Exception as e:
        return {
            "ssl_subject": "не найдено",
            "ssl_issuer": "не найдено",
            "ssl_status": f"ssl error: {e}"
        }

def check_ioc(ioc, ioc_type):
    headers = {"x-apikey": api_key}
    alerts = []

    try:
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif ioc_type in ["hash_md5", "hash_sha1", "hash_sha256"]:
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"
        elif ioc_type == "url":
            encoded_url = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        else:
            return [{"ioc": ioc, "type": ioc_type, "alert": "Unknown IOC type"}]

        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        attr = data.get("data", {}).get("attributes", {})

        reputation = attr.get("reputation", 0)
        stats = attr.get("last_analysi", {})
        country = attr.get("country", "не найдено")

        hostname = extract_hostname(ioc, ioc_type)
        ssl_info = get_ssl_info(hostname) if hostname and ioc_type in ["ip", "domain", "url"] else {
            "ssl_subject": "не найдено",
            "ssl_issuer": "не найдено",
            "ssl_status": "не найдено"
        }

        if reputation > 3 or stats.get("malicious", 0) > 1:
            alert = "High Risk IOC Detected"
        elif stats.get("suspicious", 0) > 0:
            alert = "Suspicious IOC Detected"
        else:
            return None

        alerts.append({
            "ioc": ioc,
            "type": ioc_type,
            "reputation": reputation,
            "country": country,
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "alert": alert,
            "ssl_info": ssl_info
        })

    except requests.RequestException as e:
        alerts.append({"ioc": ioc, "type": ioc_type, "alert": f"Request error: {e}"})

    return alerts

if __name__ == "__main__":
    alerting = []
    try:
        with open("ioc.txt", "r") as f:
            iocs = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("Файл ioc.txt не найден")
        iocs = []

    for ioc in iocs:
        ioc_type = get_ioc(ioc)
        result = check_ioc(ioc, ioc_type)
        if result:
            alerting.extend(result)

    if alerting:
        with open("IOC.json", "w") as f:
            json.dump(alerting, f, indent=4)
            print("Данные сохранены в IOC.json")   
