import requests
import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def lookup_ip(ip: str) -> dict:
    """Looks up IP reputation on AbuseIPDB"""
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Accept": "application/json",
                "Key": ABUSEIPDB_API_KEY
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            }
        )
        data = response.json().get("data", {})
        return {
            "ip": ip,
            "country": data.get("countryCode", "Unknown"),
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "isp": data.get("isp", "Unknown"),
            "is_tor": data.get("isTor", False)
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}


def extract_ips(alert_text: str) -> list:
    """Extracts IP addresses from alert text"""
    import re
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(pattern, alert_text)
    # Filter out private IPs for external lookup
    public_ips = []
    for ip in ips:
        parts = ip.split('.')
        if not (
            parts[0] == '10' or
            (parts[0] == '172' and 16 <= int(parts[1]) <= 31) or
            (parts[0] == '192' and parts[1] == '168') or
            ip.startswith('127.')
        ):
            public_ips.append(ip)
    return list(set(public_ips))