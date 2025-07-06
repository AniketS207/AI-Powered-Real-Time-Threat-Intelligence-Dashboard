import os
import requests

def get_virustotal(ip, key):
    headers = {"x-apikey": key}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        data = resp.json().get("data", {}).get("attributes", {})
        return {
            "IP": ip,
            "Country": data.get("country", "N/A"),
            "ASN": data.get("asn", "N/A"),
            "Malicious": data.get("last_analysis_stats", {}).get("malicious", 0),
            "Suspicious": data.get("last_analysis_stats", {}).get("suspicious", 0),
            "Abuse Confidence": 0,
            "Reputation": 0,
            "Source": "VirusTotal"
        }

def get_abuseipdb(ip, key):
    headers = {"Key": key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    url = "https://api.abuseipdb.com/api/v2/check"
    resp = requests.get(url, headers=headers, params=params)
    if resp.status_code == 200:
        data = resp.json()["data"]
        return {
            "IP": ip,
            "Country": data.get("countryCode", "N/A"),
            "ISP": data.get("isp", "N/A"),
            "Malicious": 0,
            "Suspicious": 0,
            "Abuse Confidence": data.get("abuseConfidenceScore", 0),
            "Reputation": 0,
            "Source": "AbuseIPDB"
        }

def get_otx(ip, key):
    headers = {"X-OTX-API-KEY": key}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        return {
            "IP": ip,
            "Country": data.get("country_name", "N/A"),
            "Malicious": 0,
            "Suspicious": 0,
            "Abuse Confidence": 0,
            "Reputation": data.get("reputation", 0),
            "Source": "AlienVault OTX"
        }

def get_hybrid_report(ip, api_keys, user_key=None):
    functions = {
        "VirusTotal": get_virustotal,
        "AbuseIPDB": get_abuseipdb,
        "AlienVault OTX": get_otx
    }
    for name, func in functions.items():
        key = user_key or api_keys.get(name)
        if key:
            try:
                result = func(ip, key)
                if result:
                    result["Source"] = name
                    return result
            except:
                continue
    return None

api_function_map = {
    "VirusTotal": get_virustotal,
    "AbuseIPDB": get_abuseipdb,
    "AlienVault OTX": get_otx
}
