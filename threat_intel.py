import requests
import os
from dotenv import load_dotenv

load_dotenv()

def get_virustotal(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return f"VirusTotal error: {response.status_code}"

def get_abuseipdb(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    return f"AbuseIPDB error: {response.status_code}"

def get_otx(ip, api_key):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return f"OTX error: {response.status_code}"
