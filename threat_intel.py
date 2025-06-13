import requests
import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Get API key from environment variable
API_KEY = os.getenv("VT_API_KEY")
ip = "8.8.8.8"

def get_virustotal_ip_report(api_key, ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "x-apikey": api_key
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print(f"Error {response.status_code}: {response.text}")
        return None

# Call the function
report = get_virustotal_ip_report(API_KEY, ip)
if report:
    print(report)
