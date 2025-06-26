import streamlit as st
import requests
import csv
import io
import os
from dotenv import load_dotenv

# ✅ Must be first Streamlit command
st.set_page_config(page_title="AI-Powered Real-Time Threat Intelligence Dashboard", layout="wide")

load_dotenv()

# ✅ Session state for fetch control
if "fetch_triggered" not in st.session_state:
    st.session_state.fetch_triggered = False

def trigger_fetch():
    st.session_state.fetch_triggered = True

st.title("🛡️ AI-Powered Real-Time Threat Intelligence Dashboard")

# ✅ Sidebar form to control input and fetch
with st.sidebar.form("input_form"):
    st.header("🔧 Configuration")
    api_choice = st.selectbox("Select Threat Intelligence API", ["VirusTotal", "AbuseIPDB", "AlienVault OTX"])
    api_key = st.text_input("🔐 API Key (leave blank to use .env)", type="password")

    st.header("🔍 Input IP Addresses")
    ip_input = st.text_area("Enter IPs (one per line)")
    uploaded_file = st.file_uploader("Or upload .txt/.csv", type=["txt", "csv"])
    limit = st.slider("Max IPs to analyze", 1, 50, 10)

    # ✅ Submit button triggers fetch
    submitted = st.form_submit_button("🚀 Fetch Threat Reports")

# ✅ Trigger flag on submit
if submitted:
    trigger_fetch()

# ✅ Get key from .env if not entered
api_key_env_map = {
    "VirusTotal": "VT_API_KEY",
    "AbuseIPDB": "ABUSEIPDB_API_KEY",
    "AlienVault OTX": "OTX_API_KEY"
}
if not api_key:
    api_key = os.getenv(api_key_env_map[api_choice])

# ✅ Process IP input
ip_list = []
if ip_input:
    ip_list = [ip.strip() for ip in ip_input.splitlines() if ip.strip()]
elif uploaded_file:
    content = uploaded_file.read().decode("utf-8").splitlines()
    ip_list = [line.strip() for line in content if line.strip()]
ip_list = ip_list[:limit]


# API Functions
def get_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        data = resp.json()["data"]["attributes"]
        return {
            "IP": ip,
            "Country": data.get("country", "N/A"),
            "ASN": data.get("asn", "N/A"),
            "Malicious": data["last_analysis_stats"].get("malicious", 0),
            "Suspicious": data["last_analysis_stats"].get("suspicious", 0)
        }

def get_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    resp = requests.get(url, headers=headers, params=params)
    if resp.status_code == 200:
        data = resp.json()["data"]
        return {
            "IP": ip,
            "Country": data.get("countryCode", "N/A"),
            "ISP": data.get("isp", "N/A"),
            "Abuse Confidence": data.get("abuseConfidenceScore", 0)
        }

def get_otx(ip):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": api_key}
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        data = resp.json()
        return {
            "IP": ip,
            "Country": data.get("country_name", "N/A"),
            "Reputation": data.get("reputation", "N/A"),
            "Pulses": len(data.get("pulse_info", {}).get("pulses", []))
        }

api_function_map = {
    "VirusTotal": get_virustotal,
    "AbuseIPDB": get_abuseipdb,
    "AlienVault OTX": get_otx
}

# Main Execution
if st.session_state.fetch_triggered:
    if not ip_list:
        st.info("👉 Enter at least one IP to begin.")
    elif api_choice != "VirusTotal" and not api_key:
        st.warning(f"⚠️ API key required for {api_choice}. Please enter it to use this source.")
    else:
        st.subheader(f"📊 {api_choice} Threat Reports")
        results = []
        for ip in ip_list:
            try:
                report = api_function_map[api_choice](ip)
                if report:
                    st.markdown(f"### 🔎 {ip}")
                    for k, v in report.items():
                        if k != "IP":
                            st.markdown(f"- **{k}**: `{v}`")
                    results.append(report)
            except Exception as e:
                st.error(f"❌ Error processing {ip}: {e}")

        if results:
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
            st.download_button("⬇️ Download CSV", output.getvalue(), "threat_reports.csv", "text/csv")
